# History of Java Authorization and the Origins of Dirty Chai

This document traces the history of Java's authorization and security architecture from its
origins through its deprecation and removal upstream, the ecosystem of projects that kept the
model alive, and the founding of Dirty Chai.

---

## 1. Java Security — Early Foundations (1995–1997)

Java 1.0 introduced a simple **sandbox model** aimed at applets running in web browsers. All
local code was fully trusted; all remotely loaded code ran in a tightly restricted sandbox with
no file system or network access beyond the originating host. The model was binary — trusted or
untrusted — with no middle ground.

Java 1.1 extended the sandbox with **signed JAR files**. Signed code from a trusted signer could
be granted additional permissions. The model was still coarse: a signed JAR was either fully
trusted or treated as unsigned.

---

## 2. Java 2 — The Architecture That Mattered (1998)

Java 1.2 (branded *Java 2 Platform*) introduced the security architecture that would underpin
the Java platform for the next two decades. Sun Microsystems' security team — **Li Gong, Gary
Ellison, and Mary Dageforde**, with input from IBM — redesigned the system from the ground up
for enterprise server workloads, not just browser applets.

The key concepts introduced in Java 1.2:

- **ProtectionDomain** — a grouping of code (by `CodeSource`: URL and signers) associated with
  a set of permissions.
- **Policy** — an administrator-configurable, replaceable mapping of code sources and principals
  to permissions.
- **AccessController / AccessControlContext** — a stack-inspection mechanism to compute the
  effective set of permissions across an entire call chain, preventing privilege escalation
  through untrusted intermediaries.
- **SecurityManager** — a hook for the platform to call into application-level policy enforcement
  at security-relevant operations (file access, network access, class loading, etc.).
- **Principle of Least Privilege (POLP)** — the design philosophy that code should be granted
  only the minimum permissions it requires, documented by Li Gong in *Inside Java 2 Platform
  Security* (ISBN 0201787911).

The model was designed so that even if an attacker reached code deep in the call chain, the
least-privileged caller in the stack would limit what the exploit could accomplish.

---

## 3. The Jini Project and Dynamic Policy (1999–2004)

Sun's [Jini Technology](https://river.apache.org/) project, initiated in 1999, built a
distributed services platform on top of Java's security model. Jini's requirements pushed the
model significantly:

- **Dynamic class loading** — service proxies were downloaded over the network at runtime.
  The security model needed to express fine-grained trust for downloaded code.
- **DynamicPolicy** (Jini 2.0, Java 1.4) — rather than baking permissions statically into a
  `ProtectionDomain` at class-loading time, policy was consulted live during `implies` calls,
  allowing grants to change after deployment.
- **GrantPermission** — a permission that allows one piece of code to delegate a restricted
  subset of its own permissions to another piece of code, enabling controlled delegation to
  downloaded service proxies without a monolithic administrator grant.
- **Debug Policy Tool** (2004) — Jini engineers created a tool that logged each permission
  checked at runtime so administrators could construct accurate policy files. This was the
  direct predecessor of PolicyWriter.

Java 1.4 incorporated the dynamic policy requirement by adding live `Policy.implies` consultation
into `ProtectionDomain.implies`, a change driven specifically by the Jini 2.0 release.

---

## 4. Java 1.8 — doPrivileged with Permission Scope (2014)

Java 8 added `AccessController.doPrivileged(PrivilegedAction, AccessControlContext, Permission...)`
variants that allow a caller to voluntarily **reduce** its effective permissions to a named
subset. The intent was to limit the blast radius of a privileged block.

The implementation required significant complexity in `AccessControlContext` — a separate
"limited privilege" wrapper layer around existing context — that ultimately made it impractical
to support Virtual threads without architectural changes.

Dirty Chai later reimplemented this semantics by pushing a restricting `ProtectionDomain` onto
the stack rather than using the wrapper, preserving the security contract with much less
complexity and better debuggability.

---

## 5. Apache River — Revocation and Grant Permissions (2010–present)

After Sun's acquisition by Oracle, the Jini codebase was donated to the Apache Software
Foundation as [Apache River](https://river.apache.org/). River extended the security model with:

- **Revocation** — policy grants could be garbage-collected when the granting object became
  unreachable, allowing dynamic revocation of permissions in long-lived service environments.
- **ScalableNestedPolicy** and **PermissionGrant** APIs — immutable, safely publishable
  authorization building blocks.

---

## 6. JGDMS — PolicyWriter and Modern Hardening (2012–present)

[JGDMS](https://github.com/pfirmstone/JGDMS) (Java Generic Distributed and Mobile Systems) is a
security-focused fork of Apache River developed by Peter Firmstone. It introduced several
components that now form the core of Dirty Chai:

- **PolicyWriter / SecurityPolicyWriter** — a runtime audit agent that observes permission
  checks and incrementally appends required grants to a policy file. This solved the
  "trial-and-error" problem that made least-privilege deployment impractical. JGDMS was
  inspired by the Jini Debug Policy Tool; PolicyWriter removed the manual editing step.
- **ConcurrentPolicyFile** — a high-performance, lock-free policy implementation replacing the
  original `PolicyFile`, which was synchronized and performed DNS lookups inside `implies`
  calls. RFC 3986 URI handling was added to eliminate DNS from the critical path and enforce
  strict URL validation.
- **OSGi-style proxy permission bundling** — service proxy JARs bundle the permissions they
  require. Following authentication, an administrator grants users the ability to extend a
  controlled subset of permissions to authenticated services via `GrantPermission`, making the
  process largely automatic while remaining bounded by administrator-defined constraints.
- **DomainIdentity** — a `ProtectionDomain` subclass with proper `equals` and `hashCode`,
  enabling `AccessControlContext` caching and deduplication, which is essential for Virtual
  thread scalability.

JGDMS proved that SecurityManager-based authorization was practical in production: the overhead
was under 1%, the policy tooling made administration manageable, and the model supported
high-throughput distributed systems.

---

## 7. SecurityManager Deprecation (Java 17, 2021)

[JEP 411](https://openjdk.org/jeps/411) deprecated `SecurityManager` for removal in Java 17.
The stated reasons:

1. **Maintenance burden** — SecurityManager had accumulated technical debt over two decades as
   the JVM evolved. Keeping the guard hooks consistent across JDK changes required constant
   effort that served a small fraction of Java deployments.
2. **Performance concerns** — Authorization checks added measurable overhead that was difficult
   to optimize without dedicated, modern tooling.
3. **Tooling gap** — No automated way to generate least-privilege policy files existed in the
   mainline JDK. Manual policy writing required discovering required permissions through
   trial and error, leading to widespread `AllPermission` grants and ultimately undermining
   the security model's usefulness.

The deprecation acknowledged that the model was not inherently flawed — the decision was
operational, not architectural.

Java 17 (2021) deprecated `SecurityManager`.  
Java 21 (2023) was the last Long-Term Support release to include SecurityManager APIs.  
Java 24 (2025) removed the SecurityManager APIs from the mainline JDK.

---

## 8. Log4Shell — The Retrospective Validation (2021)

The [Log4Shell vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) (CVE-2021-44228,
disclosed December 2021) demonstrated exactly the attack class that Java's authorization
architecture was designed to prevent:

1. Attacker sends a crafted string to a logging call.
2. Log4j's JNDI lookup follows an attacker-controlled LDAP URL.
3. The LDAP server returns a reference to a remote class.
4. The JVM downloads and executes the remote class with full application permissions.

Under a properly configured `SecurityManager` with a least-privilege policy:
- The JNDI LDAP URL would require a `URLPermission` or `SocketPermission` not granted to the
  logging library.
- Remote class download would require a `LoadClassPermission` for the remote codebase.
- Deserialized objects would require `SerialObjectPermission` grants.

Any one of these layers would have broken the attack chain — without requiring Log4j to be
patched, and without requiring the application to know about the vulnerability.

Log4Shell was discovered concurrent with the SecurityManager deprecation process, and became
one of the most cited examples of why the authorization infrastructure should not have been
removed.

---

## 9. The Foundation of Dirty Chai (2024–present)

Dirty Chai was founded to preserve and advance the Java authorization model that upstream
OpenJDK chose to discontinue. The project is a community fork of OpenJDK that:

- **Retains all SecurityManager guard hooks** throughout the JDK, preventing the attack surface
  expansion that occurs when permission checks are removed.
- **Ports ConcurrentPolicyFile and PolicyWriter from JGDMS** as the default policy provider
  and audit tooling, solving the tooling gap that contributed to the original deprecation.
- **Adds new guard permissions** (`LoadClassPermission`, `NativeAccessPermission`,
  `SerialObjectPermission`) to close attack surfaces not covered by the original model.
- **Hardens SecurityManager installation** with conditional validation: trusted implementations
  (from `java.base`) receive a lightweight check; custom implementations are subject to
  layered defense-in-depth validation including stack inspection and generated-code detection.
- **Restores Virtual thread compatibility** by redesigning `AccessControlContext` to be
  immutable, cacheable, and structurally simple enough to propagate correctly through carrier
  and virtual thread boundaries.
- **Eliminates static permissions** from `ClassLoader` construction, giving full control of
  permission grants to policy administrators rather than leaving broad grants embedded in the
  JDK's own class-loading infrastructure.

The project name is a nod to the "dirty" nature of the fork — it retains functionality that
upstream considers legacy — combined with the [Chai.js](https://www.chaijs.com/) assertion
library naming convention, reflecting a community-driven, test-grounded engineering culture.

---

## 10. Design Lineage Summary

```
Java 1.0 (1995)       — Binary sandbox (local trusted / remote sandboxed)
Java 1.1 (1997)       — Signed JARs, coarse-grained trust
Java 1.2 (1998)       — Full authorization architecture (Li Gong et al.)
                        ProtectionDomain, Policy, AccessController, SecurityManager
Jini 1.x (1999)       — Dynamic class loading, security requirements for distributed services
Java 1.4 (2002)       — DynamicPolicy: live Policy.implies consultation (Jini 2.0 driver)
Apache River (2010)   — Revocation, GrantPermission, ScalableNestedPolicy
Java 8 (2014)         — doPrivileged with Permission-array scope reduction
JGDMS (2012–)         — ConcurrentPolicyFile, PolicyWriter, DomainIdentity, OSGi-style proxies
Java 17 (2021)        — SecurityManager deprecated (JEP 411)
Log4Shell (2021)      — CVE-2021-44228 validates the authorization model
Java 21 (2023)        — Last LTS with SecurityManager APIs
Java 24 (2025)        — SecurityManager removed from mainline
Dirty Chai (2024–)    — Community fork retaining and advancing Java authorization
```

---

## References

- Li Gong, Gary Ellison, Mary Dageforde — *Inside Java 2 Platform Security* (ISBN 0201787911)
- [JEP 411 — Deprecate the Security Manager for Removal](https://openjdk.org/jeps/411)
- [Apache River Project](https://river.apache.org/)
- [JGDMS Repository](https://github.com/pfirmstone/JGDMS)
- [CVE-2021-44228 — Log4Shell](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
- [OpenJDK JDK](https://github.com/openjdk/jdk)
- Relevant presentations linked from [README.md](README.md)

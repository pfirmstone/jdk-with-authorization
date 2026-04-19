# History of Java Authorization and the Origins of Dirty Chai

This document traces the history of Java's authorization and security architecture from its
origins through its deprecation and removal upstream, the ecosystem of projects that kept the
model alive, and the founding of Dirty Chai.

---

## 1. Java Security — Early Foundations (1995–1997)

Java 1.0 introduced a simple **sandbox model** aimed at applets running in web browsers. All
local code was fully trusted; all remotely loaded code ran in a tightly restricted sandbox with
no file system or network access beyond the originating host. The model was binary — trusted or
untrusted — with no middle ground. Java 1.0 also introduced **SecurityManager** as the platform
hook through which security checks were delegated, though at this stage it enforced only the
binary sandbox boundary.

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
- **SecurityManager** — reworked from its Java 1.0 origins into a general-purpose hook for
  the platform to call into application-level policy enforcement at security-relevant operations
  (file access, network access, class loading, etc.). Li Gong described it as an
  *Archimedes fulcrum* — the fixed point on which the entire security architecture pivots.
- **Principle of Least Privilege (POLP)** — the design philosophy that code should be granted
  only the minimum permissions it requires, documented by Li Gong in *Inside Java 2 Platform
  Security* (ISBN 0201787911).

The model was designed so that even if an attacker reached code deep in the call chain, the
least-privileged caller in the stack would limit what the exploit could accomplish.

---

## 3. The Jini Ecosystem: Research Origins, RMI, and JavaSpaces (c.1990–2004)

### People and Origins

The intellectual lineage of Jini and JavaSpaces begins well before 1999. At Sun Microsystems
Laboratories, **Jim Waldo** led the Large Scale Distribution research project. Jim Waldo and
**Ken Arnold** had previously worked together at Hewlett-Packard on the Object Management
Group's first CORBA specification, bringing that experience and a long background in distributed
computing to Sun Labs. **Ann Wollrath** later joined Jim's team there.

A pivotal product of this early period was *"A Note on Distributed Computing"*, co-authored by
Waldo, Wollrath, and colleagues. The paper identified critical distinctions between local and
distributed design and argued forcefully against the then-popular notion of "local/remote
transparency" — the idea that distributed and local objects could be made to behave identically
from the programmer's perspective. It became the most cited Sun Laboratories technical report, and
its lessons are at the core of the Jini design philosophy.

At that time the team was using **Modula 3 Network Objects** for distributed computing
experiments. As Modula 3 ceased to be developed, the team looked for a replacement and settled on
**Oak**, an internal Sun project whose interesting new properties outweighed its commercial
insignificance. Ken Arnold rejoined Jim's team at this point. Oak was soon renamed **Java**.

### RMI: Java's First Distributed Computing Mechanism

Oak had once included a remote method invocation mechanism, but it was removed when that
mechanism fell into the same local/remote transparency trap the team had been arguing against.
When **Bill Joy** and **James Gosling** wanted to build a working distributed computing
mechanism, they asked Jim Waldo to lead the effort, transitioning the team from Sun Labs into the
JavaSoft product group. The first result was **Java RMI**, with **Ann Wollrath** as architect.
RMI took a language-centric approach — in contrast to the language-neutral stacks of most
distributed computing systems of the era — and shipped as part of the Java platform with
Java 1.1 (1997).

### JavaSpaces: Tuple Spaces Come to Java

Alongside the core Jini platform, the team developed **JavaSpaces**, a realization of
*tuple spaces* — a coordination model first described in 1982 by **David Gelernter** in the
context of a language called **Linda**. Tuple spaces allow processes to communicate without any
mutual knowledge: one process releases a bundle of heterogeneous values (a "tuple") into a shared
space; another process reads or consumes it, with neither needing to know the other's name,
address, or even whether the other exists. **Nick Carriero**'s 1984 implementation at Bell Labs —
built on a custom multiprocessor — demonstrated that tuple-space communication could match the
efficiency of low-level message passing, and Linda went on to become one of the most widely used
vehicles for parallel programming. The JavaSpaces project at Sun originated with Bill Joy;
**Ken Arnold** led it, with **Jim Waldo**, **Ann Wollrath**, and **Bob Scheifler** responsible for
the actual design. The design and its rationale were documented in *JavaSpaces Principles,
Patterns, and Practice* (Freeman, Hupfer, Arnold — 1999).

### The Jini Platform and Team

After RMI became part of the Java platform, Bill Joy asked the team to expand its horizons to
include a platform for easier distributed computing, coining the name **"Jini"**. He convinced
Sun management to consolidate the RMI, JavaSpaces, and Jini projects into a separate unit. This
new unit started with Jim Waldo, Ann Wollrath, Ken Arnold, and **Peter Jones**, and was soon
joined by **Bob Scheifler**, who brought extensive distributed computing experience from the
X Windows project that he had run. This assembled the original core architectural team: Jim, Ann,
Ken, and Bob.

As the project grew, many people shaped different parts of the architecture: **Bryan O'Sullivan**
designed the lookup discovery protocol; **Mike Clary** gave the project organizational shelter
while it matured; **Mark Hodapp** managed software development in partnership with the technical
leadership. **Gary Holness**, **Zane Pan**, **Brian Murphy**, **John McClain**, and
**Bob Resendes** reviewed the primary architecture documents and took responsibility for tool
design, implementation design, and the implementations themselves. **Larid Dornin** and
**Adrian Colley** joined the RMI sub-team to continue and expand its development. **Charlie Lamb**
joined the architectural team to oversee work with outside companies, starting with printing and
storage service standards. **Jen McGinn** (later joined by **Susan Snyder**) documented the
project's work. **Jimmy Torres** began as release engineer and later shifted to building the
public developer community, with **Frank Barnaby** taking over release engineering duties.
**Helen Leary** kept the project's infrastructure running throughout.

### Technical Contributions to the Java Security Model

Sun's Jini Technology project, initiated in 1999, built a distributed services platform on top
of Java's security model. Jini's requirements pushed that model significantly:

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

### Practical Obstacles: NAT, IPv6, and Class Loading

Despite its technical elegance, Jini faced significant deployment obstacles in practice.

**IPv4 NAT and the loss of end-to-end connectivity** — Jini's discovery protocol relies on
IP multicast. IPv4 Network Address Translation (NAT), which became ubiquitous as IPv4 addresses
became scarce, breaks end-to-end multicast reachability and prevented Jini services from
discovering one another across NAT boundaries. This effectively confined Jini to private,
controlled network environments and was a major factor limiting wider adoption. JGDMS has since
added support for **IPv6 multicast discovery**, which restores genuine end-to-end connectivity
on networks that support it and removes this long-standing barrier.

**Class loading and resolution complexity** — Dynamic class loading — downloading service proxy
bytecode at runtime — was central to the Jini model, but introduced subtle and hard-to-diagnose
failures. The interaction between RMI's codebase annotation mechanism, the standard Java class
loading hierarchy, and the various class loaders active in a Jini deployment created a class
of problems that were difficult to understand and even harder to debug. These issues are
documented in depth by Michael Warres of Sun Microsystems Laboratories in *"Class Loading Issues
in Java RMI and Jini Network Technology"*. JGDMS resolved the core class resolution problems
through a revised class loading architecture, making the dynamic proxy model reliable in
production environments.

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
Java 1.1 (1997)       — Signed JARs, coarse-grained trust; Java RMI (Wollrath et al.)
Java 1.2 (1998)       — Full authorization architecture (Li Gong et al.)
                        ProtectionDomain, Policy, AccessController, SecurityManager
JavaSpaces (1999)     — Tuple-space coordination model; design by Arnold, Waldo, Wollrath, Scheifler
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
- Jim Waldo, Ann Wollrath, et al. — *"A Note on Distributed Computing"* (Sun Labs Technical Report, 1994)
- Jim Waldo (ed.) — *The Jini Specifications, Second Edition* (Addison-Wesley, 2000)
- Eric Freeman, Susanne Hupfer, Ken Arnold — *JavaSpaces Principles, Patterns, and Practice* (Addison-Wesley, 1999)
- Michael Warres (Sun Microsystems Laboratories) — *"Class Loading Issues in Java RMI and Jini Network Technology"*
- [JEP 411 — Deprecate the Security Manager for Removal](https://openjdk.org/jeps/411)
- [Apache River Project](https://river.apache.org/)
- [JGDMS Repository](https://github.com/pfirmstone/JGDMS)
- [CVE-2021-44228 — Log4Shell](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
- [OpenJDK JDK](https://github.com/openjdk/jdk)
- Relevant presentations linked from [README.md](README.md)

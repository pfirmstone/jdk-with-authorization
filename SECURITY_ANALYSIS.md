# Dirty Chai Security Analysis

**Date:** 2026-04-16  
**Project:** Dirty Chai  
**Scope:** `System.setSecurityManager()`, `AccessController`, `ConcurrentPolicyFile`, URI handling, guard permissions, Executors, and virtual-thread/security-manager interaction paths

---

## Executive Summary

Dirty Chai implements a layered authorization model with strong fail-secure behavior, explicit trust boundaries, and policy-centric permission enforcement. The current implementation is materially stronger than baseline OpenJDK in the analyzed areas.

This update corrects stale claims in the prior document, removes duplication, and captures current residual risks.

**Current assessment:** **Strong security posture with low-to-moderate residual risk, primarily policy/configuration dependent.**

---

## Comparison to OpenJDK 21 (LTS) — In-Depth

OpenJDK 21 is the last LTS release line that still includes SecurityManager APIs, but Dirty Chai applies materially stronger hardening in the analyzed paths.

| Area | OpenJDK 21 | Dirty Chai |
|---|---|---|
| `System.setSecurityManager()` behavior | Compatibility-focused path with `allow/disallow` gating and no Dirty Chai-style caller-stack hardening | Conditional trust gate plus layered validation for untrusted/custom SecurityManager implementations |
| Trusted-vs-untrusted SecurityManager distinction | No explicit `trustedSMClass()` gate with exact-class whitelist | Exact-class trust gate (`SecurityManager`, `CombinerSecurityManager`, `PolicyOnlySecurityManager`) |
| Reflection/generated-caller blocking for custom SM install | Not implemented as a dedicated layered defense at install time | Explicit stack/reflection/method-handle/generated-code blocking for custom SM install |
| Guard permission model | No `au.zeus.jdk.authorization.guards.*` guard classes | Adds dedicated guard permissions (`LoadClassPermission`, `NativeAccessPermission`, `SerialObjectPermission`) and integrates them into security-critical flows |
| Executors + thread factory behavior | `Executors.defaultThreadFactory()` returns classic `DefaultThreadFactory` | `Executors.defaultThreadFactory()` routes through `Thread.ofPlatform().group(...).factory()` and therefore through Dirty Chai platform-thread permission checks |
| Virtual thread creation path | `ThreadBuilders` virtual/platform builder paths do not enforce dedicated `createVirtualThread`/`createPlatformThread` checks | Builder `unstarted()` and `factory()` paths enforce explicit runtime permissions and capture `AccessController.getContext()` for inherited security context |
| `AccessController` / `AccessControlContext` / `Subject` model | OpenJDK 21 `doPrivileged(..., AccessControlContext, Permission...)` uses wrapper/context-validation flow (`checkContext`/`createWrapper`), with `Subject` propagation via ACC/`SubjectDomainCombiner` | Explicit limited-privilege domain intersection via `DomainIdentity`, ACC builder/authorization helpers, and dual ACC/`ScopedValue` Subject propagation |

### A) New Guards vs OpenJDK 21

Dirty Chai introduces and wires three new guard permissions that are absent in OpenJDK 21:

- `LoadClassPermission` (`au.zeus.jdk.authorization.guards.LoadClassPermission`)
  - integrated in `SecureClassLoader` (`LOAD_CLASS_ALLOW`) and checked during `ProtectionDomain` creation (`sm.checkPermission(LOAD_CLASS_ALLOW, ...)`)
- `NativeAccessPermission` (`au.zeus.jdk.authorization.guards.NativeAccessPermission`)
  - enforced in `Module.ensureNativeAccess(...)` before native/restricted access paths proceed
- `SerialObjectPermission` (`au.zeus.jdk.authorization.guards.SerialObjectPermission`)
  - enforced in `ObjectInputStream.readOrdinaryObject()` before `desc.newInstance()`

In OpenJDK 21, these specific guard classes and checks are not present. This is a structural authorization-surface expansion in Dirty Chai.

### B) Executors Delta vs OpenJDK 21

#### `Executors.defaultThreadFactory()`

- **OpenJDK 21:** returns `new DefaultThreadFactory()`
- **Dirty Chai:** returns `Thread.ofPlatform().name(...).group(...).factory()`

Security implication: Dirty Chai default executor thread factories now flow through platform-thread builder checks, including `RuntimePermission("createPlatformThread")` enforcement in `ThreadBuilders`.

#### `Executors.privilegedThreadFactory()`

Dirty Chai retains this authorization-relevant API path and updates internal checks to guard-based permission checks (`SecurityConstants.*.checkGuard(null)`) while preserving captured ACC/classloader semantics.

### C) Virtual Threads Delta vs OpenJDK 21

`Executors.newVirtualThreadPerTaskExecutor()` remains API-equivalent (`Thread.ofVirtual().factory()`), but its effective security posture differs because Dirty Chai changed the underlying builder path:

- `ThreadBuilders.VirtualThreadBuilder.unstarted/factory` now check `RuntimePermission("createVirtualThread")`
- platform builder paths analogously check `RuntimePermission("createPlatformThread")`
- builder-created factories/threads capture and propagate `AccessController.getContext()`

OpenJDK 21 builder paths do not include these explicit thread-creation runtime-permission checks, and use less restrictive inherited-context defaults.

### D) `AccessController`, `AccessControlContext`, and `Subject` Delta vs OpenJDK 21

#### `AccessController`

Dirty Chai changes the limited-privilege overload behavior from OpenJDK 21 wrapper construction to explicit permission-domain intersection:

- OpenJDK 21 `doPrivileged(..., AccessControlContext, Permission...)` paths use wrapper/context validation flow (`checkContext`/`createWrapper`).
- Dirty Chai computes a caller-linked protection domain (`DomainIdentity`, a Dirty Chai `ProtectionDomain` subtype in `src/java.base/share/classes/java/security/DomainIdentity.java`) from caller `CodeSource` + requested permissions and intersects it into the effective context before executing privileged code, binding the limitation directly to caller provenance instead of validating through a separate wrapper object.

Security impact: tighter binding of limited-privilege execution to caller provenance and explicit intersection semantics, reducing risk of over-broad inherited privilege in mixed-domain calls.

#### `AccessControlContext`

Dirty Chai introduces builder APIs not present in OpenJDK 21, plus authorization checks around ACC construction (`AccessControlContext.build(...)`, `checkAuthorized(...)`, permission intersection helpers).

Notable security effect versus OpenJDK 21:

- if caller lacks `createAccessControlContext`, Dirty Chai builder paths fold caller-context domains into the resulting ACC rather than allowing construction of a potentially more-privileged synthetic context.
- permission-limiting operations are represented as explicit ACC intersection operations (`intersectionPermissions`, `intersectionOfPermsDoWithCombiner`).

Security impact: stronger anti-escalation behavior when constructing or constraining ACCs programmatically.

#### `Subject`

Dirty Chai diverges from OpenJDK 21’s ACC-only retrieval/execution model by adding an explicit dual path:

- when the JVM SecurityManager-installation capability is enabled (`SharedSecrets.getJavaLangAccess().allowSecurityManager()` returns true): behavior remains ACC/`SubjectDomainCombiner` based (legacy compatibility path),
- when the JVM SecurityManager-installation capability is disabled (`allowSecurityManager()` returns false): `Subject.current()` / `Subject.callAs(...)` use `ScopedValue`-bound subject propagation.

Security impact: preserves legacy authorization checks where SecurityManager flows are active, while reducing dependence on deprecated ACC propagation where they are not.

---

## What Was Corrected (Errors in Prior Version)

1. **Incorrect claim: `System.getSecurityManager()` performs ProtectionDomain validation.**  
   **Current reality:** `getSecurityManager()` returns `security` directly and performs no validation.

2. **Outdated recommendation: “Update JavaDoc for conditional validation.”**  
   **Current reality:** `System.setSecurityManager()` JavaDoc already documents the conditional strategy.

3. **Outdated deserialization gap status.**  
   **Current reality:** `ObjectInputStream.readOrdinaryObject()` calls
   `new SerialObjectPermission(cl.getName()).checkGuard(null);` before
   `desc.newInstance()` (see
   `src/java.base/share/classes/java/io/ObjectInputStream.java`:
   line ~2231 check, line ~2234 instantiation), covering ordinary object paths at
   the common funnel point:
   - `new SerialObjectPermission(cl.getName()).checkGuard(null);`
   - `obj = desc.isInstantiable() ? desc.newInstance() : null;`

4. **Document duplication and drift.**  
   Repeated sections (“Conditional Validation Strategy” appeared multiple times), repeated conclusions, and stale recommendations were removed.

---

## Security Model (Current State)

### 1) SecurityManager Installation Gate (`System.setSecurityManager`)

`setSecurityManager(sm)` applies a **conditional validation strategy**:

- **Always:** reject `null` (`IllegalArgumentException`)
- **Trusted classes:** bypass deep validation
  - `SecurityManager`
  - `CombinerSecurityManager`
  - `PolicyOnlySecurityManager`
- **Untrusted/custom classes:** enforce layered checks
  1. Caller-sensitive direct caller check
  2. StackWalker scan (up to 50 frames)
  3. Caller ProtectionDomain retrieval/validation
  4. Generated/synthetic caller detection

**Key property:** trust gate uses exact class equality (`equals`), not `instanceof`, blocking subclass bypass.

### 2) Stack-Based Attack Detection

Custom SecurityManager installation path blocks:

- Reflection invocation frames (`java.lang.reflect.*`, `sun.reflect.*`)
- Unsafe invocation surfaces (`jdk.internal.misc.Unsafe`, `sun.misc.Unsafe`)
- Non-whitelisted `java.lang.invoke` call paths
- Common generated class patterns (`$$Lambda$`, generated accessor classes, proxy indicators)

### 3) Policy Enforcement / Fail-Secure Behavior

`ConcurrentPolicyFile` and related grant handling preserve fail-secure design:

- URI parse/validation failures are handled as security failures
- policy refresh error handling was hardened following Issue #85 fixes
- null/invalid code source paths are treated as non-privileged

### 4) URI/CodeSource Hardening

URI validation is consistently RFC-3986-oriented (via URI parsing paths), reducing path/encoding confusion risks during policy matching.

### 5) Deserialization Permission Boundary

`SerialObjectPermission` now executes at `ObjectInputStream.readOrdinaryObject()` before `desc.newInstance()`, which is the right boundary for ordinary object instantiation control.

### 6) RuntimePermission Thread-Creation Controls

Dirty Chai enforces explicit permissions for thread creation:

- `RuntimePermission("createPlatformThread")`
- `RuntimePermission("createVirtualThread")`

Enforcement points in current implementation include:

- `ThreadBuilders.PlatformThreadBuilder.unstarted/factory` (`createPlatformThread`)
- `ThreadBuilders.VirtualThreadBuilder.unstarted/factory` (`createVirtualThread`)
- `Thread.canCreatePlatformThread()` and platform construction path checks

Security effect:

- policy can separately govern code allowed to spawn platform vs virtual threads
- reduces uncontrolled thread-creation abuse risk (resource-exhaustion/DoS vectors)
- strengthens least-privilege for concurrent runtimes where thread creation is security-sensitive

---

## Threat Review (Current)

### Blocked or strongly mitigated

- Reflection-driven custom SecurityManager installation
- Generated-code caller spoofing for custom SecurityManager installation
- `setSecurityManager(null)` disablement attack
- URI/path-manipulation against policy CodeSource matching
- Several Issue #85 classes of exception-handling and validation drift

### Conditional / policy-dependent

- Trusted SecurityManager installation bypasses deep stack checks by design; safety depends on policy and runtime permission model.
- Mis-scoped policy grants can still over-authorize trusted code.
- Over-broad grants of `createVirtualThread` / `createPlatformThread` can expand DoS blast radius.

---

## Residual Risks and Omissions (Now Explicit)

1. **Finite stack scan depth (`limit(50)`)**  
   Deep-stack evasions are harder than before but still a theoretical residual if malicious frames fall outside scanned depth (see
   `src/java.base/share/classes/java/lang/System.java`, `validateCallerStackWithStackWalker()`, line ~2923).

2. **Heuristic generated-class detection**  
   Name-pattern detection can produce false positives/negatives in edge cases; it is not a formal proof of provenance.

3. **Trusted-class list governance risk**  
   Security relies on disciplined maintenance of `trustedSMClass()`; whitelist expansion is a high-impact operation.

4. **Policy quality remains critical**  
   The architecture is strong, but permissive policy files can negate hardening benefits.

5. **Cross-document consistency drift**  
   `VULNERABILITIES_ADDRESSED.md`, `SECURITY_MODEL.md`, and `EXECUTIVE_SUMMARY.md`
   may still describe older deserialization coverage status and should be synchronized:
   - remove/replace claims that `SerialObjectPermission` only applies to custom `readObject()` paths
   - align stack-frame scan depth references to current `limit(50)` behavior
   - remove claims that `getSecurityManager()` performs ProtectionDomain validation

---

## Recommendations

### High priority

1. **Keep `trustedSMClass()` under strict review control**  
   Any additions should require explicit security review and rationale.

2. **Add targeted regression tests for residual-risk boundaries**
   - Deep-stack attack simulation beyond typical frame depth
   - Edge-case generated/invoke frame classification

3. **Synchronize security docs**
    Align `VULNERABILITIES_ADDRESSED.md`, `SECURITY_MODEL.md`, and related docs with current deserialization and `getSecurityManager()` facts.
    Also align thread-creation permission guidance for `createVirtualThread` and `createPlatformThread`.

### Medium priority

4. **Consider making stack scan depth configurable (safe defaults retained)**
   This would support hardening in high-risk deployments while preserving compatibility defaults.

5. **Add optional security telemetry for denied installation attempts**
   Useful for attack detection and policy-tuning feedback loops.

---

## Final Assessment

Dirty Chai’s current implementation demonstrates robust defense-in-depth for SecurityManager installation and policy enforcement paths, with clear fail-secure tendencies and improved handling from the Issue #85 cycle.

The main remaining risks are **operational** (policy configuration and whitelist governance) rather than obvious structural bypasses in the reviewed core logic.

**Overall rating:** **Strong** (with documented residual risks).

---

## References

- `src/java.base/share/classes/java/lang/System.java` — conditional SecurityManager validation, stack-walk depth (`limit(50)`), trusted-class gate
- `src/java.base/share/classes/java/security/AccessController.java` — privileged execution and limited-privilege intersection behavior
- `src/java.base/share/classes/java/security/AccessControlContext.java` — ACC construction/authorization and intersection helpers
- `src/java.base/share/classes/java/security/DomainIdentity.java` — caller-linked protection-domain type used in limited-privilege intersection paths
- `src/java.base/share/classes/javax/security/auth/Subject.java` — subject propagation behavior across ACC and `ScopedValue` paths
- `src/java.base/share/classes/java/lang/ThreadBuilders.java` — enforcement points for `RuntimePermission("createPlatformThread")` and `RuntimePermission("createVirtualThread")`
- `src/java.base/share/classes/java/lang/Thread.java` — platform thread-creation security checks and builder security notes
- `src/java.base/share/classes/java/util/concurrent/Executors.java` — default/privileged thread factory behavior and virtual-thread executor entry points
- `src/java.base/share/classes/java/security/SecureClassLoader.java` — `LoadClassPermission` integration in class-loading permission path
- `src/java.base/share/classes/java/lang/Module.java` — `NativeAccessPermission` enforcement in native-access checks
- `src/java.base/share/classes/au/zeus/jdk/authorization/guards/LoadClassPermission.java` — guard definition
- `src/java.base/share/classes/au/zeus/jdk/authorization/guards/NativeAccessPermission.java` — guard definition
- `src/java.base/share/classes/au/zeus/jdk/authorization/guards/SerialObjectPermission.java` — guard definition
- `src/java.base/share/classes/java/io/ObjectInputStream.java` — `SerialObjectPermission` check placement in `readOrdinaryObject()` before instantiation
- `src/java.base/share/classes/java/io/SerialCallbackContext.java` — confirms callback context no longer carries the permission check logic
- `src/java.base/share/classes/au/zeus/jdk/authorization/policy/ConcurrentPolicyFile.java` — policy grant evaluation and fail-secure behavior references
- `src/java.base/share/classes/au/zeus/jdk/net/Uri.java` — URI validation behavior used in CodeSource/policy matching rationale
- Issue #85 (repository issue tracker) — remediation baseline for hardened exception and validation handling
- OpenJDK 21 reference (`jdk-21+35`): `java/lang/System.java`, `java/security/AccessController.java`, `java/security/AccessControlContext.java`, `javax/security/auth/Subject.java`, `java/lang/ThreadBuilders.java`, `java/lang/Thread.java`, `java/util/concurrent/Executors.java`, `java/security/SecureClassLoader.java`, `java/lang/Module.java`, `java/io/ObjectInputStream.java`

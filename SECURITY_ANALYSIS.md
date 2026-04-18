# Dirty Chai Security Analysis

**Date:** 2026-04-16  
**Project:** Dirty Chai  
**Scope:** `System.setSecurityManager()`, `AccessController`, `ConcurrentPolicyFile`, URI handling, guard permissions, Executors, and virtual-thread/security-manager interaction paths

---

## Executive Summary

Dirty Chai implements a layered authorization model with strong fail-secure behavior, explicit trust boundaries, and policy-centric permission enforcement. The current implementation is materially stronger than baseline OpenJDK in the analyzed areas.

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
| `AccessController` / `AccessControlContext` / `Subject` model | OpenJDK 21 `doPrivileged(..., AccessControlContext, Permission...)` uses wrapper/context-validation flow (`checkContext`/`createWrapper`), with `Subject` propagation via ACC/`SubjectDomainCombiner` | Explicit limited-privilege domain intersection via `DomainIdentity`, ACC builder/authorization helpers, and ACC/`SubjectDomainCombiner` subject propagation in active Dirty Chai runtime path |

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

### D) Additional `ManagementPermission` Checks (Including Native-Backed Paths)

Dirty Chai includes explicit `ManagementPermission("monitor")` / `ManagementPermission("control")` gating on management operations that feed into JNI/JMM native entry points.

- Permission gate implementation is centralized in `sun.management.Util` (`checkMonitorAccess` / `checkControlAccess`).
- Gate checks are applied in management implementations before privileged/native-backed operations, including:
  - `sun.management.ThreadImpl` (`getAllThreadIds`, `getThreadInfo`, deadlock queries, dumps, peak/cpu/contention controls)
  - `sun.management.MemoryImpl` / `MemoryPoolImpl` (verbosity and threshold/control operations)
  - `sun.management.ClassLoadingImpl` (`setVerbose`)
  - `sun.management.RuntimeImpl` (`getInputArguments`)
- Native operation surfaces for these paths are in `src/java.management/share/native/libmanagement/*.c` (`ThreadImpl.c`, `MemoryImpl.c`, `MemoryPoolImpl.c`, `ClassLoadingImpl.c`) via `jmm_interface`/JVM calls.

Security impact versus OpenJDK 21 baseline: Dirty Chai’s management surface is more explicitly permission-gated at Java entry points for operations that dispatch into native management functions, reducing risk of unauthorized runtime introspection/control through MXBean/JMM paths.

### E) `AccessController`, `AccessControlContext`, and `Subject` Delta vs OpenJDK 21

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

Dirty Chai runtime `Subject` behavior is single-path because `allowSecurityManager()` is always true (`System.java`):

- effective Dirty Chai runtime path: ACC/`SubjectDomainCombiner`-based retrieval and execution (legacy compatibility path)

Security impact in Dirty Chai runtime: legacy authorization checks remain consistently active for subject propagation paths.

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

### 7) ClassLoader Permission Boundary Separation

Dirty Chai enforces two distinct `RuntimePermission` checks for ClassLoader operations:

#### `RuntimePermission("createClassLoader")` — Creation Control

- **Purpose:** Gates the ability to **instantiate** ClassLoader's.
- **Enforcement point:** `ClassLoader.checkCreateClassLoader(String name)` called from all ClassLoader constructors
- **Check type:** Unconditional — executed for every ClassLoader instantiation attempt
- **Implementation:** Delegates to `SecurityManager.checkCreateClassLoader()` which checks `SecurityConstants.CREATE_CLASSLOADER_PERMISSION`
- **Policy integration:** Administrators can grant `createClassLoader` to allow code to instantiate loaders without granting extension rights

#### `RuntimePermission("extendClassLoader")` — Extension Control

- **Purpose:** Gates the ability to **extend/subclass** ClassLoader itself  
- **Enforcement point:** Conditionally checked within `ClassLoader.checkCreateClassLoader()` via `checkExtendClassLoader(Class<?>)`
- **Check type:** Conditional — only executed when caller is creating a ClassLoader subclass (not a built-in loader)
- **Stack-walk logic:** `checkExtendClassLoader()` performs stack inspection to identify the actual caller class and determine if extension is being attempted
- **Exemption list:** Built-in/trusted loaders are exempted:
  - `BuiltinClassLoader` — platform/system class loader
  - `URLClassLoader` — URL-based class loader
  - `JrtFileSystemProvider` — module/JRT file system provider
  - `Module$ModuleInfoLoader` — module metadata loader
  - `CDS$UnregisteredClassLoader` — CDS unregistered loader
  - `MethodUtil` — utility class for reflection
  - `Loader` — internal loader utility
- **Policy integration:** Administrators can restrict `extendClassLoader` to prevent custom loader implementations while still allowing code to use existing loaders

#### Security Effects

This two-permission split provides:

1. **Granular authorization:** Code can be authorized to use existing loaders without being able to create custom implementations
2. **Code-injection prevention:** Untrusted code cannot create rogue ClassLoader subclasses that could intercept class resolution
3. **Attack surface reduction:** Prevents proxy-style attacks where custom loaders masquerade as legitimate ones
4. **Least-privilege enforcement:** Each permission can be granted independently based on policy requirements

#### Integration with LoadClassPermission

The three-layer defense architecture works as follows:

- **Layer 1 (Creation/Extension):** `RuntimePermission("createClassLoader")` and `RuntimePermission("extendClassLoader")` gate who can create or extend class loaders
- **Layer 2 (Loading Control):** `LoadClassPermission` guard gates which classes can be loaded by whom
- **Layer 3 (Policy):** Admin-controlled policy file governs what code gets granted which permissions

This stratified approach ensures that even if code obtains a ClassLoader reference, it cannot load arbitrary code without explicit policy authorization.
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
   Security relies on disciplined maintenance of `trustedSMClass()`; whitelist expansion is a high-impact operation.  ClassLoader exemption list maintenance...

4. **Policy quality remains critical**  
   The architecture is strong, but permissive policy files can negate hardening benefits.

5. **Source-file Javadoc drift — resolved**  
   All repository Markdown documentation and Java source-file Javadoc comments are now
   consistent with the `limit(50)` implementation. `System.java` line 468 was corrected by
   the human author to read "50 stack frames", matching `limit(50)` at line 2923 and the
   "up to 50 frames" statement at line 424. No further drift is known.

---

## Recommendations

### High priority

1. **Keep `trustedSMClass()` under strict review control**  
   Any additions should require explicit security review and rationale.

2. **Add targeted regression tests for residual-risk boundaries**
   - Deep-stack attack simulation beyond typical frame depth
   - Edge-case generated/invoke frame classification

3. ~~**Correct stale Javadoc in `System.java` (source file)**~~  
   Resolved: `System.java` line 468 has been corrected by the human author to read "50 stack
   frames", consistent with `limit(50)` at line 2923 and "up to 50 frames" at line 424.
   All stack-scan-depth references are now consistent across source and documentation.

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
- `src/java.base/share/classes/javax/security/auth/Subject.java` — active ACC/`SubjectDomainCombiner` subject propagation path in Dirty Chai runtime
- `src/java.management/share/classes/sun/management/Util.java` — centralized `ManagementPermission("monitor"/"control")` gate checks
- `src/java.management/share/classes/sun/management/ThreadImpl.java` — management permission checks protecting native-backed thread inspection/control operations
- `src/java.management/share/classes/sun/management/MemoryImpl.java` — management permission checks for native-backed memory control operations
- `src/java.management/share/classes/sun/management/MemoryPoolImpl.java` — management permission checks for threshold/reset sensor operations
- `src/java.management/share/classes/sun/management/ClassLoadingImpl.java` — management permission checks before native class-loading verbosity control
- `src/java.management/share/classes/sun/management/RuntimeImpl.java` — monitor access checks on runtime-arguments access
- `src/java.management/share/native/libmanagement/ThreadImpl.c` — JNI/JMM thread management native entry points guarded by Java-side permission checks
- `src/java.management/share/native/libmanagement/MemoryImpl.c` — JNI/JMM memory management native entry points
- `src/java.management/share/native/libmanagement/MemoryPoolImpl.c` — JNI/JMM memory-pool management native entry points
- `src/java.management/share/native/libmanagement/ClassLoadingImpl.c` — JNI/JMM class-loading management native entry points
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

---

## Vulnerabilities identified and addressed in prior analysis:
(Issue [#85](https://github.com/pfirmstone/DirtyChai/issues/85) — All Findings Resolved)

A code review raised eleven findings (F-1–F-11) against the new `java.base` security code.
All were addressed by pfirmstone in nine commits on April 13, 2026.

| ID   | Severity | Description | Fix Committed |
|------|----------|-------------|---------------|
| F-1  | High | `limit(10)` in `validateCallerStackWithStackWalker()` allowed a deep-stack bypass | Raised to `limit(50)` |
| F-2  | High | `Uri.implies(null)` threw NPE; propagated as `RuntimeException` past `SecurityException` catch blocks | Null guard restored in `Uri.implies()` |
| F-3  | High | All-invalid-URI grant silently became a wildcard CodeSource grant | `URIGrant` constructor now throws `SecurityException` on any `URISyntaxException` |
| F-4  | Medium | `SecurityPolicyWriter` and `PolicyOnlySecurityManager` (bootstrap-loaded, `java.base`) ran through the full 4-layer custom-SM validation unnecessarily | Added `PolicyOnlySecurityManager` to `trustedSMClass()` whitelist; rationale for excluding `SecurityPolicyWriter` documented |
| F-5  | Medium | `ConcurrentPolicyFile.refresh()` silently swallowed errors and leaked paths to `System.err` | Now throws `SecurityException("Unable to refresh policy.", ex)` |
| F-6  | Medium | `CombinerSecurityManager` latch had a 180-second DoS window | Timeout reduced to 10 seconds |
| F-7  | Medium | Worker `ExecutionException` wrapped as `RuntimeException`, escaping `SecurityException` catch blocks; `Level.ERROR` tested but `Level.DEBUG` logged — exception silently dropped in production | `ExecutionException` cause now wrapped as `SecurityException("Unrecoverable: ", ex.getCause())` (no longer escapes as `RuntimeException`); `isLoggable(Level.DEBUG)` now guards `log(Level.DEBUG, ...)` in all affected paths |
| F-8  | Low | Truncated `LAYEAccessController.` comment in `System.java` | Corrected to `LAYER 3: AccessController.` |
| F-9  | Low | `Level.ERROR` tested but `Level.DEBUG` used — exception silently dropped in production | Fixed: `isLoggable(Level.DEBUG)` now guards `log(Level.DEBUG, ...)` |
| F-10 | Low | Overly broad `java.lang.invoke.*` filter could block legitimate JDK-internal linkage-time frames | Replaced with switch-based whitelist; linkage-time-only classes (`StringConcatFactory`, `LambdaMetafactory`, `MethodHandles`, `MethodType`, etc.) are now excluded |
| F-11 | Low | `sun.misc.Unsafe` not detected in `isUnsafeReflectionFrame()` | Added `sun.misc.Unsafe` check alongside `jdk.internal.misc.Unsafe` |

### Additional Fix — SocketPermission DNS Pre-fetch (DoS Prevention)

During the same review a denial-of-service risk was identified: hostname lookups in
`SocketPermission.implies()` would occur at access-check time (after the SecurityManager is
active), opening a window for DNS-based DoS attacks.

**Fix:** A new `SocketPermission.init()` method eagerly resolves the canonical hostname and
the untrusted-host flag during policy construction. `PermissionGrant` now calls `sp.init()`
for every `SocketPermission` added to a grant.

The `init()` catch block swallows `UnknownHostException` because `init()` starts from a
fail-secure `invalid = true` state; if hostname resolution fails, the permission remains invalid
and any subsequent `implies()` call returns `false`, so swallowing is fail-secure:

```java
invalid = true;
try {
    // hostname canonicalization / trust checks
} catch (UnknownHostException e){
    // Swallow: invalid remains true, failing securely.
}
```

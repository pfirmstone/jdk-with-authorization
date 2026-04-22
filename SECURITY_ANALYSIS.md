# Dirty Chai Security Analysis

**Date:** 2026-04-21  
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
| Guard permission model | No `au.zeus.jdk.authorization.guards.*` guard classes | Adds dedicated guard permissions (`LoadClassPermission`, `NativeInvocationPermission`, `NativeMemoryPermission`, `SerialObjectPermission`) and integrates them into security-critical flows |
| Runtime module-topology mutation API gate (`Module.addExports()` / `Module.addOpens()`) | No dedicated `RuntimePermission("mutateModuleTopology")` gate at these API entry points | `SecurityManager.checkPermission(new RuntimePermission("mutateModuleTopology"))` gate at runtime mutation entry points before caller-identity validation |
| Executors + thread factory behavior | `Executors.defaultThreadFactory()` returns classic `DefaultThreadFactory` | `Executors.defaultThreadFactory()` routes through `Thread.ofPlatform().group(...).factory()` and therefore through Dirty Chai platform-thread permission checks |
| Virtual thread creation path | `ThreadBuilders` virtual/platform builder paths do not enforce dedicated `createVirtualThread`/`createPlatformThread` checks | Builder `unstarted()` and `factory()` paths enforce explicit runtime permissions and capture `AccessController.getContext()` for inherited security context |
| `AccessController` / `AccessControlContext` / `Subject` model | OpenJDK 21 `doPrivileged(..., AccessControlContext, Permission...)` uses wrapper/context-validation flow (`checkContext`/`createWrapper`), with `Subject` propagation via ACC/`SubjectDomainCombiner` | Explicit limited-privilege domain intersection via `DomainIdentity`, ACC builder/authorization helpers, and ACC/`SubjectDomainCombiner` subject propagation in active Dirty Chai runtime path |

### A) New Guards vs OpenJDK 21

Dirty Chai introduces and wires four new guard permissions that are absent in OpenJDK 21:

- `LoadClassPermission` (`au.zeus.jdk.authorization.guards.LoadClassPermission`)
  - integrated in `SecureClassLoader` (`LOAD_CLASS_ALLOW`) and checked during `ProtectionDomain` creation (`sm.checkPermission(LOAD_CLASS_ALLOW, ...)`)
- `NativeInvocationPermission` (`au.zeus.jdk.authorization.guards.NativeInvocationPermission`)
  - enforced in `ClassLoader.findNative()`, `SymbolLookup.loaderLookup()`, `SymbolLookup.libraryLookup()`, and `SystemLookup` before native symbol addresses are returned; the permission name is the **resolved library name** (library-scoped), so each native library requires a separate, explicit policy grant
  - library name resolution is performed by `NativeLibraries.findLibraryNameAddress()`, which applies a three-level null-safe fallback: (1) the map key of the native library entry, (2) `NativeLibrary.name()`, (3) the symbol name itself — guaranteeing that `NativeInvocationPermission` is always constructed with a non-null name even when library path metadata is incomplete
- `NativeMemoryPermission` (`au.zeus.jdk.authorization.guards.NativeMemoryPermission`)
  - enforced at FFM native-memory boundaries: `Arena.global()` requires `NativeMemoryPermission("global-arena")`, and `AbstractMemorySegmentImpl.reinterpretInternal()` requires `NativeMemoryPermission("reinterpret-memory-segment")`
  - purpose: separate native-memory authority from native-symbol/native-library authority, so policy can independently control off-heap lifecycle/capability expansion operations
  - security effect: reduces memory-corruption and resource-exhaustion attack surface by requiring explicit permission before global-arena access or segment reinterpretation is allowed
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

**Principal identity model and cross-realm risk:**

DirtyChai does not currently define a canonical principal identity model beyond what the JDK provides (`Principal.getName()`). Policy grants keyed on principal class and name are compared by exact type and name string. This creates two residual risks:

1. **Cross-realm name collision** — two `Subject` instances from different authentication realms (e.g., `user@REALM-A` and `user@REALM-B`) share the same principal name if realm is not encoded in the `getName()` return value or if separate `Principal` subtypes are not used. A policy grant matching by name alone would apply to both subjects, enabling privilege escalation by a principal from an unintended realm. Administrators must use fully-qualified `Principal` types (e.g., `KerberosPrincipal` where the realm is embedded in the name) and avoid name-only matching across authentication domains.
2. **Trusted-service principal injection** — a trusted service that calls `subject.getPrincipals().add(...)` during or after authentication may unintentionally match an existing policy grant. If untrusted code can observe or trigger the principal set of a shared `Subject`, it can exploit the expanded grant. `Subject.getPrincipals()` returns the live mutable set; callers that modify it after the Subject is in use are subject to this risk. See residual N-12.

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

**Additional attack surfaces not directly blocked by `validateCallerStackWithStackWalker()` (documented residuals):**

- `MethodHandles.Lookup.in(Class<?> requestedLookupClass)` — a `Lookup` object obtained by trusted code and passed to untrusted code can be used to perform private/package-private field and method access across trust-domain boundaries. The stack walk blocks generation of a new `Lookup` via reflection, but does not revoke an already-transferred `Lookup` object's capabilities. This is an object-capability transfer risk rather than a stack-spoofing risk.
- `Instrumentation.getAllLoadedClasses()` / `Instrumentation.redefineClasses()` — reachable only when a `-javaagent` is active at startup. Runtime dynamic agent injection via `VirtualMachine.attach()` is gated by `AttachPermission` when the `SecurityManager` is active; hardened deployments should deny `AttachPermission("attachVirtualMachine")` to untrusted code and may also set `-XX:+DisableAttachMechanism` as defense in depth. See N-11.
- JVM startup flags `--add-opens`, `--add-exports`, `--add-modules` — these bypass module encapsulation before the SecurityManager is installed and cannot be revoked at runtime. They must be treated as part of the trusted deployment perimeter, not as runtime security controls subject to SecurityManager enforcement.

### 3) Policy Enforcement / Fail-Secure Behavior

`ConcurrentPolicyFile` and related grant handling preserve fail-secure design:

- URI parse/validation failures are handled as security failures
- policy refresh error handling was hardened following Issue #85 fixes
- null/invalid code source paths are treated as non-privileged

### 4) URI/CodeSource Hardening

URI validation is consistently RFC-3986-oriented (via URI parsing paths), reducing path/encoding confusion risks during policy matching.

### 5) Deserialization Permission Boundary

`SerialObjectPermission` now executes at `ObjectInputStream.readOrdinaryObject()` before `desc.newInstance()`, which is the right boundary for ordinary object instantiation control.

**Activation-group deserialization scope (undocumented boundary):**

The `SerialObjectPermission` enforcement described above applies to the calling JVM. It is not currently documented whether a group JVM (in an RMI activation scenario) re-enforces this permission when it reconstructs activatable objects from `ActivationDesc` descriptors passed by the activation daemon. Three specific gaps exist:

- **Descriptor integrity** — DirtyChai does not document whether activation-daemon-stored `ActivationDesc` objects are integrity-protected (e.g., with a signature or HMAC). A compromised or malicious activation daemon could inject arbitrary descriptors, causing the group JVM to deserialize objects that would have been blocked by `SerialObjectPermission` in the originating JVM.
- **Policy authority on re-activation** — it is undefined whether the group JVM applies its own policy file or the registering administrator's policy when evaluating `SerialObjectPermission` during activation reconstruction. If the group's policy is weaker, the permission check may be ineffective.
- **`AccessControlContext` freshness on restart** — when a group JVM crashes and restarts, it is unspecified whether it receives a fresh `AccessControlContext` or inherits state from the previous run. Stale context could carry permissions that were valid before a policy change, enabling escalation after a policy tightening event.

See residual N-13.

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

#### Delegation Attack Residuals

The three-layer defense model assumes binary loader trust (a loader is either trusted or untrusted). Several residual gaps exist at the boundaries:

- **Parent-delegation bypass** — a custom `ClassLoader` that overrides `loadClass(String)` and refuses parent delegation can introduce class name collisions (shadow classes). `RuntimePermission("extendClassLoader")` partially mitigates this by requiring explicit policy authorization to subclass `ClassLoader`. However, the exemption list (see above) means several built-in loader types can still exhibit delegation variation without triggering the extension check.
- **Resource lookup** — `ClassLoader.findResource()` and `getResource()` are not subject to `LoadClassPermission`. A hostile loader that passes the `extendClassLoader` gate can intercept and redirect resource lookups (property files, service descriptors, configuration files) without triggering any DirtyChai permission check.
- **Partial trust** — code that holds both `createClassLoader` and `LoadClassPermission` with selective delegation is not modeled by the three-layer architecture. The current design does not define the security properties of partially-trusted loaders that legitimately create ClassLoader instances but apply non-standard delegation policies.
- **Dynamic class definition via `MethodHandles.Lookup.defineClass()`** — classes defined through `MethodHandles.Lookup.defineClass()` bypass the `ClassLoader.loadClass()` path entirely and therefore bypass the `LoadClassPermission` gate. DirtyChai does not currently document whether a separate permission check guards `Lookup.defineClass()`. If unguarded, untrusted code with access to a sufficiently privileged `Lookup` object can inject new classes into an existing module without `LoadClassPermission`. See residual N-15 for the broader module interaction and the medium-priority recommendation below.

#### Module System and LoadClassPermission Interaction

`LoadClassPermission` and module-system encapsulation are independent, non-redundant gates operating at different layers:

- **Module enforcement layer** — the JVM enforces module access control at the bytecode level (reads, exports, opens). This applies to already-loaded classes and does not involve the SecurityManager.
- **SecurityManager enforcement layer** — `LoadClassPermission` is checked at class-load time by `SecureClassLoader`. It applies to classes being loaded, not to classes already present in the module layer.

These layers are not redundant. Untrusted code that is granted module `reads` access via an `--add-opens` or `--add-exports` JVM flag bypasses `LoadClassPermission` because the target class is already loaded; the SecurityManager check is never triggered for pre-loaded classes.

Additional module-specific risks:

- **Export cycle bridging** — if trusted module A exports a package to untrusted module B, and A's exported package contains a class with internal access to module C (a third module, not exported to B), then B gains indirect access to C's internals through A's public API surface. This indirect bridge is not blocked by either `LoadClassPermission` or module-system encapsulation as long as A's exported class remains reachable.
- **Module topology disclosure** — `Module.getDescriptor()`, `ModuleLayer.modules()`, and related reflection APIs are available to untrusted code without a permission check. These calls reveal the full module graph (names, packages, dependencies). DirtyChai currently accepts this as an information-disclosure risk; administrators should be aware that module topology is observable.
- **Hidden module pre-population** — the `--add-modules` JVM flag can force-load hidden modules before the SecurityManager is installed. Code in those modules is then available as a trusted bridge for untrusted access at runtime. This flag must be treated as part of the trusted deployment perimeter.

See residual N-15 and the medium-priority recommendation for a `LoadModulePermission` gate evaluation.

### 8) Foreign Function & Memory API (FFM) Trust Boundaries

DirtyChai adds SecurityManager permission gating on several FFM entry points.  Several residual risks remain:

- **`MemorySegment.reinterpret()`** — DirtyChai gates all three `reinterpret()` overloads with `NativeMemoryPermission("reinterpret-memory-segment")` (checked in `AbstractMemorySegmentImpl.reinterpretInternal()`). Code that does not hold this permission receives a `SecurityException`. This is the core boundary for controlling segment-size/capability reinterpretation.
- **`Arena.global()`** — DirtyChai gates global arena access with `NativeMemoryPermission("global-arena")` (checked in `Arena.global()`). This protects the process-wide native-memory arena from direct use by untrusted code unless explicitly authorized by policy.
- **Security impact of `NativeMemoryPermission`** — by requiring explicit grants at both reinterpret and global-arena boundaries, DirtyChai reduces the attack surface for memory-corruption and memory-retention abuse patterns (for example, unchecked reinterpretation and unbounded process-lifetime off-heap retention).
- **Binary module-open grants** — opening `jdk.foreign` to untrusted code still increases exposure to FFM APIs. Module opens do not replace SecurityManager checks; they only make API reachability easier. `NativeMemoryPermission` remains the enforcement gate for `reinterpret()` and `Arena.global()` calls.
- **Residual gaps / limitations (known hardening backlog)** — `NativeMemoryPermission` currently does not gate all native-memory allocation surfaces (for example, `Arena.ofConfined()`, `Arena.ofShared()`, and `Arena.ofAuto()` creation paths, and subsequent allocation through those arenas). This is a known, not-yet-finalized hardening area rather than a fully closed boundary. Object-capability transfer risk also remains: if trusted code creates/returns memory capabilities to untrusted code, the permission checks at guarded methods are the final boundary.

Policy guidance for administrators:

- Grant `NativeMemoryPermission` only to fully trusted code bases.
- Prefer explicit target names (`"global-arena"` and/or `"reinterpret-memory-segment"`) instead of wildcard grants.
- Treat any grant to code with broad `jdk.foreign` access as high sensitivity and document the operational rationale.
- Until broader FFM native-memory coverage decisions are finalized, treat grants that expose general arena-creation APIs as high risk and constrain them to trusted code only.

See the FFM bullet under the Conditional / policy-dependent section and the medium-priority recommendation for broader FFM guard-coverage evaluation.

### 9) Network Permission Granularity

DirtyChai enforces network access through standard `SocketPermission` grants and the DNS pre-fetch hardening described at the end of this document. However, the current policy model has structural coarseness risks:

- **Wildcard `connect` grants** — a `SocketPermission("*", "connect")` grant authorizes connections to any host. DirtyChai policy guidance recommends avoiding wildcards entirely. Hardened policy should specify separate grants at minimum for loopback (`localhost`), LAN/subnet (e.g., `192.168.0.0/16`), multicast address ranges (e.g., `224.0.0.0/4`), and external addresses.
- **Unconnected `DatagramSocket` discovery** — an unconnected `DatagramSocket` can be used by untrusted code to perform local-network peer discovery (UDP broadcast/multicast enumeration). This requires `SocketPermission` with `accept` or `connect` to the relevant address range, but policy grants that are intended only for application traffic may inadvertently authorize discovery. This is not blocked by the module system alone and requires explicit policy governance.
- **`MulticastSocket.getInterface()` topology disclosure** — calling `getInterface()` or `getNetworkInterface()` on a `MulticastSocket` leaks local network interface topology (interface names, addresses, subnet membership). Policy should explicitly separate multicast permissions from unicast permissions to limit information disclosure to code that legitimately requires multicast capability.

See residual N-14.

### 10) Module Topology Mutation Permission

DirtyChai now gates runtime module-topology mutation APIs with
`RuntimePermission("mutateModuleTopology")`.

- **Enforcement points** — `Module.addExports(String, Module)` and
  `Module.addOpens(String, Module)` perform
  `SecurityManager.checkPermission(new RuntimePermission("mutateModuleTopology"))`
  at API entry before caller-identity validation.
- **Security effect** — untrusted code can no longer mutate module export/open
  topology at runtime unless explicitly granted policy authority.
- **Threat-model effect (N-15)** — runtime reflective module mutation now has an
  explicit policy gate; this closes the previously documented ungated mutation
  surface for these APIs.
- **Static vs runtime mutation boundary** — this gate applies to runtime API
  calls only. JVM bootstrap flags (`--add-opens`, `--add-exports`,
  `--add-modules`) remain startup-time trust-boundary decisions and are not
  retroactively constrained by this runtime permission.

Policy guidance for administrators:

- Default deny `RuntimePermission("mutateModuleTopology")` to untrusted code.
- Grant only to narrowly scoped, fully trusted code that must perform runtime
  reflective integration.
- Continue treating all module-altering JVM flags as explicit deployment-time
  security decisions.

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
- Opening `jdk.foreign` to untrusted code increases reachability of FFM APIs, including `MemorySegment.reinterpret()` and `Arena.global()`, both gated by `NativeMemoryPermission`; such module-open grants must be treated as high-sensitivity policy decisions.
- Principal name-keyed policy grants are vulnerable to cross-realm name collision; administrators must use fully-qualified principal types in grants (e.g., `KerberosPrincipal` with realm embedded) and avoid name-only matching across authentication domains.
- Module export grants to untrusted code may introduce indirect access paths via trusted code's public APIs; every export decision must be reviewed as a security-relevant policy choice.

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

6. **Reflection and MethodHandle invocation paths (N-8)**  
   `Method.invoke()` and `MethodHandle.invoke*()` do **not** remove the untrusted
   caller's `ProtectionDomain` from the permission-check stack walk.  DirtyChai's
   `validateCallerStackWithStackWalker()` already blocks custom `SecurityManager`
   installation via both reflection and non-whitelisted `java.lang.invoke.*` frames.
   The residual is the same as the general confused-deputy rule: trusted code that
   uses unrestricted `doPrivileged` inside a method reachable via reflection can still
   drop the untrusted caller's domain from the intersection.  See detailed analysis
   **N-8** below.

7. **Finalizer and Cleaner thread context escape (N-9)**  
   Untrusted code in a finalizer or `Cleaner` callback is guarded by stack-intersection
   because the untrusted class's `ProtectionDomain` is present on the finalizer thread's
   stack at the time of any permission check.  Finalizer threads are now created with
   `AccessControlContext.neverPrivileged()` (matching `Cleaner` daemon behavior via
   `InnocuousThread`), so this residual is narrower than before.  The remaining gap is
   context escape: the creator thread's limited `AccessControlContext` is **not**
   propagated to finalizer/Cleaner callback threads.  Trusted objects whose finalizers
   perform sensitive operations are therefore not constrained by the context the creating
   code was running under.
   Mitigation: avoid sensitive operations in finalizers; use explicit `close()` patterns
   and process isolation for strong context-confinement.  See detailed analysis
   **N-9** below.

8. **Constant-pool and class-initialization leakage (N-10)**  
   `<clinit>`, `invokedynamic` bootstrap methods, and `CONSTANT_Dynamic` all execute on
   the triggering thread's call stack, so the untrusted caller's `ProtectionDomain` is
   present and the stack-intersection guard applies.  The `LoadClassPermission` gate
   prevents untrusted code from loading new classes.  The residual is the same
   confused-deputy rule: trusted `<clinit>` or bootstrap methods that use unrestricted
   `doPrivileged` can drop the untrusted triggering caller's domain from the intersection.
   See detailed analysis **N-10** below.

9. **Runtime instrumentation attach (N-11)**  
   `VirtualMachine.attach()` is policy-gated when the `SecurityManager` is active. The attach path enforces `AttachPermission("attachVirtualMachine")`, and attach-provider construction enforces `AttachPermission("createAttachProvider")`, so runtime attach is not an ungated surface inside DirtyChai's Java security model. Residual risk remains if policy over-grants these permissions, if the `SecurityManager` is inactive, or for hostile OS-level control of the JVM process. `-XX:+DisableAttachMechanism` remains recommended as an optional VM-level defense-in-depth layer.

10. **Principal scope and isolation (N-12)**  
    DirtyChai does not currently define whether principals are globally unique or scoped to an authentication domain. Policy grants keyed on principal class and name are vulnerable to cross-realm name collision (two subjects from different realms sharing the same `getName()` value) and to trusted-service principal injection (a trusted service mutating a shared `Subject`'s principal set after policy evaluation). Recommendation: define a canonical principal identity model; consider adding a permission check on `Subject.getPrincipals()` mutating calls when the subject is in use by untrusted code.

11. **Activation deserialization authority (N-13)**  
    The `SerialObjectPermission` check documented in §5 applies to the calling JVM at `ObjectInputStream.readOrdinaryObject()`. It is not documented whether this check is re-enforced inside a group JVM at activation reconstruction time, nor whether the group's own policy file or the registering administrator's policy takes precedence. Crash-recovery `AccessControlContext` freshness is also undefined. A compromised activation daemon could inject arbitrary `ActivationDesc` descriptors, bypassing the permission boundary documented here.

12. **Coarse network permission granularity (N-14)**  
    Current `SocketPermission` grants do not distinguish multicast from unicast, local loopback from LAN ranges, or connected sockets from unconnected discovery sockets. Over-broad grants (e.g., wildcard `connect`) expose local network topology and enable peer discovery attacks via unconnected `DatagramSocket`. DirtyChai documentation does not yet provide guidance on the recommended grant structure for hardened deployments. See §9 and the medium-priority recommendation.

13. **Module export cycles and hidden module visibility (N-15)**  
    DirtyChai now gates runtime `Module.addOpens()` and `Module.addExports()`
    mutations with `RuntimePermission("mutateModuleTopology")`, closing the
    previously ungated runtime mutation surface. Residual N-15 risk remains for
    independent module-system behavior outside this runtime API gate:
    `--add-opens`/`--add-exports` JVM flags can still bypass
    `LoadClassPermission` for already-loaded classes; `--add-modules` still
    pre-populates the module layer before the SecurityManager is installed; and
    `MethodHandles.Lookup.defineClass()` still bypasses `LoadClassPermission`
    for dynamically defined classes. Export cycles can still create indirect
    access bridges via trusted public API surfaces. See §7, §10, and the
    remaining medium-priority recommendations.

---

## Analysis: Reflection and MethodHandle Invocation in the Permission-Check Path (N-8)

### The Question

Does `Method.invoke()` or `MethodHandle.invoke*()` allow untrusted code to bypass
`SecurityManager.checkPermission` and the stack-intersection semantics that protect
confused-deputy native-call scenarios?  Specifically:

1. Does the reflective frame remove the untrusted caller's `ProtectionDomain` from
   the permission-check stack walk?
2. Can an attacker install a custom `SecurityManager` via a reflected call?
3. Does a `MethodHandle` invocation create frames that evade the confused-deputy
   guard?

### How Stack Intersection Works

`AccessController.getContext()` (called inside `SecurityManager.checkPermission`)
walks the live call stack and computes the *intersection* of every
`ProtectionDomain` present on the stack.  It stops only at an
`AccessController.doPrivileged(...)` frame.

A reflective call inserts frames from `java.lang.reflect` (or
`sun.reflect.GeneratedMethodAccessor*`) between the untrusted caller frame and
the target method.  Those intermediate frames belong to `java.base`, which holds
`AllPermission`.  However, the untrusted caller's frame is **still on the stack
below the reflection frames**.  The stack walk reaches it and includes its
`ProtectionDomain` in the intersection.

**Consequence:** `Method.invoke()` does **not** remove the untrusted caller from
the permission-intersection.  If the untrusted caller lacks
`NativeInvocationPermission`, a permission check for that permission anywhere in
the reflective call chain will still fail.

```
Stack (innermost first)
─────────────────────────────────────────────────
TrustedClass.nativeWrapper()        ← checks NativeInvocationPermission
  ↑ called via reflection ↓
java.lang.reflect.Method.invoke()   ← java.base, AllPermission
  ↑ called by ↓
UntrustedClass.attack()             ← no NativeInvocationPermission
  ↑ called by ↓
Thread.run()
─────────────────────────────────────────────────
Intersection: AllPermission ∩ AllPermission ∩ {no NativeInvocationPermission} = DENY
```

### Installing a Custom SecurityManager via Reflection

DirtyChai's `System.setSecurityManager()` is `@CallerSensitive`.  After the direct
caller check, it invokes `validateCallerStackWithStackWalker()`, which walks the
call stack and throws `SecurityException` if any frame belongs to:

- `java.lang.reflect.*` or `sun.reflect.*`
- `jdk.internal.misc.Unsafe` / `sun.misc.Unsafe`
- Non-whitelisted `java.lang.invoke.*` call paths
- Common generated-class patterns (`$$Lambda$`, proxy indicators, generated accessors)

A call of the form `setSecurityManagerMethod.invoke(null, myCustomSM)` inserts a
`java.lang.reflect.Method` frame into the stack.  The stack walker detects this
reflection frame and throws `SecurityException` before the custom
`SecurityManager` is installed.  **This attack path is blocked by DirtyChai.**

### MethodHandle Invocation Frames

`MethodHandle.invoke()` / `MethodHandle.invokeExact()` produce frames in the
`java.lang.invoke` package.  DirtyChai's stack-walk inspection uses a
switch-based whitelist (added as part of the F-10 remediation) that allows only
linkage-time-only `java.lang.invoke` classes to pass:

| Class | Status in whitelist | Reason |
|-------|---------------------|--------|
| `java.lang.invoke.LambdaMetafactory` | Allowed | Linkage-time only |
| `java.lang.invoke.StringConcatFactory` | Allowed | Linkage-time only |
| `java.lang.invoke.MethodHandles` | Allowed | Lookup utility, linkage-time |
| `java.lang.invoke.MethodType` | Allowed | Type descriptor, linkage-time |
| `java.lang.invoke.MethodHandle` (invocation frames) | **Blocked** | Runtime invocation frame |
| `java.lang.invoke.MethodHandles$Lookup` (runtime invoke) | **Blocked** | Runtime invocation frame |

A `MethodHandle` that targets `System.setSecurityManager` would leave a
`java.lang.invoke.MethodHandle` invocation frame on the stack.  That frame is
**not** in the linkage-time whitelist, so the stack walk blocks installation of a
custom `SecurityManager` via this path.  **This attack path is blocked by DirtyChai.**

### MethodHandle Lookup and Caller Context

`MethodHandles.Lookup` captures the *lookup class* at creation time, not an
`AccessControlContext`.  The lookup class governs which members are accessible
via the lookup (access-control semantics at *lookup creation* time).

However, when a `MethodHandle` is invoked at runtime, the *live call stack* is
used for any subsequent `SecurityManager.checkPermission()` calls triggered by
the target method.  The lookup class context does not replace the calling thread's
live stack.  The same stack-intersection logic described above applies: the
untrusted caller's `ProtectionDomain` is present on the stack at the point of
any permission check inside the target.

### Residual Considerations

**Unrestricted `doPrivileged` inside the target:** The confused-deputy protection
described in the "Remaining Residual Gaps" section above applies equally to
reflective and `MethodHandle` call paths.  If the *target* method uses unrestricted
`AccessController.doPrivileged(...)`, the stack walk stops at that frame, removing
the untrusted caller's domain from the intersection.  This is a design obligation
for trusted library authors — see Task N-6 guidance.

**`Lookup.in(otherClass):`** Allows creating a lookup in another class's namespace.
`SecurityManager.checkPackageAccess()` is called during lookup construction for
non-accessible packages, gating cross-package access.

**`MethodHandle` adapters (`asType`, `bindTo`, `asSpreader`):** These create
wrapper method handles.  Invocation still places frames from the calling code on
the live stack; the adapter frames belong to `java.base`.  No bypass is introduced.

### Summary — Reflection and MethodHandle Path Status

| Attack Scenario | Stack Walk Result | DirtyChai Status |
|-----------------|-------------------|-----------------|
| `Method.invoke(target, args)` used to trigger a native permission check | Untrusted caller PD remains on stack; intersection enforced | **Protected by default** |
| `Method.invoke(null, customSM)` to install custom `SecurityManager` | Reflect frame detected by `validateCallerStackWithStackWalker()` | **Blocked by DirtyChai** |
| `MethodHandle.invoke` to install custom `SecurityManager` | Non-whitelisted `java.lang.invoke.*` frame detected | **Blocked by DirtyChai** |
| `MethodHandle.invoke` to call trusted class native method | Untrusted caller PD remains on stack; intersection enforced | **Protected by default** |
| Trusted target uses unrestricted `doPrivileged` inside reflective call | Stack walk stops at `doPrivileged`; untrusted caller PD dropped | **Residual gap — trusted code must not use unrestricted `doPrivileged`** |

---

## Analysis: Finalizer and Cleaner Thread Execution Contexts (N-9)

### The Question

Finalizer threads and `java.lang.ref.Cleaner` daemon threads execute callback
code in a different thread than the one that created the object.  Does this
mean the original creator's restricted `AccessControlContext` is lost, and can
this loss be exploited to run sensitive operations with escalated permissions?

### Finalizer Thread Execution Model

When the JVM determines that an object with a non-trivial `finalize()` method is
no longer strongly reachable, it enqueues the object onto an internal finalizer
queue.  A dedicated daemon thread (typically named `Finalizer`) dequeues objects
and calls their `finalize()` method.

The finalizer thread is created during JVM bootstrapping via:
`AccessController.doPrivileged(..., AccessControlContext.neverPrivileged())`.
This preserves the privileged thread-creation step while ensuring the resulting
`Finalizer` thread executes with a never-privileged context (parity with
`Cleaner` daemon behavior).  The *creator thread's* `AccessControlContext` is
still **not** inherited by the finalizer thread and is **not** available when
`finalize()` runs.

### Stack Composition During Finalization

When `finalize()` executes, the call stack looks like:

```
java.lang.ref.Finalizer$FinalizerThread.run()  ← java.base, neverPrivileged context
  java.lang.ref.Finalizer.runFinalizer()        ← java.base, neverPrivileged context
    UntrustedClass.finalize()                   ← untrusted ProtectionDomain
      [any permission check triggered here]
```

When `SecurityManager.checkPermission()` is called from within `finalize()`,
`AccessController.getContext()` walks this stack.  The `UntrustedClass`
frame **is on the stack** and its `ProtectionDomain` is included in the
intersection.

If `UntrustedClass` lacks `NativeInvocationPermission`, any permission check
for that permission during `finalize()` will fail.  **DirtyChai's
stack-intersection guard therefore applies to untrusted finalizer code.**

### The Execution-Context Escape

The genuine threat is subtler: the **creator's restricted context is lost**, not
that the finalizer gains extra permission beyond what the class is granted by
policy.  Concretely:

1. Trusted code runs a restricted operation under a limited
   `AccessControlContext` (e.g., `doPrivileged(action, limitedContext)`).
2. Inside that limited scope, a trusted object is created whose `finalize()`
   performs a sensitive native call.
3. The creator's limited context was deliberately preventing that native call.
4. When the object is GC'd, the finalizer runs on the finalizer thread where
   the limited context **does not apply**.
5. The trusted class holds `NativeInvocationPermission` in its policy grant.
6. `SecurityManager.checkPermission()` succeeds because only the trusted class's
   domain and the `java.base` finalizer frames are on the stack.

**In this scenario, the finalizer thread performs an action that the creating
thread's limited context was intended to prevent.**  The in-process guard does
not protect against this because the constraint was encoded in the thread's
`AccessControlContext`, not in the class's policy grant.

### Cleaner Callbacks (java.lang.ref.Cleaner)

`java.lang.ref.Cleaner` (introduced in Java 9) is the recommended replacement
for `finalize()`.  A `Cleaner.Cleanable` is registered by supplying a
`Runnable` that is invoked when the registered object becomes phantom-reachable.

The `Cleaner` creates its own daemon thread using `InnocuousThread` (no
permissions).  The `Runnable` implementation class **is** on the stack when the
callback fires, so its `ProtectionDomain` is included in the
permission-intersection.  The execution-context-escape property is the same as
for finalizers: the context of the code that called `Cleaner.register(...)` is
not preserved for the callback thread.

### Policy Decision

| Scenario | In-Process Guard (DirtyChai) | Process Isolation Required? |
|----------|------------------------------|-----------------------------|
| Untrusted class finalizer calls native method | Stack intersection blocks it — untrusted PD on stack | No (in-process guard sufficient) |
| Trusted class finalizer / Cleaner callback calls native method | Allowed only if trusted class policy grants `NativeInvocationPermission`; finalizer/Cleaner threads themselves are unprivileged | No (this is intended behavior) |
| Trusted class finalizer bypasses a creator's limited context | **Not blocked** — limited context is not part of policy grant | **Yes — use process isolation** |
| Attacker triggers GC of a trusted object whose finalizer does privileged work | Allowed if trusted class has the permission | Mitigate by avoiding sensitive ops in finalizers |

### Guidance for Trusted Library Authors

Trusted classes whose finalizers or `Cleaner` callbacks perform sensitive
operations (native calls, file I/O, network access) should:

1. **Prefer `Cleaner` over `finalize()`** — `Cleaner` avoids JVM finalizer
   thread contention and is more predictable in timing.
2. **Use `doPrivileged` with a minimal limited context** inside the callback if
   the operation must succeed regardless of the invoking (finalizer) thread's
   inherited context, and document explicitly why the bypass of the caller
   context is safe.
3. **Avoid encoding application-level security constraints in finalizers.**
   If a security constraint must survive GC, enforce it at the time of object
   construction or through an explicit `close()` / `release()` pattern, not via
   finalization.
4. **Process isolation is the ultimate backstop:** an attacker that exploits a
   finalizer-context escape is still confined to the OS process boundary.

---

## Analysis: Constant-Pool and Class-Initialization Security (N-10)

### The Question

Java class initialization (`<clinit>`) and the constant-pool resolution mechanisms
(`invokedynamic`, `CONSTANT_Dynamic`) trigger executable code lazily — at the point
of first use, which may be on any thread and in any calling context.  Does this
lazy execution model allow privileged effects to occur outside the security
assumptions of the calling code?

### Class Initialization (`<clinit>`) and the Call Stack

Class initialization runs when a class is first *actively used*: `new`, `getstatic`,
`putstatic`, `invokestatic`, `Class.forName()` with `initialize=true`, etc.  The
JVM guarantees class initialization is thread-safe: the initializing thread holds
the class's initialization lock while `<clinit>` executes, and other threads block
until initialization completes.

The critical security property is **stack membership**: the thread that triggers
class initialization has its complete call stack present when `<clinit>` runs.  If
untrusted code triggers initialization of a trusted class, the untrusted caller's
frame **is on the stack** when `<clinit>` executes.

```
UntrustedClass.doSomething()          ← triggers TrustedClass static field access
  ↑ triggers initialization ↓
TrustedClass.<clinit>()               ← trusted ProtectionDomain
  [SecurityManager.checkPermission called here]
```

`SecurityManager.checkPermission()` during `<clinit>` intersects:
- `TrustedClass`'s `ProtectionDomain` (has `NativeInvocationPermission`), AND
- `UntrustedClass`'s `ProtectionDomain` (does **not** have `NativeInvocationPermission`)

**Result:** permission check fails.  **DirtyChai's stack-intersection guard
applies during class initialization triggered by untrusted code.**

### The `LoadClassPermission` Gate

Before a class can be triggered for initialization by untrusted code, it must first
be *loaded* into the untrusted class's namespace.  DirtyChai gates class loading
with `LoadClassPermission`.  Untrusted code that is not granted
`LoadClassPermission("some.trusted.Class")` cannot cause that class to be loaded
into its classloader's namespace, and therefore cannot trigger its `<clinit>`.

Once a class has been loaded (e.g., because the system loaded it at startup),
further references from untrusted code to already-loaded classes in its namespace
can trigger initialization without re-checking `LoadClassPermission`.  The
`LoadClassPermission` gate applies to the *loading* step, not to the
*initialization* step.

**Residual:** If a class was previously loaded (e.g., by platform startup code)
into a classloader namespace that untrusted code can reach, untrusted code may
trigger initialization of that class without holding `LoadClassPermission`.  The
stack-intersection guard still applies at any permission check inside `<clinit>`.

### Unrestricted `doPrivileged` Inside `<clinit>`

The same confused-deputy risk applies here as in normal method calls.  If
`<clinit>` uses **unrestricted** `AccessController.doPrivileged(...)`, the stack
walk stops at that frame, removing the untrusted triggering caller's domain from
the intersection.  This gives `<clinit>` a privilege elevation path reachable by
untrusted code.

**Obligation for trusted library authors:** Do **not** use unrestricted
`doPrivileged` inside `<clinit>` (or any static initializer block) on code paths
that access security-sensitive resources.  Use `doPrivileged` with a
restricted `AccessControlContext` or with an explicit `Permission` list.

### `invokedynamic` Bootstrap Methods

An `invokedynamic` call site is resolved lazily: the first time the JVM executes
the `invokedynamic` bytecode, it calls the designated *bootstrap method* to
produce a `CallSite`.  Subsequent invocations use the cached `CallSite` directly.

Bootstrap methods run on the *calling thread* at the point of first invocation.
The calling thread's stack is fully present during bootstrap resolution.  Standard
JDK bootstrap methods (`LambdaMetafactory`, `StringConcatFactory`) are trusted
`java.base` code.  Custom bootstrap methods defined in application code run in the
context of whatever thread first executes the call site.

**Security impact:**
- If untrusted code has an `invokedynamic` call site targeting a custom bootstrap
  method that performs a sensitive operation, the untrusted class's frame **is on
  the stack** during resolution, so permission checks inside the bootstrap method
  are intersection-enforced.
- If the bootstrap method uses unrestricted `doPrivileged`, the same confused-deputy
  risk applies.

### `CONSTANT_Dynamic` (JEP 309)

`CONSTANT_Dynamic` (Java 11+) allows constant-pool entries whose values are
computed at runtime by bootstrap methods, lazily on first `ldc`.  The security
model is identical to `invokedynamic`: the calling thread's stack is present, and
any permission check during bootstrap execution is intersection-enforced.

### Class Initialization Deadlock (Security Dimension)

Two classes whose `<clinit>` blocks hold initialization locks in a circular
dependency can deadlock (JVMS §5.5).  In a security context, an attacker
controlling one class in the dependency cycle could induce a DoS by triggering
initialization in two threads simultaneously.  DirtyChai's `LoadClassPermission`
gate reduces this risk by preventing untrusted code from loading new classes into
the namespace in the first place.

### Summary — Class-Init and Constant-Pool Path Status

| Scenario | Stack Walk Result | DirtyChai Status |
|----------|-------------------|-----------------|
| Untrusted code triggers `<clinit>` of trusted class | Untrusted PD on stack; intersection enforced | **Protected by default** |
| Trusted `<clinit>` uses unrestricted `doPrivileged` | Stack walk stops; untrusted PD dropped | **Residual gap — trusted code must not use unrestricted `doPrivileged`** |
| Untrusted code loads new class (which would trigger `<clinit>`) | `LoadClassPermission` blocks loading | **Blocked by DirtyChai** |
| Untrusted code triggers `<clinit>` of already-loaded trusted class | Untrusted PD on stack; intersection enforced | **Protected by default** |
| `invokedynamic` bootstrap method invoked from untrusted code | Untrusted PD on stack; intersection enforced | **Protected by default** |
| Bootstrap method uses unrestricted `doPrivileged` | Stack walk stops; untrusted PD dropped | **Residual gap — same as confused-deputy rule** |
| `CONSTANT_Dynamic` ldc from untrusted code | Untrusted PD on stack; intersection enforced | **Protected by default** |

---

## Recommendations

### High priority

1. **Keep `trustedSMClass()` under strict review control**  
   Any additions should require explicit security review and rationale.

2. **Add targeted regression tests for residual-risk boundaries**
   - Deep-stack attack simulation beyond typical frame depth
   - Edge-case generated/invoke frame classification
   - Reflection and MethodHandle paths through trusted native wrappers (N-8 test plan)
   - Finalizer / Cleaner thread permission enforcement (N-9 test plan)
   - Class-initialization stack-intersection enforcement (N-10 test plan)

3. ~~**Correct stale Javadoc in `System.java` (source file)**~~  
   Resolved: `System.java` line 468 has been corrected by the human author to read "50 stack
   frames", consistent with `limit(50)` at line 2923 and "up to 50 frames" at line 424.
   All stack-scan-depth references are now consistent across source and documentation.

4. **Document hardened-deployment attach controls and JVM flag requirements (N-11)**  
   Hardened deployments MUST deny `AttachPermission("attachVirtualMachine")` (and, where appropriate, `AttachPermission("createAttachProvider")`) to untrusted code. Deployments SHOULD also launch with `-XX:+DisableAttachMechanism` as VM-level defense in depth. Deployments MUST NOT use `--add-opens`, `--add-exports`, or `--add-modules` JVM flags unless each flag has been explicitly reviewed as a security-relevant policy decision. These flags bypass module encapsulation before the SecurityManager is installed and cannot be revoked at runtime; they must be treated as part of the trusted deployment perimeter.

### Medium priority

5. **Consider making stack scan depth configurable (safe defaults retained)**
   This would support hardening in high-risk deployments while preserving compatibility defaults.

6. **Add optional security telemetry for denied installation attempts**
   Useful for attack detection and policy-tuning feedback loops.

7. **Evaluate broader FFM native-memory guard coverage (§8)**  
   `MemorySegment.reinterpret()` and `Arena.global()` are now gated by `NativeMemoryPermission` (`"reinterpret-memory-segment"` and `"global-arena"`). Evaluate whether additional native-memory allocation/lifecycle paths (e.g., `Arena.ofConfined()`, `Arena.ofShared()`, `Arena.ofAuto()`) require equivalent permission checks. Until coverage decisions are finalized, policy must not open `jdk.foreign` to any code base that is not fully trusted, and any such grant must be documented with an explicit security rationale.

8. **Evaluate `MethodHandles.Lookup.defineClass()` permission gate (N-15 / §7)**  
   `MethodHandles.Lookup.defineClass()` and related dynamic class-definition APIs bypass `LoadClassPermission` entirely. Evaluate whether an extension of `LoadClassPermission` or a new `DefineClassPermission` is warranted to gate dynamic class injection into existing modules. Until such a gate exists, access to privileged `Lookup` objects must be treated as equivalent to `LoadClassPermission` for the target module.

9. **Document recommended `SocketPermission` policy structure for hardened deployments (N-14 / §9)**  
   DirtyChai documentation should provide a reference policy template that separates loopback, LAN, multicast, and external address grants rather than using wildcard `connect` grants. The template should also restrict `DatagramSocket`-based discovery and separate multicast permissions from unicast permissions to reduce topology disclosure risk.

10. ~~**Evaluate `LoadModulePermission` gate for runtime module mutation (N-15 / §7)**~~  
    Resolved: runtime `Module.addExports()` and `Module.addOpens()` now enforce
    `RuntimePermission("mutateModuleTopology")` via
    `SecurityManager.checkPermission()` before caller-identity validation.
    Runtime reflective topology mutations are now policy-gated. Residual risk
    for startup-time topology changes from `--add-opens`/`--add-exports`/
    `--add-modules` remains and must still be handled as a trusted deployment
    perimeter decision.

---

## Final Assessment

Dirty Chai’s current implementation demonstrates robust defense-in-depth for SecurityManager installation and policy enforcement paths, with clear fail-secure tendencies and improved handling from the Issue #85 cycle.

The main remaining risks are **operational** (policy configuration and whitelist governance) rather than obvious structural bypasses in the reviewed core logic.

**Overall rating:** **Strong** (with documented residual risks).

---

## References

- `src/java.base/share/classes/java/lang/System.java` — conditional SecurityManager validation, stack-walk depth (`limit(50)`), trusted-class gate
- `src/java.base/share/classes/java/lang/Module.java` — `RuntimePermission("mutateModuleTopology")` enforcement in `addExports(String, Module)` and `addOpens(String, Module)` runtime mutation entry points
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
- `src/java.base/share/classes/java/lang/ClassLoader.java`, `java/lang/foreign/SymbolLookup.java`, `jdk/internal/foreign/SystemLookup.java`, `jdk/internal/loader/NativeLibraries.java` — `NativeInvocationPermission` enforcement at native symbol resolution; `NativeLibraries.findLibraryNameAddress()` provides null-safe library name resolution for permission construction
- `src/java.base/share/classes/jdk/internal/foreign/AbstractMemorySegmentImpl.java` — `NativeMemoryPermission("reinterpret-memory-segment")` enforcement in `reinterpretInternal()` before `MemorySegment.reinterpret()` proceeds
- `src/java.base/share/classes/java/lang/foreign/Arena.java` — `NativeMemoryPermission("global-arena")` enforcement in `Arena.global()`
- `src/java.base/share/classes/au/zeus/jdk/authorization/guards/LoadClassPermission.java` — guard definition
- `src/java.base/share/classes/au/zeus/jdk/authorization/guards/NativeInvocationPermission.java` — guard definition
- `src/java.base/share/classes/au/zeus/jdk/authorization/guards/NativeMemoryPermission.java` — guard definition
- `src/java.base/share/classes/au/zeus/jdk/authorization/guards/SerialObjectPermission.java` — guard definition
- `src/java.base/share/classes/java/io/ObjectInputStream.java` — `SerialObjectPermission` check placement in `readOrdinaryObject()` before instantiation
- `src/java.base/share/classes/java/io/SerialCallbackContext.java` — confirms callback context no longer carries the permission check logic
- `src/java.base/share/classes/au/zeus/jdk/authorization/policy/ConcurrentPolicyFile.java` — policy grant evaluation and fail-secure behavior references
- `src/java.base/share/classes/au/zeus/jdk/net/Uri.java` — URI validation behavior used in CodeSource/policy matching rationale
- Issue #85 (repository issue tracker) — remediation baseline for hardened exception and validation handling
- OpenJDK 21 reference (`jdk-21+35`): `java/lang/System.java`, `java/security/AccessController.java`, `java/security/AccessControlContext.java`, `javax/security/auth/Subject.java`, `java/lang/ThreadBuilders.java`, `java/lang/Thread.java`, `java/util/concurrent/Executors.java`, `java/security/SecureClassLoader.java`, `java/lang/Module.java`, `java/io/ObjectInputStream.java`
- `java.lang.foreign.MemorySegment` / `java.lang.foreign.Arena` — FFM capability transfer; `reinterpret()` and `Arena.global()` object-capability risks documented in §8
- `java.lang.instrument.Instrumentation` — agent attachment threat surface; `getAllLoadedClasses()` / `redefineClasses()` only reachable with an active `-javaagent`, but see N-11 for the runtime-attach path
- `com.sun.tools.attach.VirtualMachine`, `com.sun.tools.attach.AttachPermission`, `com.sun.tools.attach.spi.AttachProvider`, `sun.tools.attach.HotSpotAttachProvider` — runtime attach path and enforced permission gates (`attachVirtualMachine`, `createAttachProvider`) discussed in N-11
- `javax.security.auth.Subject.getPrincipals()` — principal mutation boundary; live mutable set; cross-realm collision and injection risks documented in §E and N-12
- `java.lang.invoke.MethodHandles.Lookup.defineClass()` — dynamic class definition gate; bypasses `LoadClassPermission`; residual documented in §7 (Delegation Attack Residuals) and N-15
- `java.net.DatagramSocket` / `java.net.MulticastSocket` — network isolation surface; unconnected discovery and topology-disclosure risks documented in §9 and N-14
- `java.lang.Module.addOpens()` / `java.lang.Module.addExports()` — runtime module mutation APIs; `RuntimePermission("mutateModuleTopology")` gate and interaction with `LoadClassPermission` documented in §7, §10, and N-15

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

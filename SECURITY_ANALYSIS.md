# Dirty Chai Security Analysis

**Date:** 2026-04-24  
**Project:** Dirty Chai  
**Scope:** `System.setSecurityManager()`, `AccessController`, `ConcurrentPolicyFile`, URI handling, guard permissions, Executors, and virtual-thread/security-manager interaction paths

> This document is focused on DirtyChai's **in-process** security model.
> For cross-JVM, JGDMS activation, and multi-process trust-boundary analysis, see `PROCESS_ISOLATION.md`.

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
| Module topology read/inspection API gate (`Module.getDescriptor()`, `Module.getLayer()`, `ModuleLayer.modules()`, `ModuleLayer.findModule()`, `Configuration.modules()`, `ModuleReference.descriptor()`) | No dedicated `RuntimePermission("readModuleTopology")` gate at these API entry points | `SecurityConstants.READ_MODULE_TOPOLOGY.checkGuard(null)` gate at topology-inspection entry points, preventing untrusted code from enumerating internal module structure |
| Executors + thread factory behavior | `Executors.defaultThreadFactory()` returns classic `DefaultThreadFactory` | `Executors.defaultThreadFactory()` routes through `Thread.ofPlatform().group(...).factory()` and therefore through Dirty Chai platform-thread permission checks |
| Virtual thread creation path | `ThreadBuilders` virtual/platform builder paths do not enforce dedicated `createVirtualThread`/`createPlatformThread` checks | Builder `unstarted()` and `factory()` paths enforce explicit runtime permissions and capture `AccessController.getContext()` for inherited security context |
| `AccessController` / `AccessControlContext` / `Subject` model | OpenJDK 21 `doPrivileged(..., AccessControlContext, Permission...)` uses wrapper/context-validation flow (`checkContext`/`createWrapper`), with `Subject` propagation via ACC/`SubjectDomainCombiner` | Explicit limited-privilege domain intersection via `DomainIdentity`, ACC builder/authorization helpers, and ACC/`SubjectDomainCombiner` subject propagation in active Dirty Chai runtime path |

### A) New Guards vs OpenJDK 21

Dirty Chai introduces and wires five new guard permissions that are absent in OpenJDK 21 (four in the initial implementation; `DefineClassPermission` added in commit 0f90b38):

- `LoadClassPermission` (`au.zeus.jdk.authorization.guards.LoadClassPermission`)
  - integrated in `SecureClassLoader` (`LOAD_CLASS_ALLOW`) and checked during `ProtectionDomain` creation (`sm.checkPermission(LOAD_CLASS_ALLOW, ...)`)
- `NativeInvocationPermission` (`au.zeus.jdk.authorization.guards.NativeInvocationPermission`)
  - enforced in `ClassLoader.findNative()`, `SymbolLookup.loaderLookup()`, `SymbolLookup.libraryLookup()`, and `SystemLookup` before native symbol addresses are returned; the permission name is the **resolved library name** (library-scoped), so each native library requires a separate, explicit policy grant
  - library name resolution is performed by `NativeLibraries.findLibraryNameAddress()`, which applies a three-level null-safe fallback: (1) the map key of the native library entry, (2) `NativeLibrary.name()`, (3) the symbol name itself — guaranteeing that `NativeInvocationPermission` is always constructed with a non-null name even when library path metadata is incomplete
- `NativeMemoryPermission` (`au.zeus.jdk.authorization.guards.NativeMemoryPermission`)
  - enforced at FFM native-memory boundaries: `Arena.global()` requires `NativeMemoryPermission("global-arena")`; `Arena.ofAuto()` requires `NativeMemoryPermission("auto-arena")`; `Arena.ofConfined()` requires `NativeMemoryPermission("confined-arena")`; `Arena.ofShared()` requires `NativeMemoryPermission("shared-arena")` (all four arena creation methods gated as of commit b62577c); and `AbstractMemorySegmentImpl.reinterpretInternal()` requires `NativeMemoryPermission("reinterpret-memory-segment")`
  - purpose: separate native-memory authority from native-symbol/native-library authority, so policy can independently control off-heap lifecycle/capability expansion operations
  - security effect: reduces memory-corruption and resource-exhaustion attack surface by requiring explicit permission before any arena allocation or segment reinterpretation is allowed
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

Dirty Chai introduces builder APIs not present in OpenJDK 21, plus authorization checks around ACC construction (`AccessControlContext.create(...)`, `checkAuthorized(...)`, permission intersection helpers).

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
- `Instrumentation.getAllLoadedClasses()` / `Instrumentation.redefineClasses()` — reachable only when a `-javaagent` is active at startup. Runtime dynamic agent injection via `VirtualMachine.attach()` is gated by `AttachPermission` when the `SecurityManager` is active; hardened deployments should deny `AttachPermission("attachVirtualMachine")` to untrusted code and may also set `-XX:+DisableAttachMechanism` as defense in depth. **Under PoLP-generated policies, agent codebases are absent from the observation window and therefore receive no `LoadClassPermission` grants; this provides a second independent gate that blocks agent class loading even if `AttachPermission` is bypassed.** See N-11.
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

This document treats that gate as the DirtyChai in-process boundary for standard Java serialization paths. For activation-group, cross-JVM, and `DeSerializationPermission` trust-boundary analysis, see `PROCESS_ISOLATION.md` ("Residual N-13: Activation Deserialization Authority Trust Boundaries").

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
- **Dynamic class definition via `MethodHandles.Lookup.defineClass()`** — **GATED (commit 0f90b38, see §12):** `DefineClassPermission` now enforces a SecurityManager check at the package-private `Lookup.defineClass(boolean, Object)` method in `MethodHandles.java`, before any class-definition work begins. Untrusted code can no longer bypass `LoadClassPermission` by defining classes dynamically through this path. See §12 for the complete documentation of the `DefineClassPermission` enforcement point and the updated layered defense model.

#### Module System and LoadClassPermission Interaction

`LoadClassPermission` and module-system encapsulation are independent, non-redundant gates operating at different layers:

- **Module enforcement layer** — the JVM enforces module access control at the bytecode level (reads, exports, opens). This applies to already-loaded classes and does not involve the SecurityManager.
- **SecurityManager enforcement layer** — `LoadClassPermission` is checked at class-load time by `SecureClassLoader`. It applies to classes being loaded, not to classes already present in the module layer.

These layers are not redundant. Untrusted code that is granted module `reads` access via an `--add-opens` or `--add-exports` JVM flag bypasses `LoadClassPermission` because the target class is already loaded; the SecurityManager check is never triggered for pre-loaded classes.

#### `checkPackageAccess`, `checkPackageDefinition`, and the `nonExportedPkgs` Split-Package Guard

The JVM (`systemDictionary.cpp`) skips the `check_package_access` callback entirely when the class being loaded belongs to a **named** module (JEP 403 enforcement):

```
ModuleEntry* mod_entry = loaded_class->module();
if (mod_entry != nullptr && mod_entry->is_named()) {
    should_check_package_access = false;  // named module — JVM handles encapsulation
}
```

`SecurityManager.checkPackageAccess()` (and `checkPackageDefinition()`) are therefore **only ever invoked for unnamed-module classes**. This is also documented in `RuntimePermission.java` for `accessClassInPackage.*` and `defineClassInPackage.*`: *"This is only checked for Unnamed Modules."*

Within `checkPackageAccess()`, the `nonExportedPkgs` check is **not** redundant with the module system. It guards a distinct threat surface — the split-package scenario:

> Unnamed-module code places a class in a package namespace that matches a non-exported boot/platform package (e.g., `sun.security.util.Exploit` on the classpath). Because the class is in the unnamed module, `is_named()` = false and the JVM invokes `checkPackageAccess`. The `nonExportedPkgs` map contains `sun.security.util` (a non-unqualified-exported package from `java.base`). The check requires `RuntimePermission("accessClassInPackage.sun.security.util")` before load is allowed.

| Guard | Threat surface |
|-------|---------------|
| Module system (JVM) | Unnamed-module code cannot *access* non-exported packages of **named**-module classes |
| `nonExportedPkgs` in `checkPackageAccess` | Unnamed-module code cannot *load its own classes* in package namespaces matching non-exported platform packages without an explicit policy grant |

These guards are complementary, not redundant. The module system skips `checkPackageAccess` precisely in the case where named-module encapsulation applies; the `nonExportedPkgs` check covers the remaining unnamed-module split-package surface that the module system leaves ungated.

Additional module-specific risks:

- **Export cycle bridging** — if trusted module A exports a package to untrusted module B, and A's exported package contains a class with internal access to module C (a third module, not exported to B), then B gains indirect access to C's internals through A's public API surface. This indirect bridge is not blocked by either `LoadClassPermission` or module-system encapsulation as long as A's exported class remains reachable.
- **Module topology disclosure** — **GATED (see §11):** `Module.getDescriptor()`, `ModuleLayer.modules()`, and related topology-inspection APIs now require `RuntimePermission("readModuleTopology")`; untrusted code can no longer enumerate the deployed module graph without an explicit policy grant.
- **Hidden module pre-population** — the `--add-modules` JVM flag can force-load hidden modules before the SecurityManager is installed. Code in those modules is then available as a trusted bridge for untrusted access at runtime. This flag must be treated as part of the trusted deployment perimeter.

See residual N-15. Runtime module mutation and inspection are now gated by `RuntimePermission("mutateModuleTopology")` and `RuntimePermission("readModuleTopology")` respectively (see §10–11).

### 8) Foreign Function & Memory API (FFM) Trust Boundaries

DirtyChai adds SecurityManager permission gating on selected FFM entry points. This section provides a complete, repo-specific inventory of the FFM API surface, identifies which entry points are gated, and documents remaining gaps through a code-backed gap analysis. An implementation plan is in §8.8.

#### Currently Gated FFM Entry Points

The following FFM entry points have explicit SecurityManager or guard-permission checks in this repository. Each row includes a source reference to the exact check location.

| Entry Point | Guard Location | Permission | Security Intent |
|---|---|---|---|
| `Arena.global()` | [`Arena.java:246–249`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/java/lang/foreign/Arena.java#L246-L249) | `NativeMemoryPermission("global-arena")` | Block unbounded process-lifetime off-heap memory retention by untrusted code |
| `Arena.ofAuto()` | [`Arena.java:229–232`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/java/lang/foreign/Arena.java#L229-L232) | `NativeMemoryPermission("auto-arena")` | Block unbounded GC-bounded off-heap allocation by untrusted code (commit b62577c) |
| `Arena.ofConfined()` | [`Arena.java:265–268`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/java/lang/foreign/Arena.java#L265-L268) | `NativeMemoryPermission("confined-arena")` | Block unbounded thread-confined off-heap allocation by untrusted code (commit b62577c) |
| `Arena.ofShared()` | [`Arena.java:280–283`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/java/lang/foreign/Arena.java#L280-L283) | `NativeMemoryPermission("shared-arena")` | Block unbounded cross-thread off-heap allocation by untrusted code (commit b62577c) |
| `Linker.nativeLinker()` | [`Linker.java:578–581`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/java/lang/foreign/Linker.java#L578-L581) | `NativeInvocationPermission("native-linker")` | Block untrusted code from obtaining the platform native linker and creating downcall/upcall handles (commit b62577c) |
| `MemorySegment.reinterpret(long)` | [`AbstractMemorySegmentImpl.java:157–161`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/jdk/internal/foreign/AbstractMemorySegmentImpl.java#L157-L161) | `NativeMemoryPermission("reinterpret-memory-segment")` | All three `reinterpret()` overloads route through the shared `reinterpretInternal()` path at this location |
| `MemorySegment.reinterpret(Arena, Consumer)` | (same `reinterpretInternal()` at line 157) | same as above | — |
| `MemorySegment.reinterpret(long, Arena, Consumer)` | (same `reinterpretInternal()` at line 157) | same as above | — |
| `SymbolLookup.loaderLookup()` — per-symbol resolution | [`SymbolLookup.java:274`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/java/lang/foreign/SymbolLookup.java#L274) | `NativeInvocationPermission(<libName>)` | Library name resolved by `NativeLibraries.findLibraryNameAddress()` with null-safe fallback; checked before the resolved address segment is returned |
| `SymbolLookup.libraryLookup(String/Path, Arena)` — library load | [`SymbolLookup.java:358–361`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/java/lang/foreign/SymbolLookup.java#L358-L361) | `SecurityManager.checkLink(name)` at load time; additionally [`NativeInvocationPermission(<libName>)` at line 382](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/java/lang/foreign/SymbolLookup.java#L382) per symbol at find time | Two-layer gate: library-load check then per-symbol invocation check |
| `SystemLookup.lookup()` — default linker per-symbol | [`SystemLookup.java:139`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/jdk/internal/foreign/SystemLookup.java#L139) | `NativeInvocationPermission(<libName>)` | Checked per resolved symbol in the default C-library lookup used by `Linker.defaultLookup()` |
| `ClassLoader.findNative()` — JNI native-method binding | [`ClassLoader.java:2575–2580`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/java/lang/ClassLoader.java#L2575-L2580) | `NativeInvocationPermission(<libName>)` | Fired at JNI method link time; bootstrap-loader callers (`loader == null`) are excluded at line 2575 |
| `MemorySegment.ofAddress(long)` | [`MemorySegment.java:1573–1576`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/java/lang/foreign/MemorySegment.java#L1573-L1576) | `NativeMemoryPermission("address-memory-segment")` | Blocks address-to-segment round-trip native invocation bypass (commit 3561dab, 2026-04-24) |

**Note on `@Restricted` and `ensureNativeAccess`:** Several FFM API methods carry the `@Restricted` annotation and call `Reflection.ensureNativeAccess()`. This is a module-system gate (JEP 442: requires `--enable-native-access=<moduleName>` at JVM startup) that is complementary to but independent of SecurityManager checks. It is a deployment-time module-access control, not a runtime policy control, and does not replace or supplement `NativeMemoryPermission` / `NativeInvocationPermission` policy checks. Both mechanisms can coexist and serve distinct, non-overlapping purposes.

#### 8.1 Gap Analysis: Arena Allocation Surfaces

**Status: All arena allocation surfaces are now gated (commit b62577c, 2026-04-24).**

[`Arena.ofAuto()`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/java/lang/foreign/Arena.java#L229), [`Arena.ofConfined()`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/java/lang/foreign/Arena.java#L265), and [`Arena.ofShared()`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/java/lang/foreign/Arena.java#L280) now each require a `NativeMemoryPermission` check. Previously these factory methods had no SecurityManager check and no `@Restricted` annotation.

**Security consequence (historical, now mitigated):** Untrusted code that could call these factory methods could allocate unbounded amounts of off-heap native memory without any policy check. Off-heap memory is not bounded by the JVM heap limit (`-Xmx`). The arena-creation gap allowed:

- Unbounded native-memory allocation by the calling thread (DoS / resource exhaustion).
- Creation of shared arenas accessible across threads (`Arena.ofShared()`), widening the cross-thread attack surface compared to heap-only code.
- Creation of arenas passed to less-trusted code, enabling that code to allocate native memory indirectly without holding an arena-creation permission itself (capability delegation, see §8.4).

| Arena Kind | SM gated? | DoS risk | Lifetime risk |
|---|---|---|---|
| `Arena.global()` | ✅ `"global-arena"` | High if ungated — permanent process-lifetime off-heap retention | Process lifetime |
| `Arena.ofAuto()` | ✅ `"auto-arena"` (commit b62577c) | Medium — GC-bounded but unbounded peak allocation | GC-controlled |
| `Arena.ofConfined()` | ✅ `"confined-arena"` (commit b62577c) | Medium — bounded by explicit `close()`; thread-confined | Thread-confined, explicit |
| `Arena.ofShared()` | ✅ `"shared-arena"` (commit b62577c) | Medium-High — cross-thread access; explicit `close()` by any thread | Any thread, explicit |

All arena allocation surfaces are now protected. The separate per-kind targets (`"auto-arena"`, `"confined-arena"`, `"shared-arena"`) allow fine-grained policy control. The capability-delegation residual (§8.4) remains by design — see §8.8 Completed Implementations and remaining work.

#### 8.2 Gap Analysis: Address Acquisition (`MemorySegment.ofAddress`)

**Status: GATED (commit 3561dab, 2026-04-24)** ✅

Previously ungated entry point [`MemorySegment.ofAddress(long)`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/java/lang/foreign/MemorySegment.java#L1573) now requires `NativeMemoryPermission("address-memory-segment")`. Guard is at [`MemorySegment.java:1573–1576`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/java/lang/foreign/MemorySegment.java#L1573-L1576).

**Historical security consequence (now mitigated):** `MemorySegment.ofAddress(long)` creates a zero-length native segment with the global scope from a raw `long` address value. A zero-length segment (`byteSize() == 0`) cannot read or write memory — there is no valid access range. To access memory at the obtained address, code must call `reinterpret()` to give the segment a non-zero size, and `reinterpret()` IS gated by `NativeMemoryPermission("reinterpret-memory-segment")`. This gate is the effective barrier for memory access.

However, a zero-length segment holding a native address can be passed directly to `Linker.downcallHandle(MemorySegment, FunctionDescriptor, ...)` as a function-pointer argument. The `AbstractLinker.downcallHandle()` implementation at [`AbstractLinker.java:94–96`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/jdk/internal/foreign/abi/AbstractLinker.java#L94-L96) calls `SharedUtils.checkSymbol(symbol)`, which validates only that the segment is non-null and native — not that it has non-zero size. Before commit 3561dab, if untrusted code already held a raw native address value (obtained, for example, by reading from a native segment delegated to it by trusted code), it could construct a function-pointer segment via `ofAddress()` and invoke native code through a downcall handle without holding `NativeInvocationPermission` or `NativeMemoryPermission`.

The address-round-trip threat model was: `long address → MemorySegment.ofAddress(address) → downcallHandle(segment, fd) → invoke`. This path bypassed `NativeInvocationPermission` if the address was obtained outside a guarded symbol-lookup path.

**Resolution:** The `NativeMemoryPermission("address-memory-segment")` gate added in commit 3561dab blocks the creation of the address-carrying segment. Combined with existing `NativeInvocationPermission("native-linker")` and arena-allocation gates, all FFM address-acquisition and arena-allocation entry points are now protected. Untrusted code can no longer acquire or create native segments without explicit policy authorization.

**Risk rating:** Resolved. See residual N-16 (updated to RESOLVED).

#### 8.3 Gap Analysis: Linker, Downcall, and Upcall Paths

The table below covers the full linker API surface. `Linker.nativeLinker()` is now gated by `NativeInvocationPermission("native-linker")` (commit b62577c). The remaining three entry points — `downcallHandle()` and `upcallStub()` — have no `NativeInvocationPermission` or `NativeMemoryPermission` check; they are gated only by the module-level `ensureNativeAccess` check:

| Entry Point | File:Line | Guard Present | Note |
|---|---|---|---|
| `Linker.nativeLinker()` | [`Linker.java:578`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/java/lang/foreign/Linker.java#L578) | `NativeInvocationPermission("native-linker")` (commit b62577c) | Static factory; now gated — untrusted code cannot obtain the platform native linker without this permission |
| `Linker.downcallHandle(MemorySegment, FunctionDescriptor, ...)` | [`AbstractLinker.java:93–97`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/jdk/internal/foreign/abi/AbstractLinker.java#L93-L97) | `ensureNativeAccess` only | Module-level native-access check; no `NativeInvocationPermission` or `NativeMemoryPermission` |
| `Linker.downcallHandle(FunctionDescriptor, ...)` | [`AbstractLinker.java:101–104`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/jdk/internal/foreign/abi/AbstractLinker.java#L101-L104) | `ensureNativeAccess` only | Returns an unbound handle requiring a function address at invocation time; no SM check |
| `Linker.upcallStub(MethodHandle, FunctionDescriptor, Arena, ...)` | [`AbstractLinker.java:128–147`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/jdk/internal/foreign/abi/AbstractLinker.java#L128-L147) | `ensureNativeAccess` only | Registers Java callback for native invocation; no SM check at stub creation or at callback invocation time |

**Security consequence — downcall:** Creating a downcall handle requires only `ensureNativeAccess` (a module-level check). The security boundary for native invocation relies on `NativeInvocationPermission` being checked at the **symbol-lookup stage** before a function address is returned. If a function address is available by means other than a gated symbol lookup (see §8.2), the downcall handle creation and invocation impose no SecurityManager check.

**Security consequence — upcall:** `Linker.upcallStub()` creates a native function pointer that, when called from native code, dispatches to a Java `MethodHandle`. There is no SecurityManager check at stub creation or at upcall-invocation time. If privileged Java code creates an upcall stub and passes its address (a `MemorySegment`) to less-trusted code, the less-trusted code can supply that pointer to native callees, causing native code to invoke the privileged Java method. This is a confused-deputy risk for callbacks registered by trusted code.

**Downcall handle cache:** `AbstractLinker` caches downcall handles and upcall stub factories by `(FunctionDescriptor, LinkerOptions)` in `SoftReferenceCache` instances at [`AbstractLinker.java:88–89`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/jdk/internal/foreign/abi/AbstractLinker.java#L88-L89). Cached entries are shared across callers: once a template handle is created for a `FunctionDescriptor`, subsequent callers reuse the cached instance. Since the permission check is at address-acquisition time (not at handle-creation time), the cache does not introduce an additional permission-bypass gap — but it confirms that the security model depends entirely on the address-acquisition path being gated. Additionally, because cache-hit responses are faster than cache-miss responses, an unprivileged caller can probe whether a privileged caller has already created a handle for a given `FunctionDescriptor` by measuring response latency — a minor side-channel information-disclosure risk about privileged code behavior. This is noted as a low-severity information-leakage residual under §8.4 delegation risks.

#### 8.4 Gap Analysis: Delegation and Confused-Deputy Risks

The FFM API is an **object-capability system**: possessing a `MemorySegment`, a downcall `MethodHandle`, or an upcall stub segment confers the authority to perform the corresponding privileged operation. SecurityManager checks in DirtyChai are placed at **capability-acquisition time** (symbol lookup, arena creation, segment reinterpretation), not at **capability-use time**. This creates the following delegation risks:

**D-1: Downcall handle transfer.** Trusted code that calls `linker.downcallHandle(symbol, fd)` receives a `MethodHandle`. If it passes that handle to untrusted code, the untrusted code can invoke native functions without holding any SecurityManager permission. There is no permission check at `MethodHandle.invoke*()` for FFM handles.

**D-2: Upcall stub transfer.** Trusted code that calls `linker.upcallStub(target, fd, arena)` receives a `MemorySegment` (the stub's native function-pointer address). If it passes that segment to untrusted code, the untrusted code can supply it as a callback pointer to native callers, causing native code to invoke the Java method specified by `target`. No permission is checked at callback time; the invocation is controlled entirely by native-side caller choice.

**D-3: Arena and allocator transfer.** Trusted code that creates `Arena.ofConfined()` or `Arena.ofShared()` and passes the resulting `Arena` (or a `SegmentAllocator` backed by it) to untrusted code enables that code to allocate off-heap memory using the trusted code's arena — without holding any `NativeMemoryPermission` itself. Each allocation drains the arena's capacity and increases off-heap pressure.

**D-4: Memory segment transfer (read/write access).** Once a native segment is created by trusted code and passed to untrusted code, the untrusted code can read and write memory within the segment's bounds without any SecurityManager check on `get()` / `set()` / `copy()` operations. It can also slice the segment (`asSlice()`), pass it as a downcall argument, or store it in further data structures — all without triggering any SM check. The SM boundary is purely at capability-acquisition time.

**Mitigation principle:** Trusted code that creates FFM capabilities (segments, handles, stubs, arenas) must treat them as authority-carrying objects and must not delegate them to less-trusted code without explicit trust elevation. DirtyChai's current FFM security model is a **"front-door" model**: the guards are at acquisition time. Once past the front door, FFM capability objects confer unrestricted access within their stated bounds.

#### 8.5 Gap Analysis: Module-Open Bypass Risks

**`jdk.internal.foreign` encapsulation:** The `jdk.internal.foreign` package is an internal package not exported to user code under normal module encapsulation. Key factory methods within this package — notably [`SegmentFactories.makeNativeSegmentUnchecked(long, long)`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/jdk/internal/foreign/SegmentFactories.java#L81) and its overloads — have no SecurityManager check and directly construct native segments from raw addresses and sizes.

If `jdk.internal.foreign` is opened to user code via `--add-opens java.base/jdk.internal.foreign=<module>` or `--add-opens java.base/jdk.internal.foreign=ALL-UNNAMED`, reflection access to `SegmentFactories.makeNativeSegmentUnchecked()` would allow construction of arbitrary-address native segments at arbitrary sizes without any SecurityManager check. This completely bypasses `NativeMemoryPermission("reinterpret-memory-segment")` — the primary reinterpretation guard — and `NativeMemoryPermission("global-arena")`. Critically, it also defeats all arena-creation guards implemented in §8.8 Steps 1–3: once `makeNativeSegmentUnchecked()` is accessible, arena-based allocation gating becomes moot because arbitrary native segments can be created directly without going through any arena factory.

**Consequence:** Opening `jdk.internal.foreign` to untrusted code must be treated as equivalent to granting `AllPermission` for FFM memory operations. No SecurityManager FFM guard remains effective if this package is opened.

**Public `java.lang.foreign` package:** Opening `java.lang.foreign` to untrusted code widens the reachable FFM surface (it is the module-access prerequisite for several `@Restricted` methods) but does not by itself bypass SecurityManager checks. Gated methods (`reinterpret()`, `Arena.global()`, symbol lookups) still check permissions. However, `MemorySegment.ofAddress()` (ungated) is already public regardless of module opens. Module-open grants to `java.lang.foreign` must still be treated as high-sensitivity policy decisions.

**`@Restricted` + `ensureNativeAccess` interaction with module opens:** Opening a package grants reflective access but does not automatically grant `--enable-native-access`. A module open combined with a broad `--enable-native-access=ALL-UNNAMED` grant effectively removes both the module-system and SecurityManager barriers for users of the opened package. Policy must control both flags independently and conservatively.

#### 8.6 Gap Analysis: Resource Exhaustion and Availability Risks

FFM presents availability risks distinct from integrity and confidentiality risks:

- **Unbounded off-heap allocation:** `Arena.ofConfined()`, `Arena.ofShared()`, and `Arena.ofAuto()` can be called to allocate arbitrarily large native memory regions. Off-heap memory is not subject to the JVM heap limit (`-Xmx`). Exhausting native memory causes `OutOfMemoryError`, JVM process termination, or OS-level failure — all denial-of-service outcomes. All four arena creation methods are now gated (commit b62577c).
- **Long-lived leaked arenas:** An `Arena.ofShared()` or `Arena.ofConfined()` created but never explicitly closed retains all allocated native memory until the arena itself becomes unreachable and is GC-finalized. In request-handling or per-connection code, creating arenas without closing them is a progressive memory-leak vector.
- **Pinned native segments:** Long-lived segments (especially those allocated via `Arena.global()` or file-mapped segments) can interfere with JVM GC interaction and increase native memory fragmentation over time.
- **Downcall invocation saturation:** A downcall handle targeting a slow or blocking native function can be invoked in a tight loop to exhaust platform thread capacity or pin virtual threads to carrier threads, constituting a thread-DoS vector.

**Current protection status:** All four arena creation methods are now gated: `Arena.global()` requires `NativeMemoryPermission("global-arena")` (existing), and `Arena.ofAuto()`, `Arena.ofConfined()`, and `Arena.ofShared()` each require their respective `NativeMemoryPermission` target (commit b62577c). Off-heap resource exhaustion via these arena factory methods is now blocked for any caller that lacks the appropriate policy grant.

#### 8.7 Policy Guidance for Administrators

- Grant `NativeMemoryPermission` only to fully trusted code bases.
- Prefer explicit target names rather than wildcard grants. All arena-creation targets (`"global-arena"`, `"auto-arena"`, `"confined-arena"`, `"shared-arena"`) and the reinterpretation target (`"reinterpret-memory-segment"`) are now finalized and should be granted individually based on least-privilege need.
- Grant `NativeInvocationPermission("native-linker")` only to code that must create downcall or upcall handles; this is the front-door gate for linker-based native invocation.
- Do not open `jdk.internal.foreign` to any user code under any circumstance; doing so bypasses all FFM SecurityManager guards regardless of policy.
- Treat a combined `java.lang.foreign` module-open grant plus `--enable-native-access` grant as high-sensitivity; audit all FFM API paths reachable by the granted module.
- Be aware that downcall handles, upcall stubs, arenas, and native segments are object-capabilities: once created by trusted code, they confer native-invocation or native-memory authority regardless of the holder's declared permissions.

Policy template fragment for arena-allocation grants (replace `/path/to/trusted/` with the actual trusted codebase path; trailing `-` is a recursive directory wildcard):

```
grant codeBase "file:/path/to/trusted/-" {
    permission au.zeus.jdk.authorization.guards.NativeMemoryPermission "auto-arena";
    permission au.zeus.jdk.authorization.guards.NativeMemoryPermission "confined-arena";
    permission au.zeus.jdk.authorization.guards.NativeMemoryPermission "shared-arena";
    permission au.zeus.jdk.authorization.guards.NativeMemoryPermission "global-arena";
    permission au.zeus.jdk.authorization.guards.NativeMemoryPermission "reinterpret-memory-segment";
    permission au.zeus.jdk.authorization.guards.NativeInvocationPermission "native-linker";
};
```

See residual risk N-16 (updated: all address-acquisition and allocation surfaces now gated — RESOLVED), N-17 (delegation risks, by-design capability model), and the completed implementations in §8.8.

#### 8.8 Implementation Plan

This section identifies prioritized, concrete steps for closing the gaps identified above. Steps 1–5 have been completed in commits b62577c and 3561dab (2026-04-24). Steps 6–8 remain as future work.

##### Completed Implementations (commits b62577c and 3561dab, 2026-04-24)

**Step 1 ✅ COMPLETED: Gate `Arena.ofShared()` with `NativeMemoryPermission("shared-arena")`**

- **Rationale:** `Arena.ofShared()` creates cross-thread-accessible off-heap memory — the highest-risk previously-ungated arena because cross-thread lifetime management increases use-after-free and confusion risk.
- **Guard point:** [`Arena.java:280–283`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/java/lang/foreign/Arena.java#L280-L283) — `sm.checkPermission(new NativeMemoryPermission("shared-arena"))` at the start of `ofShared()` body.
- **Permission target name:** `NativeMemoryPermission("shared-arena")`
- **Compatibility:** When a SecurityManager is active, existing callers of `Arena.ofShared()` without the new grant will receive `SecurityException`. When no SecurityManager is installed, the guard is a no-op and existing code continues to work unchanged.

**Step 2 ✅ COMPLETED: Gate `Arena.ofConfined()` with `NativeMemoryPermission("confined-arena")`**

- **Rationale:** Enables unbounded off-heap allocation per calling thread. Lower cross-thread risk than shared, but still a resource-exhaustion vector.
- **Guard point:** [`Arena.java:265–268`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/java/lang/foreign/Arena.java#L265-L268) — `sm.checkPermission(new NativeMemoryPermission("confined-arena"))`.
- **Permission target name:** `NativeMemoryPermission("confined-arena")`

**Step 3 ✅ COMPLETED: Gate `Arena.ofAuto()` with `NativeMemoryPermission("auto-arena")`**

- **Rationale:** GC-bounded lifetime reduces long-term leak risk, but unbounded peak off-heap allocation is still a viable DoS vector.
- **Guard point:** [`Arena.java:229–232`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/java/lang/foreign/Arena.java#L229-L232) — `sm.checkPermission(new NativeMemoryPermission("auto-arena"))`.
- **Permission target name:** `NativeMemoryPermission("auto-arena")`

**Step 4 ✅ COMPLETED: Gate `Linker.nativeLinker()` with `NativeInvocationPermission("native-linker")`**

- **Rationale:** Obtaining the native linker is the first step toward creating downcall and upcall handles. Gating it prevents untrusted code from creating any linker-based handles.
- **Guard point:** [`Linker.java:578–581`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/java/lang/foreign/Linker.java#L578-L581) — `sm.checkPermission(new NativeInvocationPermission("native-linker"))`.
- **Permission target name:** `NativeInvocationPermission("native-linker")` (linker access is an invocation authority, not a memory authority).
- **Design decision resolved:** Gated at `nativeLinker()` (coarser, simpler) rather than separately at `downcallHandle()` and `upcallStub()`.

**Step 5 ✅ COMPLETED: Gate `MemorySegment.ofAddress(long)` with `NativeMemoryPermission("address-memory-segment")`**

- **Rationale:** Creating a native segment from a raw address is a previously-ungated entry point to the FFM capability model. The address-round-trip threat model (`long address → MemorySegment.ofAddress(address) → downcallHandle(segment, fd) → invoke`) could bypass `NativeInvocationPermission` if both segment creation and linker access were ungated.
- **Guard point:** [`MemorySegment.java:1573–1576`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/java/lang/foreign/MemorySegment.java#L1573-L1576) — `sm.checkPermission(new NativeMemoryPermission("address-memory-segment"))`
- **Permission target name:** `NativeMemoryPermission("address-memory-segment")`
- **Security effect:** Combined with existing `NativeInvocationPermission("native-linker")` and arena-allocation gates, this completes the FFM trust-boundary model. Untrusted code can no longer acquire or create native segments without explicit policy authorization.
- **Compatibility:** When a SecurityManager is active, existing callers of `MemorySegment.ofAddress()` without the new grant will receive `SecurityException`. When no SecurityManager is installed, the guard is bypassed.

##### Remaining Work

**Step 6 (Evaluate): Delegation risk for downcall handles and upcall stubs (D-1, D-2)**

- **Option A (Recommended for now):** Document the delegation risk explicitly in `NativeMemoryPermission` and `NativeInvocationPermission` Javadoc and in policy guidance. Rely on the front-door model and policy governance to prevent trusted code from delegating capabilities to untrusted code. No implementation change required.
- **Option B (Future evaluation):** Evaluate whether a `doPrivileged`-style wrapper at downcall-handle invocation time can carry the creator domain into the invocation for a SecurityManager intersection check. This would be a significant design change and may affect FFM performance characteristics. Defer until the front-door model is fully closed (Steps 1–5 are now complete) and if residual risk N-17 is elevated.

**Step 7 (Testing Strategy)**

For each new permission gate added (Steps 1–5):

- **Positive test:** Verify that trusted code holding the appropriate `NativeMemoryPermission` grant can call the gated method without `SecurityException`.
- **Negative test:** Verify that code lacking the permission receives `SecurityException` from the gated method.
- **Delegation test:** Verify that code holding an arena or segment object obtained from trusted code can use it (allocate from the arena, access the segment) even without the arena-creation permission — confirming the front-door model is correct by design.
- **DoS regression test:** Verify that a loop attempting large off-heap allocations via the newly gated arena factory method (with SM active) is blocked.
- **Address-segment test:** Verify that `MemorySegment.ofAddress()` throws `SecurityException` without `NativeMemoryPermission("address-memory-segment")` and succeeds with it.
- **Test infrastructure:** Use `CombinerSecurityManager` with a test policy that grants only the specific `NativeMemoryPermission` target(s) under test, consistent with existing security test patterns in the repository.

**Step 8 (Compatibility and Administrator Documentation Strategy)**

- Policy template fragments for all permission targets are now provided in §8.7.
- `NativeMemoryPermission` and `NativeInvocationPermission` Javadoc have been updated to enumerate all recognized target names and their semantics (commits b62577c and 3561dab).
- Document that `--add-opens java.base/jdk.internal.foreign` is a complete SecurityManager bypass for FFM; hardened deployments must prohibit this flag.
- Administrator migration notes: When upgrading to a build containing commits b62577c / 3561dab, SecurityManager-enabled deployments must add grants for `"auto-arena"`, `"confined-arena"`, `"shared-arena"`, `"native-linker"`, and `"address-memory-segment"` to trusted codebases that require these FFM capabilities. Deployments without a SecurityManager are unaffected.

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

See cross-reference: §11 documents the complementary `RuntimePermission("readModuleTopology")` gate
that controls inspection of the topology that mutation APIs operate on.

### 11) Module Topology Read Permission

DirtyChai gates runtime module-topology inspection APIs with
`RuntimePermission("readModuleTopology")` (via `SecurityConstants.READ_MODULE_TOPOLOGY`).

- **Enforcement points** — the following API methods perform
  `SecurityConstants.READ_MODULE_TOPOLOGY.checkGuard(null)` before returning
  module-structure data:
  - `Module.getDescriptor()` — returns the `ModuleDescriptor` for the named module,
    revealing all declared exports, opens, uses, and provides declarations.
  - `Module.getLayer()` — returns the `ModuleLayer` the module belongs to, exposing
    the layer hierarchy.
  - `ModuleLayer.modules()` — returns all `Module` instances in the layer, exposing
    the complete set of named modules.
  - `ModuleLayer.findModule(String name)` — resolves a named module by name within
    a layer, exposing existence and identity of modules by name.
  - `Configuration.modules()` — returns all `ResolvedModule` instances in the
    module-system configuration, exposing the resolved module graph.
  - `ModuleReference.descriptor()` — returns the `ModuleDescriptor` for a module
    reference (used by `ModuleFinder` results), exposing descriptor content before
    the module is loaded.
- **Security effect** — untrusted code can no longer enumerate the deployed module
  graph, inspect module descriptors, or resolve modules by name unless explicitly
  granted policy authority.  This closes an information-disclosure path: an attacker
  that cannot enumerate exports/opens cannot easily identify soft targets for
  reflection or confused-deputy attacks.
- **Information-disclosure threat model** — without this gate, any untrusted code
  could:
  - enumerate all named modules and their layer hierarchy to map the internal
    architecture of the running JVM;
  - read `ModuleDescriptor` exports/opens tables to discover which packages are
    accessible via deep reflection;
  - use `ModuleLayer.findModule()` to probe for the presence of sensitive or
    security-relevant modules (e.g., internal instrumentation or management modules).
- **Relationship to `mutateModuleTopology` (§10)** — `readModuleTopology` is the
  complementary read gate.  An attacker that cannot read topology cannot easily
  determine which `addExports()`/`addOpens()` calls would succeed even if they
  somehow obtained `mutateModuleTopology` authority.  Together the two gates
  implement a read-write split on the module-system API surface.
- **Static vs runtime boundary** — like `mutateModuleTopology`, this gate applies
  to runtime API calls only.  Calling `Module.getDescriptor()` (which is one of
  the gated entry points) requires `readModuleTopology` at runtime; this does not
  affect `module-info` compilation or static descriptor resolution during module
  resolution at JVM startup.  JVM bootstrap flags and `module-info` compilation
  are not affected by this runtime permission.

Policy guidance for administrators:

- Default deny `RuntimePermission("readModuleTopology")` to untrusted code.
- Grant only to trusted frameworks, diagnostic tooling, monitoring agents, and
  code that legitimately needs to inspect the module graph at runtime (e.g.,
  OSGi containers, dependency-injection frameworks, build-time reflective scanners).
- Treat a `readModuleTopology` grant to code that also has
  `mutateModuleTopology` as equivalent to unrestricted module-topology authority
  (the code can both read and rewrite the module graph); audit such combined
  grants carefully even if other SecurityManager permission boundaries remain.
- Do not grant `readModuleTopology` to code that is only authorized to perform
  narrow reflective operations; prefer granting the specific `ReflectPermission`
  or `AccessDeclaredMembers` rights instead.

See cross-reference: §10 documents the complementary `RuntimePermission("mutateModuleTopology")`
gate that controls runtime mutation of the topology that the read APIs expose.

---

### 12) Dynamic Class Definition Permission

DirtyChai gates dynamic class definition via `MethodHandles.Lookup.defineClass()` with
the dedicated `DefineClassPermission` guard (commit 0f90b38, 2026-04-24).

- **Permission name:** `au.zeus.jdk.authorization.guards.DefineClassPermission`
- **Enforcement point:** `MethodHandles.Lookup.defineClass(boolean, Object)` — a
  package-private method in the `Lookup` inner class of `MethodHandles.java` that all public
  `defineClass()` entry points route through.  The check fires before any class-definition
  work begins (fail-secure placement).
- **Security effect:** Untrusted code can no longer bypass `LoadClassPermission` by
  defining classes dynamically through a sufficiently privileged `Lookup` object.  Prior to
  this gate, a caller holding a `Lookup` with `PACKAGE` or `MODULE` lookup mode could inject
  new classes into an existing module without triggering any `LoadClassPermission` check,
  because `Lookup.defineClass()` routes through the JVM's `jvm_lookup_define_class` path
  rather than `ClassLoader.loadClass()`.
- **Permission semantics:** No-target binary permission — code either holds `defineClass`
  authority or it does not.  The `DefineClassPermission` constructor uses the fixed target
  string `"ALLOW"` (inherited from `BasicPermission`) and carries no action field.  This
  reflects the uniform nature of the gate: the check applies to every dynamic class
  definition attempt regardless of the class being defined.
- **Integration with layered defense:**

  | Layer | Control | Enforcement |
  |-------|---------|-------------|
  | Layer 1 (Creation/Extension) | `RuntimePermission("createClassLoader")` / `RuntimePermission("extendClassLoader")` | ClassLoader instantiation / subclassing |
  | Layer 2 (Loading Control) | `LoadClassPermission` | Class loading via `ClassLoader.loadClass()` |
  | Layer 3 (Dynamic Definition) | `DefineClassPermission` ✅ **NOW GATED** | Class definition via `Lookup.defineClass()` (commit 0f90b38) |
  | Layer 4 (Policy) | Admin-controlled policy file | Governs permission grants for all layers |

- **Policy guidance:** Grant `DefineClassPermission` only to fully trusted code that
  legitimately needs to generate or define classes at runtime (e.g., bytecode-generation
  frameworks, compiler back-ends, instrumentation agents operating under a known
  trust boundary).  Do not grant to untrusted or sandboxed code.  A policy fragment
  template:

  ```
  grant codeBase "file:/path/to/trusted/bytecode-generator/-" {
      permission au.zeus.jdk.authorization.guards.DefineClassPermission;
  };
  ```

- **Residual N-15 resolution:** This implementation closes the previously documented
  dynamic-class-definition bypass sub-item of residual N-15.  The remaining N-15 items
  (module-system startup flags) are documented separately in the updated residual risks
  table below.

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

| ID | Residual risk | Root cause | Mitigation |
|---|---|---|---|
| 1 | Finite stack scan depth (`limit(50)`) | Bounded scan can miss deep malicious frames | Keep checks near entry points; fail secure on detection within scanned depth; treat out-of-range evasion as bounded residual |
| 2 | Generated-class detection is heuristic | Name patterns are probabilistic (false +/−) | Keep layered caller/stack/CodeSource/policy checks |
| 3 | Trusted-list and exemption governance | `trustedSMClass()` / ClassLoader exemptions are trust boundaries | Keep lists minimal; require explicit security review for additions |
| 4 | Policy quality remains critical | Over-broad grants negate hardening | Enforce least privilege with audited policy generation/review |
| 5 | Documentation drift — **RESOLVED** | Prior wording drifted from implementation | Keep docs/Javadoc synced with `limit(50)`; no open drift known |
| 6 | Confused-deputy in trusted paths (N-8, N-10; consolidated) | Reflection/MethodHandle and `<clinit>`/bootstrap can reach trusted code that uses unrestricted `doPrivileged` | Disallow unrestricted `doPrivileged` on security-sensitive trusted paths; keep stack-intersection guard |
| 7 | Finalizer/Cleaner context escape (N-9) | Both Finalizer and Cleaner threads now run under `neverPrivileged` (Issue #129), blocking `Subject.doAsPrivileged()` escalation. `neverPrivileged` alone cannot prevent unrestricted `AccessController.doPrivileged()` calls, which still intersect the callback class's `ProtectionDomain`. PoLP observation bounds those class-level grants, preventing unobserved operations. **OPERATIONALLY MITIGATED** — neverPrivileged (blocks Subject escalation) + PoLP (blocks unrestricted doPrivileged escalation) | Ensure both gates are active: deploy with `neverPrivileged` on Finalizer/Cleaner threads (Issue #129) and generate PoLP policies that reflect observed callback behaviour; avoid sensitive finalizer/cleaner work and prefer explicit `close()` |
| 8 | Runtime attach — residual risk substantially mitigated (N-11) | Attach is permission-gated, but over-grants, inactive SM, or OS compromise remain; **under PoLP + `LoadClassPermission` the agent loading gate provides defense-in-depth: agent codebases absent from PoLP observation window receive no `LoadClassPermission` grants and therefore cannot load classes even if `AttachPermission` is bypassed** | Keep attach grants narrow; use `-XX:+DisableAttachMechanism` where feasible; **deploy PoLP-generated policies so that agent codebases never receive `LoadClassPermission` grants; see N-11 analysis section** |
| 9 | Principal scope ambiguity (N-12) | Class+name grants can collide across realms; trusted-service mutation can abuse shared `Subject` | Use realm-qualified canonical principal identity; consider gating principal-set mutation |
| 10 | Coarse network permission granularity (N-14) | `SocketPermission` lacks granular distinction across network operation types and scope boundaries | Avoid wildcard network grants; publish hardened grant templates |
| 11 | Module system residuals (N-15) | Runtime topology mutation is gated (`mutateModuleTopology`) and inspection is gated (`readModuleTopology`), but startup flags `--add-opens`, `--add-exports`, and `--add-modules` bypass these checks at JVM bootstrap time and cannot be retroactively constrained by runtime permission gates | Treat startup flags as explicit trust-boundary decisions; no runtime revocation possible |
| 12 | Dynamic class definition (RESOLVED — N-15 sub-item) | `Lookup.defineClass()` now gated by `DefineClassPermission` (commit 0f90b38, 2026-04-24); untrusted dynamic class definition is no longer an ungated bypass of `LoadClassPermission` | Verify policy grants are appropriately restricted to trusted code that legitimately needs dynamic class generation; see §12 |
| 13 | FFM address/allocation surfaces (N-16) — **RESOLVED** | All FFM address-acquisition and arena-allocation surfaces are now gated: `Arena.ofConfined()`, `Arena.ofShared()`, and `Arena.ofAuto()` now each require `NativeMemoryPermission` (commit b62577c, 2026-04-24); `Linker.nativeLinker()` now requires `NativeInvocationPermission("native-linker")` (same commit); `MemorySegment.ofAddress(long)` now requires `NativeMemoryPermission("address-memory-segment")` (commit 3561dab, 2026-04-24) | — |
| 14 | FFM capability delegation risks (N-17) | Downcall `MethodHandle`, upcall stub `MemorySegment`, arena objects, and native segments are authority-carrying objects; once delegated to less-trusted code, no SM check fires at use time | Treat FFM capability objects as ambient authority; trusted code must not delegate them to untrusted code; document delegation policy constraints for administrators; see §8.4 and §8.8 Step 6 |

## Analysis: N-13 TLS Subject Authentication Context Propagation (COMPLETED)

### Issue Resolution
- **Issue:** [#134](https://github.com/pfirmstone/DirtyChai/issues/134)
- **Implementation commit:** [`5e5682a8dbb1d3aa0a0838893646e43bfd150dc6`](https://github.com/pfirmstone/DirtyChai/commit/5e5682a8dbb1d3aa0a0838893646e43bfd150dc6)
- **Status:** Completed in `src/java.rmi/share/classes/sun/rmi/transport/tcp/TCPTransport.java`

### Implementation Flow
1. `TCPTransport.ConnectionHandler.executeAcceptLoop()` checks accepted sockets for `SSLSocket`.
2. For TLS connections, peer certificates are read from `SSLSession.getPeerCertificates()`.
3. The end-entity `X509Certificate` principal (`X500Principal`) is extracted and bound to a read-only Subject: `new Subject(true, Set.of(principal), Set.of(), Set.of())`.
4. `ConnectionHandler.run()` dispatches under that identity via `Subject.doAsPrivileged(subject, (PrivilegedAction<Void>) () -> { run0(); return null; }, null)`.
5. Service execution can resolve the authenticated peer identity with `Subject.getSubject(AccessController.getContext())`.

### Exception Handling, Fallback, and Subject Immutability
- `SSLPeerUnverifiedException` is explicitly handled during peer extraction. If peer verification is unavailable, dispatch proceeds without Subject binding (unauthenticated path), preserving availability and fail-secure behavior.
- `Subject(true, principals, ...)` keeps the Subject read-only, preventing downstream principal mutation and Subject-based privilege injection.

### Integration: ACC Semantics and CombinerSecurityManager
Passing `null` ACC to `Subject.doAsPrivileged` intentionally uses an empty context so authorization derives from Subject principals through `SubjectDomainCombiner` (principal-only authorization for the authenticated peer identity). No `CombinerSecurityManager` changes were required; existing permission intersection semantics apply unchanged.

### Security Properties Achieved
- Principal binding from authenticated TLS peer to dispatch execution context.
- Immutable Subject state prevents downstream principal extension/injection.
- Policy-driven principal authorization remains active in service method context.
- Graceful fallback for unverified peers (`SSLPeerUnverifiedException`) with no cross-request context leak (peer Subject scoped to connection handler dispatch).

### Files Modified (Implementation Reference)
Implementation is contained in `src/java.rmi/share/classes/sun/rmi/transport/tcp/TCPTransport.java` (peer extraction/Subject construction in lines `430-446`; Subject-bound dispatch in lines `745-758`).

### Remaining Work
- **TLS-FACTORY-TEST:** add integration test asserting service-side `Subject.getSubject(...)` maps to authenticated client certificate principal

---

## Analysis: Reflection and MethodHandle Invocation in the Permission-Check Path (N-8)
### The Question
Does `Method.invoke()` or `MethodHandle.invoke*()` allow untrusted code to bypass
`SecurityManager.checkPermission` and the stack-intersection semantics that protect
confused-deputy native-call scenarios? This analysis checks reflective stack retention, reflected custom `SecurityManager` installation, and `MethodHandle` invocation/lookup context effects.
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
DirtyChai's `System.setSecurityManager()` is `@CallerSensitive` and runs
`validateCallerStackWithStackWalker()` after direct-caller validation.
That stack walk rejects reflection (`java.lang.reflect.*`, `sun.reflect.*`),
unsafe paths, non-whitelisted `java.lang.invoke.*` runtime frames, and common
generated-code patterns.
`setSecurityManagerMethod.invoke(null, myCustomSM)` necessarily introduces a
reflection frame, so the validation throws `SecurityException` before install.
**This attack path is blocked by DirtyChai.**
### MethodHandle Invocation Frames
A runtime `MethodHandle.invoke()` / `invokeExact()` call contributes
`java.lang.invoke` invocation frames. DirtyChai allows only linkage-time classes
(`LambdaMetafactory`, `StringConcatFactory`, `MethodHandles`, `MethodType`) and
blocks runtime invocation frames (`MethodHandle`, runtime `MethodHandles$Lookup`).
A `MethodHandle` targeting `System.setSecurityManager` therefore leaves a
non-whitelisted invocation frame and is rejected by stack validation.
**This attack path is blocked by DirtyChai.**
### MethodHandle Lookup and Caller Context
`MethodHandles.Lookup` captures lookup-time member-access context, not an
`AccessControlContext`. At invocation time, permission checks still evaluate the
*live* thread stack. The lookup class does not replace runtime stack context.
Result: for permission checks inside a target method, the untrusted caller's
`ProtectionDomain` remains part of the intersection. **Protected by default.**
### Residual Considerations
- **Unrestricted `doPrivileged` inside target code:** if trusted code executes unrestricted `AccessController.doPrivileged(...)`, stack intersection stops there and can drop the untrusted caller domain (same residual confused-deputy obligation as Task N-6).
- **`Lookup.in(otherClass)` context changes:** still gated by `SecurityManager.checkPackageAccess()` during lookup construction (unnamed-module callers only; the JVM skips `checkPackageAccess` entirely when the class being loaded is in a named module — named-module encapsulation is enforced at the JVM level before this call is reached).
- **`MethodHandle` adapters (`asType`, `bindTo`, `asSpreader`):** wrappers do not remove calling-code frames from the live stack; no new bypass is introduced.
### Summary — Reflection and MethodHandle Path Status
| Attack Scenario | Stack Walk Result | DirtyChai Status |
|-----------------|-------------------|-----------------|
| `Method.invoke(target, args)` used to trigger a native permission check | Untrusted caller PD remains on stack; intersection enforced | **Protected by default** |
| `Method.invoke(null, customSM)` to install custom `SecurityManager` | Reflect frame detected by `validateCallerStackWithStackWalker()` | **Blocked by DirtyChai** |
| `MethodHandle.invoke` to install custom `SecurityManager` | Non-whitelisted `java.lang.invoke.*` frame detected | **Blocked by DirtyChai** |
| `MethodHandle.invoke` to call trusted class native method | Untrusted caller PD remains on stack; intersection enforced | **Protected by default** |
| Trusted target uses unrestricted `doPrivileged` inside reflective call | Stack walk stops at `doPrivileged`; untrusted caller PD dropped | **Residual gap — trusted code must not use unrestricted `doPrivileged`** |

### N-8 Residual Risk Mitigation via Principle of Least Privilege (PoLP) Policy Generation

The summary table above notes that an unrestricted `doPrivileged` call inside trusted code is a
residual gap. In practice, this gap is substantially bounded when the recommended DirtyChai
deployment model is used: **observation-based PoLP policy generation via polpAudit**.

#### How PoLP Policy Generation Works

PoLP policy generation is an observation-based approach:

1. **Observe:** Run the application under an active SecurityManager with polpAudit monitoring every
   `SecurityManager.checkPermission()` call.
2. **Capture:** Generate a policy file that grants *only* the permissions that were actually requested
   during the observation run — no wildcards, no `AllPermission`, no implicit broadening.
3. **Review:** Inspect the generated policy. If a legitimate but unexercised code path requires
   additional permissions, add them explicitly after human review.
4. **Deploy:** The resulting policy constrains every domain, including trusted libraries, to exactly
   the permissions they were observed to need.

#### How PoLP Bounds the N-8 Attack Surface

Even if trusted code contains an unrestricted `doPrivileged` call, it can only execute operations
that the *policy* authorises for its domain. The `doPrivileged` frame drops the untrusted caller
from the stack intersection, but the trusted domain itself is still subject to its own policy grants.

```
Without PoLP (over-broad grant):

  grant codeBase "file:/trusted/lib/-" {
      permission java.security.AllPermission;      // ← grants everything
  };

  Trusted library calls System.load() inside unrestricted doPrivileged:
  → SecurityManager checks TrustedLib domain only (untrusted caller dropped)
  → AllPermission implies RuntimePermission("loadLibrary.*")
  → Native load SUCCEEDS  ✗ VULNERABLE — attacker can reach any native op
```

```
With PoLP Policy (observation-based grant):

  grant codeBase "file:/trusted/lib/-" {
      permission au.zeus.jdk.authorization.guards.NativeInvocationPermission "native-linker";
      permission java.lang.RuntimePermission "loadLibrary.mylib";
      permission java.io.FilePermission "/opt/myapp/lib/mylib.so", "read";
      // nothing else — polpAudit observed no other permission requests
  };

  Trusted library calls System.load("/opt/myapp/lib/mylib.so") inside unrestricted doPrivileged:
  → SecurityManager checks TrustedLib domain only (untrusted caller dropped)
  → Policy grants RuntimePermission("loadLibrary.mylib") — exact match
  → Native load SUCCEEDS for the one observed library  ✓ BOUNDED

  Attacker attempts to route a different native path through the same doPrivileged:
  → SecurityManager checks TrustedLib domain
  → Policy does NOT grant RuntimePermission("loadLibrary.evilnative")
  → SecurityException: access denied  ✓ BLOCKED BY POLICY
```

#### Concrete Before/After Comparison

| Scenario | Without PoLP | With PoLP |
|----------|-------------|-----------|
| Trusted lib has `AllPermission`; untrusted caller routes native op via `doPrivileged` | ✗ Exploit succeeds — no bound on what can be executed | ✓ Impossible — PoLP never generates `AllPermission` grants |
| Trusted lib loads one specific native library | ✓ Works | ✓ Works — `loadLibrary.<name>` grant present from observation |
| Attacker uses same `doPrivileged` path to load a different native library | ✗ Succeeds if `AllPermission` or wildcard `RuntimePermission` granted | ✓ Blocked — only the observed library is in the grant |
| Trusted lib opens a specific configuration file | ✓ Works | ✓ Works — observed `FilePermission` path present in grant |
| Attacker routes arbitrary file read via the same `doPrivileged` | ✗ Succeeds with broad `FilePermission("<<ALL FILES>>","read")` | ✓ Blocked — only the one observed path is in the grant |
| Trusted lib makes an outbound network call to a known host | ✓ Works | ✓ Works — observed `SocketPermission` for that host present |
| Attacker routes arbitrary outbound connection via `doPrivileged` | ✗ Succeeds with `SocketPermission("*","connect")` | ✓ Blocked — only the observed host/port is in the grant |

#### Why N-8 Becomes Low-Practical-Risk Under PoLP

PoLP policy generation eliminates the precondition that makes N-8 dangerous: **over-broad grants**.
Without an over-broad grant, unrestricted `doPrivileged` inside trusted code can only authorise
operations that the policy explicitly anticipated. The attack surface for confused-deputy escalation
collapses to *only those operations the code was already trusted to perform*.

The practical risk reduction works at two levels:

1. **No implicit privilege escalation path:** An attacker routing an unexpected operation through an
   unrestricted `doPrivileged` will encounter a permission denial unless the operation was explicitly
   observed and granted. The `doPrivileged` boundary cannot conjure permissions that the policy does
   not contain.

2. **Observation-based policy is self-limiting:** polpAudit-generated grants reflect actual runtime
   behaviour. Novel attacker-introduced operations were, by definition, not observed during capture,
   so they are absent from the policy. This creates a natural boundary around previously unseen
   attack paths.

#### Residual Scenarios Where N-8 Remains Relevant

PoLP deployment does not eliminate N-8 in every scenario. The following cases keep N-8 as a live
risk and must be managed through separate controls:

| Residual Scenario | Risk Level | Required Control |
|-------------------|------------|-----------------|
| Administrator manually broadens a PoLP-generated grant (e.g., adds `AllPermission` or wildcard `RuntimePermission`) | Medium | Policy governance: change-control process for policy file modifications; peer review for any grant wider than what polpAudit produced |
| Trusted library is compromised (supply-chain attack) and introduces a new unrestricted `doPrivileged` call that was not present at policy-capture time | High | Supply-chain security: code provenance, dependency signing, regular policy re-capture after library updates |
| An unexercised code path inside trusted code performs a sensitive operation that polpAudit never observed (e.g., error-handling branch that loads a diagnostic library) | Low–Medium | Test coverage: ensure all execution branches, including error-handling and shutdown paths, are exercised before policy capture; re-run polpAudit after updates |
| PoLP policy is used as a starting template but then extended with permissions not derived from observation (e.g., "just in case" grants) | Medium | Policy review discipline: treat every non-observed addition as requiring explicit security justification and documentation |

#### Updated Risk Assessment for N-8 Under PoLP

| Deployment Model | Practical Risk Level | Rationale |
|-----------------|---------------------|-----------|
| PoLP-generated policy, no manual broadening | **Low** | Attack surface bounded to observed permission set; no escalation path beyond explicit grants |
| PoLP-generated policy, with targeted manual additions reviewed by a human | **Low–Medium** | Each addition is individually scoped; risk proportional to breadth of added grants |
| Policy with `AllPermission` or broad wildcard grants | **Medium–High** | PoLP benefit is absent; N-8 residual is the full confused-deputy risk described in the summary table above |
| No SecurityManager active | **High** | No permission checks at all; N-8 is one of many unrestricted attack vectors |

**Summary:** N-8 (Confused Deputy via Unrestricted `doPrivileged`) is a genuine structural residual
in the Java security model. Under PoLP-based deployment — the primary recommended model for
DirtyChai — its practical risk is **Low**, because the attack surface is bounded by the explicit
observation-derived policy grants. Administrators following PoLP discipline should not treat N-8 as
a blocking concern; it becomes significant only when policy governance, supply-chain integrity, or
test coverage controls are absent.

---

## Analysis: Finalizer and Cleaner Thread Execution Contexts (N-9)

### The Question

Finalizer threads and `java.lang.ref.Cleaner` daemon threads execute callback
code in a different thread than the one that created the object.  Does this
mean the original creator's restricted `AccessControlContext` is lost, and can
this loss be exploited to run sensitive operations with escalated permissions?

### Finalizer and Cleaner Execution Model

- **Finalizer:** Objects with non-trivial `finalize()` are queued and processed
  by the JVM `Finalizer` daemon thread.
- **Finalizer thread context:** Created at boot via
  `AccessController.doPrivileged(..., AccessControlContext.neverPrivileged())`,
  so callback execution is never-privileged.
- **Cleaner:** `java.lang.ref.Cleaner` daemon thread is also created under
  `AccessControlContext.neverPrivileged()` (Issue #129), so cleanup callbacks
  are likewise never-privileged.
- In both models, the creator thread's `AccessControlContext` is **not**
  propagated to the callback thread.

### Stack Intersection & Permission Enforcement

During finalizer/cleaner callback execution, `SecurityManager.checkPermission()`
and `AccessController.getContext()` still walk the *current* callback stack.
The callback class frame remains on-stack, so its `ProtectionDomain` is part of
the domain intersection.

```
java.base finalizer/cleaner daemon frame (unprivileged)
  callback implementation frame (trusted or untrusted PD)
    [permission check]
```

Result: untrusted callback code without `NativeInvocationPermission` is blocked;
trusted callback code is allowed only if policy grants the required permission.

### Execution-Context Escape (Core Risk)

- **Limited-context constraint is lost when finalizer/cleaner callbacks run on a
  separate thread:** restrictions encoded in the creator's limited
  `AccessControlContext` do not survive to callback execution, while class-level
  policy grants still apply.

### Dual-Layer Mitigation: neverPrivileged + PoLP

#### Layer 1 — neverPrivileged (Issue #129)

Both Finalizer and Cleaner threads now execute under
`AccessControlContext.neverPrivileged()`.  This is **more restrictive than
unprivileged**: a `neverPrivileged` context cannot accumulate permissions from
authenticated `Subject` principals, so the `Subject.doAsPrivileged()` escalation
path is completely closed.

```
neverPrivileged (finalizer/cleaner thread):
  ✓ Blocks: Subject.doAsPrivileged(subject, action, null)
  ✓ Blocks: gaining permissions from authenticated principal credentials
  ✗ Cannot block: unrestricted AccessController.doPrivileged(() -> ...)
```

#### Layer 2 — PoLP Policy Observation

`neverPrivileged` does **not** prevent a callback from issuing an unrestricted
`AccessController.doPrivileged(action)` call.  When that call is made, the JVM
computes the stack intersection starting from the callback's `ProtectionDomain`:

```
// Callback executing in neverPrivileged context
AccessController.doPrivileged(() -> {
    // neverPrivileged does not block this path
    // Stack intersection is computed from the callback class PD
    // Policy grants for that class are the effective ceiling
    return performSensitiveOperation();
});
```

The `ProtectionDomain` of the callback class is therefore the effective
authority ceiling.  PoLP policy generation limits that ceiling to what was
**actually observed** during normal operation:

```
Observation phase:
  Finalizer observed: FilePermission("temp/cleanup.txt", "read")
  Policy grants:      FilePermission("temp/cleanup.txt", "read") only

Runtime escalation attempt:
  Finalizer calls doPrivileged(() -> read("/etc/passwd"))
  Stack intersection: PoLP grant (limited) ∩ callback class domain
  Result: DENIED — /etc/passwd not in policy grant
```

Unobserved operations are denied by default, so a callback cannot escalate to
permissions it was never observed exercising.

#### Combined Mitigation Model

| Escalation Path | neverPrivileged | PoLP | Combined Result |
|-----------------|-----------------|------|-----------------|
| `Subject.doAsPrivileged()` to gain principal permissions | ✅ **Blocked** | — | Eliminated |
| Unrestricted `AccessController.doPrivileged()` using class policy grants | ❌ Not blocked | ✅ **Bounded** to observed behaviour | Eliminated |
| Any escalation beyond observed behaviour | — | ✅ **Denied** by default | Eliminated |

**Without PoLP**: `neverPrivileged` alone is insufficient — unrestricted
`doPrivileged` in a callback can still exploit any over-broad class-level
policy grants.

**With both layers active**: no escalation path remains open.

### Policy Decision

| Scenario | In-Process Guard (DirtyChai) | Process Isolation Required? |
|----------|------------------------------|-----------------------------|
| Untrusted finalizer/callback calls native method | Blocked by stack intersection (untrusted PD is on-stack) | No |
| Trusted finalizer/callback calls native method | Allowed only if policy grants `NativeInvocationPermission`; daemon thread itself is never-privileged (Issue #129) | No (intended) |
| Trusted callback bypasses creator's limited context via `Subject.doAsPrivileged()` | **Blocked** — `neverPrivileged` context cannot gain Subject principal permissions | No (Issue #129 resolved) |
| Trusted callback issues unrestricted `AccessController.doPrivileged()` to access resources beyond observed behaviour | **Blocked by PoLP** — policy ceiling is bounded to observed callback behaviour; unobserved operations denied | No (PoLP required) |
| Trusted callback bypasses creator's limited context — no PoLP deployed | **Not blocked** — class-level grants act as ceiling; over-broad grants exploitable | **Yes — process isolation required if PoLP not in use** |
| Attacker triggers GC of trusted object with sensitive callback | Escalation bounded by PoLP ceiling; if callback never observed accessing target, denied | No under PoLP; process isolation backstop without it |

### Guidance for Trusted Library Authors

For trusted classes whose finalizers/cleaner callbacks perform sensitive
operations (native, file, network):

1. **Prefer `Cleaner` over `finalize()`** for modern, more predictable cleanup.
2. **Do not encode application security constraints in callbacks;** enforce them
   at construction/use time or via explicit `close()` / `release()`.
3. **If privileged callback work is unavoidable, keep it minimal and explicit**
   (narrow `doPrivileged` scope, documented justification).
4. **Ensure finalizer/cleaner behaviour is exercised during the PoLP observation
   window** so generated policy grants are bounded to actual callback needs;
   over-broad grants create the escalation surface that `neverPrivileged` alone
   cannot close.
5. **Treat process isolation as a backstop for deployments without PoLP** —
   when PoLP policies are properly generated and both layers (neverPrivileged +
   PoLP) are active, process isolation is not required for N-9 mitigation.

---

## Analysis: Constant-Pool and Class-Initialization Security (N-10)

### The Question

Class initialization (`<clinit>`) and constant-pool resolution (`invokedynamic`,
`CONSTANT_Dynamic`) execute lazily at first use. The security question is whether
that lazy execution can bypass DirtyChai's stack-intersection permission model.

### Class Initialization (`<clinit>`) Stack-Membership Guarantee

When code first actively uses a class (`new`, `getstatic`, `putstatic`,
`invokestatic`, `Class.forName(..., true, ...)`), `<clinit>` runs on the triggering
thread. During that execution, the triggering caller remains on the live stack.
If untrusted code triggers a trusted class initializer, the untrusted frame is
still present at permission-check time.

```
UntrustedClass.doSomething()          ← triggers TrustedClass static field access
  ↑ triggers initialization ↓
TrustedClass.<clinit>()               ← trusted ProtectionDomain
  [SecurityManager.checkPermission called here]
```

`SecurityManager.checkPermission()` intersects all stack domains present at that
point. So trusted `<clinit>` code does not erase the untrusted caller: if the
untrusted domain lacks a required permission, the check denies by default.

### The `LoadClassPermission` Gate

DirtyChai adds a front-door gate at class loading time: untrusted code must hold
`LoadClassPermission("some.trusted.Class")` to load new classes into a reachable
namespace. Without that permission, untrusted code cannot force-load a new target
and therefore cannot trigger its first initialization.

This gate applies to loading, not to initialization of classes already loaded into
a reachable namespace (for example, by startup/platform code). In that case,
untrusted code may still trigger `<clinit>`, but stack intersection still governs
security-sensitive operations inside the initializer.

### Unrestricted `doPrivileged` Inside `<clinit>`

The same confused-deputy rule from normal calls applies to static initialization:
if `<clinit>` uses unrestricted `AccessController.doPrivileged(...)`, stack walking
stops there and the untrusted triggering domain is dropped from the intersection.
That creates a privilege-elevation path reachable through class initialization.

**Obligation for trusted library authors:** Do **not** use unrestricted
`doPrivileged` inside `<clinit>` (or any static initializer block) on code paths
that access security-sensitive resources. Use restricted `AccessControlContext`
or explicit `Permission` lists.

### `invokedynamic` and `CONSTANT_Dynamic` Bootstrap Resolution

`invokedynamic` resolves lazily at first execution by invoking its bootstrap
method on the calling thread; `CONSTANT_Dynamic` does the same on first `ldc`.
In both cases, the triggering caller remains on-stack during bootstrap execution,
so permission checks are intersection-enforced by default.

Residual risk is identical: a bootstrap method that uses unrestricted
`doPrivileged` can drop the untrusted domain and act as a confused deputy.

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

## Analysis: Runtime Agent Attachment and PoLP Policy Defense (N-11)

### The Question

When an attacker gains the ability to attach a Java agent to a running JVM —
either by holding `AttachPermission("attachVirtualMachine")`, by administrative
over-grant, or by OS-level compromise — can DirtyChai prevent the attached
agent from executing code?

### Attack Model (Without PoLP)

Under a traditional SecurityManager deployment without least-privilege policy
generation, the attach path provides a viable escalation route:

1. Attacker calls `VirtualMachine.attach(pid)` (requires `AttachPermission`
   or OS-level process access).
2. JVM loads the agent JAR via `Instrumentation.appendToSystemClassLoaderSearch()`.
3. Agent classes load without a `LoadClassPermission` gate (agent classloader is
   trusted by construction under a broad policy).
4. Agent `premain` / `agentmain` executes with the full permissions granted to
   the system class loader domain.
5. **Result:** Complete privilege escalation — attacker code executes with
   system-class-loader-domain permissions.

### The PoLP + `LoadClassPermission` Defense Gate

DirtyChai's `SecureClassLoader` enforces a `LoadClassPermission` check for
every class load: the calling (loading) code domain must hold
`LoadClassPermission` for the class being loaded.  When policies are generated
by **observation-based PoLP tooling** (e.g. `polpAudit`), only permissions
actually exercised during the observation window are granted.

**Key structural property:** agent code is, by definition, *not part of the
observed baseline*.  Agents are injected dynamically after JVM startup — they
are never present during the PoLP observation window.  Consequently:

- The PoLP-generated policy grants `LoadClassPermission` only to codebases
  observed loading specific classes.
- The agent codebase has no entry in the generated policy.
- When the agent JAR is attached and agent classes are requested, the class
  loader attempts to load them.
- The `LoadClassPermission` check fires; the agent codebase domain holds no
  such grant.
- **Class loading fails.  Agent initialisation is aborted before any agent
  code runs.**

```
Attack path under PoLP + LoadClassPermission
─────────────────────────────────────────────────────────────────────
1. Attacker bypasses / is granted AttachPermission
2. VirtualMachine.attach(pid) succeeds — JVM receives attach request
3. Agent JAR appended to search path
4. Agent class loader attempts: ClassLoader.loadClass("com.attacker.Agent")
       ↓
   SecureClassLoader.checkPermission(
       new LoadClassPermission("com.attacker.Agent"))
       ↓
   Agent codebase has NO LoadClassPermission grant (absent from PoLP policy)
       ↓
   SecurityManager.checkPermission → DENY
       ↓
5. ClassNotFoundException / SecurityException — agent fails to initialise
6. No agent code executes
─────────────────────────────────────────────────────────────────────
Result: Attack surface ELIMINATED
```

### Why Agent Code Is Naturally Excluded from PoLP Observations

PoLP policy generation captures permissions from the live permission-check
stream during normal application execution.  Agent attachment is an
*administrative / adversarial* event that occurs:

- After the observation window closes, or
- In environments where the application under observation does not itself
  attach agents.

In either case, agent codebases never appear as requesting code domains in the
`SecurityManager.checkPermission()` call stream.  They therefore receive no
`LoadClassPermission` entries in the generated policy.  This exclusion is
structural, not configuration-dependent.

### Defense-in-Depth Layering

| Gate | Where Enforced | Scope |
|------|---------------|-------|
| `AttachPermission("attachVirtualMachine")` | `VirtualMachine.attach()` pre-check | Blocks the JVM from accepting the attach request |
| `-XX:+DisableAttachMechanism` | JVM startup flag | Removes the attach listener entirely at OS level |
| `LoadClassPermission` under PoLP policy | `SecureClassLoader.loadClass()` | Blocks class loading even if attach succeeds and agent JAR is appended |

All three gates are independent.  An attacker who bypasses `AttachPermission`
(e.g. admin over-grant or OS compromise) still faces the `LoadClassPermission`
gate, which is enforced purely by the SecurityManager permission-intersection
model and cannot be bypassed by the attach mechanism itself.

### Risk Assessment Update

| Deployment Model | N-11 Risk Level | Rationale |
|---|---|---|
| No SecurityManager (legacy) | **Critical** | No gate; agent executes unconditionally |
| SecurityManager, broad policy (`AllPermission`) | **High** | `AttachPermission` may be over-granted; agent loads freely once attached |
| SecurityManager, manually-written narrow policy | **Medium** | Depends on policy author excluding agent codebases from `LoadClassPermission` grants |
| SecurityManager + PoLP-generated policy | **Low** | Agent codebase structurally absent from observation window → no `LoadClassPermission` grant → class loading blocked |
| PoLP policy + `-XX:+DisableAttachMechanism` | **Negligible** | Attach mechanism removed entirely; `LoadClassPermission` gate retained as a backstop |

### Practical Guidance for Hardened Deployments

1. **Deny `AttachPermission("attachVirtualMachine")` to all untrusted code.**
   This is the primary, highest-impact control.
2. **Generate policy with PoLP tooling from a clean observation window.**
   Agent codebases must not be present during the observation run; if they are
   (e.g. monitoring agents started at JVM boot), exclude their codebases
   explicitly or restrict their `LoadClassPermission` grants after generation.
3. **Use `-XX:+DisableAttachMechanism` in production environments where runtime
   attach is not operationally required.**  This eliminates the OS-level attach
   listener and provides a hardware-independent backstop independent of
   SecurityManager state.
4. **Do not grant `LoadClassPermission` wildcards** (e.g.
   `LoadClassPermission("*")`) to any codebase.  Wildcard grants defeat the
   loading gate for all agent classes.
5. **Treat the agent codebase as untrusted by default.** Even if an agent JAR
   is from a known vendor, it should not receive `LoadClassPermission` grants
   broader than what it legitimately needs during normal operation.

---

## Recommendations

### High priority

1. **Keep `trustedSMClass()` under strict review control** — require explicit security review and written rationale for every addition.
2. **Add targeted regression tests for residual-risk boundaries** — cover deep-stack and generated/invoke-frame classification, reflection/MethodHandle native-wrapper paths (N-8), Finalizer/Cleaner permission enforcement (N-9), and class-initialization stack-intersection enforcement (N-10).
3. ~~**Correct stale Javadoc in `System.java` (source file)**~~ — Resolved: stack-scan-depth wording now consistently matches `limit(50)` across source and documentation.
4. **Document hardened-deployment attach controls and JVM flag requirements (N-11)** — deny `AttachPermission("attachVirtualMachine")` (and where applicable `AttachPermission("createAttachProvider")`) to untrusted code, use `-XX:+DisableAttachMechanism` for defense in depth, and treat `--add-opens`/`--add-exports`/`--add-modules` as trusted-perimeter decisions. **Additionally, deploy PoLP-generated policies so that agent codebases never receive `LoadClassPermission` grants — this provides a critical second gate that blocks agent class loading even if `AttachPermission` is bypassed; see the N-11 analysis section for the full layered-defense model.**

### Medium priority

5. **Consider making stack scan depth configurable (safe defaults retained)** — allow hardened deployments to raise depth while preserving compatibility defaults.
6. **Add optional security telemetry for denied installation attempts** — emit deny-event telemetry to improve attack detection and policy tuning.
7. ~~**Gate FFM arena allocation surfaces and evaluate linker guard (§8, N-16, N-17)**~~ — **Completed (commit b62577c, 2026-04-24):** Steps 1–4 from §8.8 have been implemented: `NativeMemoryPermission` checks are now enforced at `Arena.ofShared()` (`"shared-arena"`), `Arena.ofConfined()` (`"confined-arena"`), and `Arena.ofAuto()` (`"auto-arena"`); `Linker.nativeLinker()` is now gated by `NativeInvocationPermission("native-linker")`. **Continue monitoring FFM delegation risks (N-17, §8.4, §8.8 Step 6):** the front-door capability-delegation model means that downcall handles, upcall stubs, arenas, and native segments remain authority-carrying objects once created; trusted code must not delegate them to untrusted code; `MemorySegment.reinterpret()` and `Arena.global()` remain gated; do not open `jdk.internal.foreign` to user code under any circumstance (§8.5).
8. ~~**Evaluate `MethodHandles.Lookup.defineClass()` permission gate (N-15 / §7)**~~ — **Completed (commit 0f90b38, 2026-04-24):** `DefineClassPermission` now gates `Lookup.defineClass()` calls at the private inner method level in `MethodHandles.java`, preventing untrusted dynamic class definition. See §12 for the full security documentation.
9. **Document recommended `SocketPermission` policy structure for hardened deployments (N-14 / §9)** — provide a hardened template separating loopback/LAN/multicast/external grants, avoiding wildcard `connect`, and constraining `DatagramSocket` discovery plus multicast/unicast scope.
10. ~~**Evaluate `LoadModulePermission` gate for runtime module mutation (N-15 / §7)**~~ — Resolved: runtime `Module.addExports()`/`Module.addOpens()` are policy-gated by `RuntimePermission("mutateModuleTopology")` (§10) and runtime topology inspection is policy-gated by `RuntimePermission("readModuleTopology")` (§11); startup `--add-opens`/`--add-exports`/`--add-modules` remains a trusted-perimeter decision.

---

## Final Assessment

Dirty Chai’s current implementation demonstrates robust defense-in-depth for SecurityManager installation and policy enforcement paths, with clear fail-secure tendencies and improved handling from the Issue #85 cycle, and with the completion of the dynamic-class-definition gate (`DefineClassPermission`, commit 0f90b38, 2026-04-24).

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
- `src/java.base/share/classes/java/lang/ClassLoader.java`, `src/java.base/share/classes/java/lang/foreign/SymbolLookup.java`, `src/java.base/share/classes/jdk/internal/foreign/SystemLookup.java`, `src/java.base/share/classes/jdk/internal/loader/NativeLibraries.java` — `NativeInvocationPermission` enforcement at native symbol resolution; `NativeLibraries.findLibraryNameAddress()` provides null-safe library name resolution for permission construction
- `src/java.base/share/classes/jdk/internal/foreign/AbstractMemorySegmentImpl.java` — `NativeMemoryPermission("reinterpret-memory-segment")` enforcement in `reinterpretInternal()` before `MemorySegment.reinterpret()` proceeds; the permission check is at lines 157–161 (`reinterpretInternal()` method body); the three public `reinterpret()` overloads that delegate to it are at lines 132–155
- `src/java.base/share/classes/java/lang/foreign/Arena.java` — `NativeMemoryPermission("global-arena")` enforcement in `Arena.global()` (line 246); `NativeMemoryPermission("auto-arena")` in `Arena.ofAuto()` (line 229); `NativeMemoryPermission("confined-arena")` in `Arena.ofConfined()` (line 265); `NativeMemoryPermission("shared-arena")` in `Arena.ofShared()` (line 280); all four arena allocation surfaces now gated (commit b62577c); see §8.1 and §8.8
- `src/java.base/share/classes/java/lang/foreign/MemorySegment.java` — `MemorySegment.ofAddress(long)` at [`lines 1573–1576`](https://github.com/pfirmstone/DirtyChai/blob/trunk/src/java.base/share/classes/java/lang/foreign/MemorySegment.java#L1573-L1576) now gated by `NativeMemoryPermission("address-memory-segment")` (commit 3561dab, 2026-04-24); address-acquisition gap documented and resolved in §8.2
- `src/java.base/share/classes/java/lang/foreign/Linker.java` — `Linker.nativeLinker()` at line 578 now gated by `NativeInvocationPermission("native-linker")` (commit b62577c); `downcallHandle()` and `upcallStub()` methods are `@Restricted` / `ensureNativeAccess`-only with no `NativeInvocationPermission` check; linker delegation risks documented in §8.3
- `src/java.base/share/classes/jdk/internal/foreign/abi/AbstractLinker.java` — linker implementation; `DOWNCALL_CACHE` / `UPCALL_CACHE` at lines 88–89; `downcallHandle()` at lines 93–104; `upcallStub()` at lines 128–147; all gate via `ensureNativeAccess` only
- `src/java.base/share/classes/jdk/internal/foreign/SegmentFactories.java` — `makeNativeSegmentUnchecked()` (line 81) constructs native segments from raw addresses with no SecurityManager check; protected only by `jdk.internal.foreign` package encapsulation; module-open bypass risk documented in §8.5
- `src/java.base/share/classes/au/zeus/jdk/authorization/guards/LoadClassPermission.java` — guard definition
- `src/java.base/share/classes/au/zeus/jdk/authorization/guards/DefineClassPermission.java` — guard definition; binary permission gating dynamic class definition via `Lookup.defineClass()`; see §12
- `src/java.base/share/classes/au/zeus/jdk/authorization/guards/NativeInvocationPermission.java` — guard definition
- `src/java.base/share/classes/au/zeus/jdk/authorization/guards/NativeMemoryPermission.java` — guard definition; recognized target names include `"global-arena"`, `"auto-arena"`, `"confined-arena"`, `"shared-arena"`, `"reinterpret-memory-segment"`, and `"address-memory-segment"` (added commit 3561dab, 2026-04-24); see §8.1, §8.2, and §8.8
- `src/java.base/share/classes/au/zeus/jdk/authorization/guards/SerialObjectPermission.java` — guard definition
- `src/java.base/share/classes/java/io/ObjectInputStream.java` — `SerialObjectPermission` check placement in `readOrdinaryObject()` before instantiation
- `src/java.base/share/classes/java/io/SerialCallbackContext.java` — confirms callback context no longer carries the permission check logic
- `src/java.base/share/classes/au/zeus/jdk/authorization/policy/ConcurrentPolicyFile.java` — policy grant evaluation and fail-secure behavior references
- `src/java.base/share/classes/au/zeus/jdk/net/Uri.java` — URI validation behavior used in CodeSource/policy matching rationale
- Issue #85 (repository issue tracker) — remediation baseline for hardened exception and validation handling
- OpenJDK 21 reference (`jdk-21+35`): `java/lang/System.java`, `java/security/AccessController.java`, `java/security/AccessControlContext.java`, `javax/security/auth/Subject.java`, `java/lang/ThreadBuilders.java`, `java/lang/Thread.java`, `java/util/concurrent/Executors.java`, `java/security/SecureClassLoader.java`, `java/lang/Module.java`, `java/io/ObjectInputStream.java`
- `java.lang.instrument.Instrumentation` — agent attachment threat surface; `getAllLoadedClasses()` / `redefineClasses()` only reachable with an active `-javaagent`, but see N-11 for the runtime-attach path
- `com.sun.tools.attach.VirtualMachine`, `com.sun.tools.attach.AttachPermission`, `com.sun.tools.attach.spi.AttachProvider`, `sun.tools.attach.HotSpotAttachProvider` — runtime attach path and enforced permission gates (`attachVirtualMachine`, `createAttachProvider`) discussed in N-11
- `javax.security.auth.Subject.getPrincipals()` — principal mutation boundary; live mutable set; cross-realm collision and injection risks documented in §E and N-12
- `src/java.base/share/classes/java/lang/invoke/MethodHandles.java` — `DefineClassPermission` enforcement in `Lookup.defineClass(boolean, Object)` (a package-private method in the `Lookup` inner class, commit 0f90b38); all public `defineClass()` entry points route through this method, ensuring complete coverage of the dynamic class-definition path; see §12
- `java.lang.invoke.MethodHandles.Lookup.defineClass()` — dynamic class definition gate; previously bypassed `LoadClassPermission`; now gated by `DefineClassPermission` (commit 0f90b38); residual fully resolved; see §12 and updated N-15 in Residual Risks table
- `java.net.DatagramSocket` / `java.net.MulticastSocket` — network isolation surface; unconnected discovery and topology-disclosure risks documented in §9 and N-14
- `java.lang.Module.addOpens()` / `java.lang.Module.addExports()` — runtime module mutation APIs; `RuntimePermission("mutateModuleTopology")` gate and interaction with `LoadClassPermission` documented in §7, §10, and N-15
- `java.lang.Module.getDescriptor()` / `java.lang.Module.getLayer()` — runtime module inspection APIs; `RuntimePermission("readModuleTopology")` gate documented in §11
- `java.lang.ModuleLayer.modules()` / `java.lang.ModuleLayer.findModule()` — layer-level module enumeration and lookup; `RuntimePermission("readModuleTopology")` gate documented in §11
- `java.lang.module.Configuration.modules()` — resolved-module graph access; `RuntimePermission("readModuleTopology")` gate documented in §11
- `java.lang.module.ModuleReference.descriptor()` — module-reference descriptor access (used by `ModuleFinder`); `RuntimePermission("readModuleTopology")` gate documented in §11
- `sun.security.util.SecurityConstants.READ_MODULE_TOPOLOGY` — shared constant used across all `readModuleTopology` enforcement points
- `java.lang.foreign.MemorySegment` / `java.lang.foreign.Arena` — FFM capability transfer; full gap analysis of gated and ungated entry points in §8; `reinterpret()` and all four arena creation methods now gated (commit b62577c); `MemorySegment.ofAddress()` and linker `downcallHandle()`/`upcallStub()` remain `ensureNativeAccess`-only (N-17); delegation/confused-deputy risks in §8.4; module-open bypass in §8.5; completed implementations and remaining work in §8.8

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

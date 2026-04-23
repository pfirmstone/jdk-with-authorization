# Dirty Chai Security Analysis

**Date:** 2026-04-22  
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

| ID | Residual risk | Root cause | Mitigation |
|---|---|---|---|
| 1 | Finite stack scan depth (`limit(50)`) | Bounded scan can miss deep malicious frames | Keep checks near entry points; fail secure on detection within scanned depth; treat out-of-range evasion as bounded residual |
| 2 | Generated-class detection is heuristic | Name patterns are probabilistic (false +/−) | Keep layered caller/stack/CodeSource/policy checks |
| 3 | Trusted-list and exemption governance | `trustedSMClass()` / ClassLoader exemptions are trust boundaries | Keep lists minimal; require explicit security review for additions |
| 4 | Policy quality remains critical | Over-broad grants negate hardening | Enforce least privilege with audited policy generation/review |
| 5 | Documentation drift (resolved) | Prior wording drifted from implementation | Keep docs/Javadoc synced with `limit(50)`; no open drift known |
| 6 | Confused-deputy in trusted paths (N-8, N-10; consolidated) | Reflection/MethodHandle and `<clinit>`/bootstrap can reach trusted code that uses unrestricted `doPrivileged` | Disallow unrestricted `doPrivileged` on security-sensitive trusted paths; keep stack-intersection guard |
| 7 | Finalizer/Cleaner context escape (N-9) | Finalizer/Cleaner threads run `neverPrivileged`/innocuous by default, but creator-thread limited `AccessControlContext` is not propagated to callbacks | Avoid sensitive finalizer/cleaner work; prefer explicit `close()` and process isolation |
| 8 | Runtime attach still policy/OS dependent (N-11) | Attach is permission-gated, but over-grants, inactive SM, or OS compromise remain | Keep attach grants narrow; use `-XX:+DisableAttachMechanism` where feasible |
| 9 | Principal scope ambiguity (N-12) | Class+name grants can collide across realms; trusted-service mutation can abuse shared `Subject` | Use realm-qualified canonical principal identity; consider gating principal-set mutation |
| 10 | Coarse network permission granularity (N-14) | `SocketPermission` lacks granular distinction across network operation types and scope boundaries | Avoid wildcard network grants; publish hardened grant templates |
| 11 | Module/dynamic-define residuals (N-15) | Runtime topology mutation is gated, but startup flags, `Lookup.defineClass()`, and export cycles can still expose access paths | Treat startup flags as trust-boundary controls; tightly review module exports and dynamic class-definition exposure |

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
- **`Lookup.in(otherClass)` context changes:** still gated by `SecurityManager.checkPackageAccess()` during lookup construction.
- **`MethodHandle` adapters (`asType`, `bindTo`, `asSpreader`):** wrappers do not remove calling-code frames from the live stack; no new bypass is introduced.
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

### Finalizer and Cleaner Execution Model

- **Finalizer:** Objects with non-trivial `finalize()` are queued and processed
  by the JVM `Finalizer` daemon thread.
- **Finalizer thread context:** Created at boot via
  `AccessController.doPrivileged(..., AccessControlContext.neverPrivileged())`,
  so callback execution is never-privileged.
- **Cleaner:** `java.lang.ref.Cleaner` uses an `InnocuousThread` daemon
  (unprivileged) to run registered `Runnable` cleanup callbacks.
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

### Policy Decision

| Scenario | In-Process Guard (DirtyChai) | Process Isolation Required? |
|----------|------------------------------|-----------------------------|
| Untrusted finalizer/callback calls native method | Blocked by stack intersection (untrusted PD is on-stack) | No |
| Trusted finalizer/callback calls native method | Allowed only if policy grants `NativeInvocationPermission`; daemon thread itself is unprivileged | No (intended) |
| Trusted callback bypasses creator's limited context | **Not blocked** — limited creator ACC is not part of class policy grants | **Yes — process isolation required** |
| Attacker triggers GC of trusted object with sensitive callback | Executes if trusted class grant allows it | Mitigate by avoiding sensitive finalizer/cleaner operations |

### Guidance for Trusted Library Authors

For trusted classes whose finalizers/cleaner callbacks perform sensitive
operations (native, file, network):

1. **Prefer `Cleaner` over `finalize()`** for modern, more predictable cleanup.
2. **Do not encode application security constraints in callbacks;** enforce them
   at construction/use time or via explicit `close()` / `release()`.
3. **If privileged callback work is unavoidable, keep it minimal and explicit**
   (narrow `doPrivileged` scope, documented justification).
4. **Treat process isolation as the primary containment backstop** for context
   escape scenarios.

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

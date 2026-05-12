# Dirty Chai Security Model

- **Version:** 2.2
- **Date:** 2026-05-12
- **Last Reviewed:** 2026-05-12
- **Project:** Dirty Chai
- **Repository:** https://github.com/pfirmstone/DirtyChai

---

## 1) Purpose and Scope

Dirty Chai extends OpenJDK authorization behavior to enforce policy-based least privilege with stronger controls around class loading, caller validation, and privilege boundaries.
It also re-exports JGDMS compatibility contracts in `org.apache.river.api.security` (`ScalableNestedPolicy`, `PermissionGrant`, `PermissionGrantBuilder`) from `java.base` so existing JGDMS applications can run without recompilation.

This document covers the active model implemented in:

- `java.lang.System`
- `java.security.AccessController`
- `org.apache.river.api.security.*` (JGDMS compatibility contracts)
- `au.zeus.jdk.authorization.policy.ConcurrentPolicyFile`
- `au.zeus.jdk.authorization.sm.CombinerSecurityManager`
- `au.zeus.jdk.authorization.guards.*`

---

## 2) Quick Start (Developer Workflow)

Use this path first, then return to the deeper sections below.

1. **Audit in staging by setting `-Djava.security.manager=polpAudit`** to generate policy grants from real permission checks:

   ```bash
   java -Djava.security.manager=polpAudit \
        -DpolpAudit.path.properties=/path/to/audit.properties \
        -jar your-app.jar
   ```

2. **Review generated policy** and narrow broad grants (`AllPermission`, wide file/socket wildcards).
3. **Deploy in production** with strict policy:

   ```bash
   java -Djava.security.manager=default \
        -Djava.security.policy==/path/to/app.policy \
        -jar your-app.jar
   ```

4. **Use Subject-aware execution where policy requires principals**:
   - Wrap entrypoints in `Subject.callAs(...)` / `Subject.doAs(...)`.
   - Use `Thread.Builder` / `ThreadFactory` inside that scope for consistent Subject-aware context inheritance.
   - Create executors using those factories within the same scope so worker threads inherit the intended context baseline.

### Why `polpAudit` first?

Manual policy authoring is error-prone in real systems. `polpAudit` activates `SecurityPolicyWriter` audit mode, observes actual runtime checks, and incrementally writes required grants, giving a practical least-privilege baseline before human tightening. For the full audit-review-deploy cycle, see section 14 ("Recommended Deployment Pattern").

---

## 3) Simple Mental Model

1. **Who is calling?** (active `Subject` scope from `Subject.callAs(...)`, plus caller context)
2. **What code is running?** (`CodeSource`, signer, module/path)
3. **What does policy grant?** (`ConcurrentPolicyFile` matching + permission implication)
4. **Does execution stay bounded?** (`AccessController` context boundaries, fail-secure on mismatch)

If any required condition does not match, the operation is denied.

---

## 4) Core Security Guarantees

1. **Fail-secure defaults**: validation failures deny access (exception or unprivileged state).
2. **Least privilege**: permissions must be explicitly granted by policy.
3. **No trust transfer**: dependencies are evaluated independently.
4. **Policy-driven principal enforcement**: principal checks apply when grants include `principal` clauses.
5. **Caller-sensitive privilege boundaries**: privileged APIs retain caller-sensitive behavior.
6. **URI-validated code source matching**: policy matching relies on RFC 3986 URI handling.

---

## 5) High-Level Architecture

1. Application invokes security-sensitive operation.
2. `SecurityManager.checkPermission(...)` delegates to policy evaluation.
3. `AccessController` computes effective context (stack + inherited + explicit context, plus active scoped user subjects when present).
4. `ConcurrentPolicyFile` resolves grants by code source, signer, principal, and permission implication.
5. Permission decision is enforced (allow/deny).

---

## 5.1) Compact Permission-Check Call-Flow Diagram

### Guard entry points → `CombinerSecurityManager`

```
ObjectInputStream.readOrdinaryObject()
  → new SerialObjectPermission(className).checkGuard(null)

ClassLoader.findNative() / SymbolLookup / SystemLookup
  → new NativeInvocationPermission(libName).checkGuard(null)

Arena.global()
  → new NativeMemoryPermission("global-arena").checkGuard(null)

AbstractMemorySegmentImpl.reinterpretInternal()
  → new NativeMemoryPermission("reinterpret-memory-segment").checkGuard(null)

SecureClassLoader.defineClass()
  → LoadClassPermission.LOAD_CLASS_ALLOW.checkGuard(pd)

ThreadBuilders.PlatformThreadBuilder.unstarted/factory
  → RuntimePermission("createPlatformThread").checkGuard(null)

ThreadBuilders.VirtualThreadBuilder.unstarted/factory
  → RuntimePermission("createVirtualThread").checkGuard(null)

Module.addExports() / Module.addOpens()
  → new RuntimePermission("mutateModuleTopology") → sm.checkPermission(...)

  all paths → Permission.checkGuard(…) → sm.checkPermission(perm)
```

### `CombinerSecurityManager.checkPermission`

```
CombinerSecurityManager.checkPermission(perm)
  │
  ├─ self-bypass: SMPrivilegedContext / SMConstructorContext? → return
  │
  ├─ checked cache hit: (executionContext, perm) already verified? → return
  │       key: ConcurrentHashMap<ACC, ConcurrentSkipListSet<Permission>>
  │       TTL: 20 s; cleared on policy.refresh()
  │
  ├─ contextCache hit: delegate ACC cached? → use cached delegate ACC
  │   miss: DelegateDomainCombiner builds optimized delegate ACC, stores it
  │       key: ConcurrentHashMap<ACC, delegate ACC>; TTL: 60 s
  │
  └─ delegateContext.checkPermission(perm)
         └─ DelegateProtectionDomain.implies(perm) for each domain
                │
                ├─ < 4 domains → sequential
                └─ ≥ 4 domains → parallel (VirtualThreadPerTaskExecutor)
```

### `AccessControlContext` / stack walk

```
AccessController.getStackAccessControlContext()  [native]
  → intersects ProtectionDomain of every frame on call stack
  → stops at doPrivileged() boundary (privilege elevation point)
  → returns effective AccessControlContext

AccessController.getContext()
  → getStackAccessControlContext()
  → optimize()
  → SubjectAccess.SCOPED.get()
      → for each scoped Subject that is not a WorkerSubject:
           SubjectDomainCombiner.combine(acc.getContext(), acc.getContext())
           also combine privilegedContext when present
  → return effective AccessControlContext

AccessControlContext.checkPermission(perm)
  → for each domain in context: policy.implies(domain, perm)
  → deny if any domain lacks the permission
```

### Limited-privilege `doPrivileged(..., perms)` / `doPrivilegedWithCombiner(..., perms)`

```
AccessController.doPrivileged(action, context, perms)
  → Reflection.getCallerClass()
  → getResource(caller)
      → named module? construct jrt:/<module>/<class> CodeSource
      → non-module code? use callerLoader.getResource(clazz.getName())
      → URI construction failure? return null CodeSource (fail-secure)
  → new DomainIdentity(codeSource, perms, null, null)
  → intersect with supplied AccessControlContext
  → execute privileged action with limited scope
```

### `ConcurrentPolicyFile.implies`

```
ConcurrentPolicyFile.implies(ProtectionDomain pd, Permission perm)
  │
  ├─ volatile read: PermissionGrant[] grantRefCopy = grantArray
  │     (single memory fence; all subsequent work is thread-local)
  │
  ├─ privileged grants first (AllPermission early-exit for infrastructure code)
  │
  ├─ static domain permissions (pd.getPermissions())
  │
  └─ for each PermissionGrant:
         ├─ CodeSource match? (RFC 3986 URI string compare, no DNS)
         │     via Uri.java — normalized at parse time
         ├─ Principal match? (Subject principal class + name exact match)
         └─ grant.getPermissions().implies(perm)?
                └─ Permission.implies() per permission type
                      (SocketPermission, FilePermission, BasicPermission, …)

  no match → deny (fail-secure default)
```

### `System.setSecurityManager` validation flow

```
System.setSecurityManager(sm)
  │
  ├─ sm == null → IllegalArgumentException (always)
  │
  ├─ trustedSMClass(sm)?    [exact Class.equals(), not instanceof]
  │     SecurityManager.class
  │     CombinerSecurityManager.class
  │     PolicyOnlySecurityManager.class
  │
  │  YES (trusted) ──────────────────────────────────────────────►
  │    → install SM (no stack inspection; policy governs it)
  │
  └─ NO (custom/untrusted) ──────────────────────────────────────►
       Layer 1 (@CallerSensitive)
         Reflection.getCallerClass() → null caller → SecurityException
        Layer 2 (StackWalker, limit 50 frames)
          rejects: java.lang.reflect.* / sun.reflect.* frames,
                   including java.lang.reflect.AccessibleObject.setAccessible
                   sun.misc.Unsafe, jdk.internal.misc.Unsafe
                   non-whitelisted java.lang.invoke.* runtime frames
                   $$Lambda$, $Proxy, GeneratedMethodAccessor*
       Layer 3 (ProtectionDomain)
         caller.getProtectionDomain() == null → SecurityException
       Layer 4 (generated/synthetic caller name check)
         isGeneratedClassName(caller.getName()) → SecurityException
       → install SM if all layers pass
```

---

## 6) SecurityManager Installation Model (`System.setSecurityManager`)

Dirty Chai uses **conditional validation** when installing a SecurityManager.

### Trusted implementations (exact class match)

`trustedSMClass(sm)` trusts only:

- `java.lang.SecurityManager`
- `au.zeus.jdk.authorization.sm.CombinerSecurityManager`
- `au.zeus.jdk.authorization.sm.PolicyOnlySecurityManager`

For these classes, Dirty Chai applies the trusted path and avoids full custom-stack hardening.

### Custom implementations (all other classes)

For non-trusted classes, Dirty Chai applies layered checks before installation:

1. Direct caller check (`@CallerSensitive` + caller lookup)
2. Stack inspection via `StackWalker` (reflection/method-handle/generated-frame detection, including `AccessibleObject.setAccessible`)
3. Caller `ProtectionDomain` validation
4. Generated/synthetic caller rejection

If any layer fails, installation is blocked with `SecurityException`.

### Important operational note

`SecurityPolicyWriter` is intentionally **not** in the trusted whitelist and is for audit/staging workflows, not production enforcement.

---

## 7) AccessController and Privilege Boundaries

Dirty Chai keeps `AccessController` and `doPrivileged` semantics active for authorization use.

- `doPrivileged(...)` establishes bounded privilege elevation.
- `doPrivilegedWithCombiner(...)` preserves combiner/domain behavior.
- Effective permissions are constrained by the active `AccessControlContext` and policy grants.

Security depends on minimizing privileged blocks and scoping them to the smallest operation necessary.

### `AccessController.getContext()` scoped-subject injection

`AccessController.getContext()` no longer returns only a stack/intersection snapshot. After optimizing the current stack context, it reads the active scoped subject array from `SubjectAccess.SCOPED.get()` and injects each non-`WorkerSubject` into the returned `AccessControlContext` with a `SubjectDomainCombiner`.

This means `Subject.callAs(...)` participates in authorization through `ScopedValue`-backed subject injection at every `getContext()` call, not only at a `doPrivileged` boundary. If a privileged context is present, the same injection is applied to that nested privileged context before the final `AccessControlContext` is returned.

### Limited-privilege `doPrivileged(..., context, Permission...)`

For the limited-privilege overloads of `doPrivileged(...)` and `doPrivilegedWithCombiner(...)`, Dirty Chai does not reuse the caller's existing `ProtectionDomain` directly. Instead it builds a `DomainIdentity` from the caller class and the requested permissions.

For named-module callers, `AccessController.getResource(Class<?>)` constructs a module-aware `CodeSource` URI of the form `jrt:/<module>/<class>`. For non-module code, it falls back to the caller class loader's resource URL. Policy grants that are meant to match these limited-privilege blocks therefore need to match the `jrt:/...` `CodeSource` for named-module callers; grants written only against the caller's original `file:` or `http:` location will not match this `DomainIdentity`.

If `getResource(Class<?>)` cannot construct the URI because of `MalformedURLException` or `URISyntaxException`, it returns `null` so the synthetic `DomainIdentity` cannot match any grant.

---

## 8) Policy Model (`ConcurrentPolicyFile`)

Policy decisions are computed from:

- **CodeSource** (location/signer)
- **Principals** (when grant clauses require them)
- **Permission implication rules**

### Default posture

- No matching grant => denied.
- Invalid or unmatched inputs do not gain privileges.

### Principal semantics

- Grants **without** principal clauses can apply without authenticated Subject identity.
- Grants **with** principal clauses require matching Subject principals.

This makes principal enforcement configurable by policy rather than globally forced.

---

## 9) Class Loading and Authorization

Dirty Chai introduces authorization-aware class loading controls (including `LoadClassPermission`) to reduce unauthorized code execution risk.

Security posture assumes:

- class loading is policy-controlled,
- code source and signer identity can be policy-constrained,
- ungranted code paths fail closed.

---

## 10) Virtual Threads and Subject Context

Dirty Chai preserves authorization behavior with virtual threads by carrying effective context through standard Java security context mechanisms, including `ScopedValue`-backed subject injection in `AccessController.getContext()`.

`Subject.callAs(...)` and `Subject.doAs(...)` remain available and participate in principal-aware authorization flows where policy requires principals.

### 10.1) UserSubject, WorkerSubject, and `callAs(...)`

- `UserSubject` represents human/client identity and can be bound with `Subject.callAs(...)`.
- `WorkerSubject` represents service/process identity and is ambient; `Subject.callAs(Subject, Callable)` rejects a `WorkerSubject` with `IllegalArgumentException`.
- The multi-subject overload `Subject.callAs(Callable<T>, UserSubject...)` binds zero or more `UserSubject` instances simultaneously. `Subject.current()` returns `subject[0]` when multiple subjects are bound.
- `WorkerSubject` is excluded from this overload by the parameter type and is also skipped by `AccessController.getContext()` when scoped subjects are injected into an `AccessControlContext`.

### 10.2) `callAs()` vs `doAs()` propagation model

- `Subject.callAs(...)` binds subjects in a `ScopedValue`. Any code path that later calls `AccessController.getContext()` inside that scope receives an `AccessControlContext` with those scoped user subjects injected automatically.
- `Subject.doAs(...)` follows the older model: it snapshots the current `AccessControlContext`, associates the subject with a `SubjectDomainCombiner`, and establishes that subject-bearing context at the `doPrivileged` boundary.
- The two APIs therefore no longer have identical propagation semantics. `callAs()` is ambient within the lexical scope through `getContext()`, while `doAs()` remains tied to the snapshotted ACC / privileged-boundary path.

### 10.3) Thread builders inside `callAs(...)`

`Thread.Builder` and builder-produced `ThreadFactory` instances created inside `Subject.callAs(...)` automatically capture the active scoped user subject because the builder `unstarted()` and `factory()` paths call `AccessController.getContext()` at creation time. A separate `doAs()` wrapper is not required to carry the `callAs()` subject into the inherited `AccessControlContext` captured by those thread-building APIs.

---

## 11) Thread Creation Security Semantics (Detailed)

### 11.1 Runtime permissions enforced at thread-creation entry points

When a SecurityManager is installed, Dirty Chai enforces explicit runtime permissions before creating threads:

- **Platform threads:** `RuntimePermission("createPlatformThread")`
- **Virtual threads:** `RuntimePermission("createVirtualThread")`

These checks are applied in builder paths (`ThreadBuilders`) and in public platform-thread constructor paths (`Thread`), so both modern and traditional creation APIs are guarded.

### 11.2 Builder methods vs traditional constructors

The implementation distinguishes context capture behavior:

- **`Thread.ofPlatform()` / `Thread.ofVirtual()` builders** capture an `AccessControlContext` at builder `unstarted()` / `factory()` creation points and propagate that captured context to created threads/factories.
- **Inside `Subject.callAs(...)`**, that captured context includes the active scoped `UserSubject` values because the builders call `AccessController.getContext()`.
- **Public platform-thread constructors** also default to `AccessController.getContext()` when no explicit inherited `AccessControlContext` is supplied, so constructor-created platform threads capture the active scoped subject at creation time too.
- **Inside `Subject.doAs(...)`**, propagation still depends on the older subject-bearing ACC snapshot established at the `doPrivileged` boundary.

In this codebase, the builder path remains the explicit mechanism for thread-factory workflows, but both builders and public platform-thread constructors rely on `AccessController.getContext()` capture for `callAs()`-scoped user subjects.

### 11.3 Platform thread builder behavior

For platform builders:

1. Permission check for `createPlatformThread`
2. Capture caller context with `AccessController.getContext()`
3. If inside `Subject.callAs(...)`, inject active scoped non-`WorkerSubject` identities into the captured ACC
4. Create thread/factory with captured inherited security context
5. Apply group/priority/daemon/UEH builder options

### 11.4 Virtual thread builder behavior

For virtual builders:

1. Permission check for `createVirtualThread`
2. Capture caller context with `AccessController.getContext()`
3. If inside `Subject.callAs(...)`, inject active scoped non-`WorkerSubject` identities into the captured ACC
4. Create virtual thread/factory with captured inherited security context
5. Preserve configured characteristics and exception handler

### 11.5 Security implication

For Subject-aware authorization, prefer `Thread.Builder` / builder-produced `ThreadFactory` created inside the intended Subject scope. Inside `Subject.callAs(...)`, builder capture automatically includes the active scoped user subject through `AccessController.getContext()`. `Subject.doAs(...)` remains available, but it follows the older ACC-snapshot path rather than the newer scoped-subject injection path.

### 11.6 Executors, ThreadFactory, Thread, and AccessControlContext

This section mirrors the thread-creation analysis for adjacent APIs that define runtime execution boundaries.

#### 11.6.1 `Executors`

- `Executors.newVirtualThreadPerTaskExecutor()` delegates to `Thread.ofVirtual().factory()`, so security context behavior follows the capture semantics of a virtual-thread builder-produced factory.
- `Executors.defaultThreadFactory()` returns a platform builder-based factory (`Thread.ofPlatform()...factory()`), so creation-time context capture is aligned with builder flows.
- `Executors.privilegedThreadFactory()` explicitly captures `AccessControlContext` and context class loader at factory creation, then runs work under `AccessController.doPrivileged(..., capturedContext)`.

**Operational guidance:** construct executor services in the intended Subject scope (`Subject.callAs(...)` / `Subject.doAs(...)`) when policy grants require principal-aware execution.

#### 11.6.2 `ThreadFactory`

- `Thread.Builder.factory()` checks `RuntimePermission("createPlatformThread")` or `RuntimePermission("createVirtualThread")` at factory creation.
- Builder factories store captured `AccessControlContext` and apply it to each `newThread(...)` call, yielding consistent inherited security context across produced threads.
- This is stronger and more predictable for Subject propagation than ad-hoc thread construction in mixed caller contexts.

#### 11.6.3 `Thread` (constructors and builders)

- Public platform-thread constructors perform platform-thread permission/checkAccess flow and set inherited context from either an explicit `AccessControlContext` parameter or `AccessController.getContext()`, so `Subject.callAs(...)`-scoped user subjects are captured there as well.
- `Thread.ofPlatform()` / `Thread.ofVirtual()` builder paths document and implement explicit inherited-context capture behavior used by both `unstarted/start` and `factory`.
- In this codebase, builder flows are the recommended mechanism when consistent Subject-bearing context inheritance is required.

#### 11.6.4 `AccessControlContext` and `AccessController.getContext()`

- `AccessController.getContext()` snapshots current effective context (including inherited context and limited-privilege scope), then injects any active scoped non-`WorkerSubject` identities from `Subject.callAs(...)` before returning the optimized `AccessControlContext`.
- `AccessControlContext.checkPermission(...)` evaluates against the encapsulated context (not merely the current thread at check site), enabling safe handoff to worker execution paths.
- Dirty Chai retains authorization-focused ACC behavior and hardens context construction so unauthorized context creation does not result in privilege escalation.

---

## 12) Threats Addressed

- Reflection/proxy/generated-code attempts to bypass SecurityManager installation controls
- `Method.invoke()` and `MethodHandle.invoke*()` attempts to install a custom
  `SecurityManager` (blocked by `validateCallerStackWithStackWalker()`)
- Reflective or MethodHandle calls that traverse a trusted native wrapper without
  `doPrivileged` (untrusted caller `ProtectionDomain` remains on stack)
- Untrusted finalizer or `Cleaner` callbacks attempting sensitive operations (untrusted
  class `ProtectionDomain` is present on finalizer/Cleaner thread stack; finalizer
  threads now run with `AccessControlContext.neverPrivileged()`, and `Cleaner`
  callbacks run on `InnocuousThread` with no permissions)
- Untrusted code triggering `<clinit>`, `invokedynamic` bootstrap methods, or
  `CONSTANT_Dynamic` bootstrap methods of trusted classes (untrusted PD on stack)
- Privilege escalation via overly broad or inherited permission assumptions
- Policy bypass through malformed/ambiguous code source handling
- Unauthorized execution through missing grant constraints
- Ordinary-object deserialization via `ObjectInputStream.readOrdinaryObject()` is
  guarded by `SerialObjectPermission` before object instantiation
- Proxy-class descriptor deserialization via `ObjectInputStream.readProxyDesc()` is
  not covered by `SerialObjectPermission`; proxy-deserialization gadget chains are
  therefore not blocked by the current guard placement (see G-3 in section 13)

---

## 13) Non-Goals / Limitations

- Dirty Chai is an authorization and policy-enforcement model, not a complete malware sandbox by itself.
- Misconfigured policy can still over-grant privileges.
- Operational security still requires key management, signer governance, secure build pipelines, and review discipline.
- **Trusted-code confused-deputy:** Dirty Chai cannot prevent a trusted class from using
  unrestricted `AccessController.doPrivileged(...)` on paths reachable from untrusted code.
  This is a design obligation for trusted library authors (see `CONTRIBUTING.md` and
  `PROCESS_ISOLATION.md`, "Task N-6 / Confused-Deputy Guidance").
- **Finalizer/Cleaner context escape:** The creator thread's `AccessControlContext` is not
  propagated to finalizer or `Cleaner` threads. Finalizer threads are now unprivileged,
  reducing the residual gap surface, but trusted-object context loss remains. If a trusted
  object's finalization behavior must be restricted by the creator's context, that
  constraint must be enforced at construction time or through an explicit `close()`
  pattern.  Process isolation is the mitigation for this residual gap (see
  `PROCESS_ISOLATION.md`, N-9 analysis).
- **G-3 confirmed — proxy deserialization gap:** `SerialObjectPermission` currently guards
  `ObjectInputStream.readOrdinaryObject()` but not `readProxyDesc()`. Streams that reach
  object creation through `TC_PROXYCLASSDESC` therefore do not hit the current
  `SerialObjectPermission` guard placement.

---

## 14) Recommended Deployment Pattern

1. **Stage/Audit** with `polpAudit` (`SecurityPolicyWriter`) to discover required permissions.
2. Review and narrow grants (remove over-broad file/socket/all-permission entries).
3. **Production** with strict policy and SecurityManager enabled.
4. Keep policy and signer trust material under change control and audit.

---

## 15) Security Invariants (Must Hold)

1. Trusted SecurityManager checks use exact class identity, not subclass trust.
2. Custom SecurityManager installation requires all validation layers.
3. Privileged execution must remain caller-sensitive and context-bounded.
4. Policy evaluation must remain deny-by-default.
5. Validation failures must remain fail-secure.
6. `WorkerSubject` is never injected via scoped-subject handling into an `AccessControlContext`; process identity remains ambient via `ProtectionDomain`.

---

## 16) Related Documents

- `SECURITY_ANALYSIS.md` (detailed findings and historical fixes)
- `STACK_VALIDATION_ANALYSIS.md` (stack-validation trade-offs)
- `VULNERABILITIES_ADDRESSED.md` (resolved issues)
- `SECURITY.md` (security policy and reporting)
- `PROCESS_ISOLATION.md` (reflection/MethodHandle N-8, finalizer/Cleaner N-9, class-init N-10, consolidated lifecycle analysis with attach gating N-11, test plan N-12)

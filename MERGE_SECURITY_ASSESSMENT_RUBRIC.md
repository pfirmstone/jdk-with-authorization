# Merge Security-Impact Assessment Rubric (Phase 2)

> **Status: ACTIVE — the operative rubric for [`AI_POLICY.md`](AI_POLICY.md) §8, Phase 2.**
> Phase 2 was **adopted 2026-07-31** (decision 1a), so this rubric governs an activity that is now
> explicitly in force rather than merely permitted-in-principle.
> It operationalizes the *security-impact assessment* of an upstream merge: the static review that
> finds where SM-free upstream code, merged into DirtyChai, is **missing a guard** or **missing a
> `doPrivileged` block** under DirtyChai's restored authorization model.
>
> It is **pure analysis** — it produces a punch-list, never edits code — so it is usable by a human or
> an agent, and its status is unaffected by whether the Zone-D partition is ever adopted. Authoring
> the fixes is Phase 3, which is **human-authored**: Zone D was **not** adopted, so the
> AI-draft-behind-gate variant described in the policy is not available today.
>
> **Authoritative trust model:** [`SECURITY_MODEL.md`](SECURITY_MODEL.md). Where this rubric and the
> model disagree, the model wins and this rubric is the bug. Section refs below (§5.1, §11, §12, §13,
> §15) are to `SECURITY_MODEL.md`. AI-authored under the Repository Documentation Exception; if kept,
> add to the exemption list.

---

## 1. What the assessment produces

Input: the diff of **one upstream build tag** (`jdk-NN+B` → the next tag) — the natural unit of merge:
each tag is a CI-validated, bounded delta, and merging tag-by-tag keeps a proper advancing merge base
(skipping ahead to a far commit manufactures spurious context-drift conflicts). Output: a
**punch-list** — zero or more finding records (schema in §8), scoped to that tag. Each finding answers
*one* of three questions about merged code:

- **C1 — Missing guard.** A security-sensitive operation now runs **unmediated** (no permission
  check). Hole.
- **C2 — Missing `doPrivileged`.** A legitimate operation that trusted code must perform will be
  **wrongly denied** when an under-privileged frame sits deeper on the stack. Breakage.
- **C2b — Over-broad `doPrivileged`.** A new or widened privilege-elevation on an untrusted-reachable
  path — the trusted-code confused-deputy (§13). Hole.
- **C3 — Behavioural delta on a §5 surface / invariant threat.** Merged code changes a
  security-relevant decision or could weaken a §15 invariant.
- **R — Removed/weakened mediation (deletions).** Upstream deletes a permission check or
  `doPrivileged`, or changes a permission/AC class DirtyChai builds on. Lives in the `-` lines, not the
  `+` lines; the **silent auto-merge** sub-case is the highest-priority finding (§4c). Hole.

The assessment **never** modifies code. Every finding is reported to the named human owner (policy §5).

---

## 2. The core distinction: guard vs `doPrivileged` are duals

This is the whole skill, so state it plainly. For any operation in the merged code, ask:

| Question | If yes → | Why |
|---|---|---|
| *If a less-privileged frame is on the stack, should this be denied?* | **C1 — add a guard** | the op is an authority-bearing action; it must be mediated |
| *Must this still succeed because trusted code performs it as an internal mechanic, regardless of the caller?* | **C2 — add `doPrivileged`** | the op is plumbing, not an authority decision; stop the stack walk here |

A guard says *"check the stack."* A `doPrivileged` says *"stop checking the stack at this line."*
Many merges need **both** on the same feature: guard the public API that decides authority; wrap the
narrow internal mechanic it calls in a (limited-privilege) `doPrivileged`. Getting the *pair* right —
and the boundary between them — is the assessment.

**Placement rule (from the design model, consistent with §13):** authority decisions stay on the live
stack; `doPrivileged` wraps only the smallest local mechanic. Prefer the limited-privilege form
`doPrivileged(action, context, perms)` granting the *exact* permission over full elevation. Never
`doPrivileged` around anything that constitutes deciding authority on a caller's behalf.

---

## 3. Catalog A — sensitive operations that need a **guard** (C1)

These are the operations DirtyChai mediates. SM-free upstream performs many of them with **no** check
because OpenJDK deleted the Security Manager. For each, the trigger is what to look for in the diff;
the guard is the DirtyChai class + target; placement is where the check belongs (the method boundary —
**all** call sites, never one site: FM-5).

### 3a. DirtyChai-specific guards (the wired entry points — §5.1)

| Operation (trigger in the diff) | Guard (`au.zeus.jdk.authorization.guards.*`) | Target / name | Canonical placement (§5.1) |
|---|---|---|---|
| Ordinary-object deserialization: `ObjectInputStream`, custom `readObject`/`readExternal`, new OIS subclass / `resolveClass` override, any **new path reaching object creation** | `SerialObjectPermission(className)` | deserialized class name | `ObjectInputStream.readOrdinaryObject()` |
| Native library load/invoke: `System.loadLibrary`/`load`, `NativeLibraries.find*`, `SymbolLookup.libraryLookup`, `SystemLookup`, `Linker…downcallHandle` | `NativeInvocationPermission(libName)` | native library name | `ClassLoader.findNative()` / `SymbolLookup` / `SystemLookup` |
| Obtain native linker / make down/upcall handles | `NativeMemoryPermission("native-linker")` | `native-linker` | `Linker.nativeLinker()` path |
| Off-heap arena allocation: `Arena.global()` / `ofShared()` / `ofConfined()` / `ofAuto()` | `NativeMemoryPermission(...)` | `global-arena` / `shared-arena` / `confined-arena` / `auto-arena` | `Arena.global()` etc. |
| `MemorySegment.reinterpret()` (resize/rebind) | `NativeMemoryPermission("reinterpret-memory-segment")` | `reinterpret-memory-segment` | `AbstractMemorySegmentImpl.reinterpretInternal()` |
| `MemorySegment.ofAddress(long)` — segment from raw address | `NativeMemoryPermission("address-memory-segment")` | `address-memory-segment` | address-from-long path |
| Class definition / loading: `defineClass`, custom `ClassLoader`, `Lookup.defineClass` / `defineHiddenClass` | `LoadClassPermission` (`LOAD_CLASS_ALLOW`) / `DefineClassPermission` | — / class | `SecureClassLoader.defineClass()` (invariant 9: pdcache only after checks + digest) |
| Thread creation: `new Thread(...)`, `Thread.ofPlatform()` / `ofVirtual()`, `ThreadFactory`, `Executors.*` | `RuntimePermission("createPlatformThread")` / `("createVirtualThread")` | — | `ThreadBuilders.*` + public `Thread` ctors (§11.1) |
| Module topology mutation: `Module.addExports` / `addOpens` / `addReads` / `addUses` | `RuntimePermission("mutateModuleTopology")` | — | `Module.addExports()` / `addOpens()` |

> **Thread creation also has a Subject-context concern (§11):** the builder/constructor must capture
> the ACC via `AccessController.getContext()` so a `callAs(...)`-scoped `UserSubject` propagates to the
> created thread. A merge that adds a new thread-creation path without that capture is a C3 finding
> even if the permission check is present.

### 3b. Standard JDK sensitive operations (historic `checkXxx()` deleted upstream)

Upstream removed the `SecurityManager.checkXxx()` call sites for these. Under DirtyChai they must
still be mediated via policy. Flag any merged op below that is reachable from less-trusted callers:

| Operation family | Trigger patterns | Permission |
|---|---|---|
| File I/O | `Files.*`, `FileInputStream`/`FileOutputStream`, `RandomAccessFile`, `FileChannel`, `Path` open | `FilePermission` (read/write/delete/execute) |
| Process exec | `Runtime.exec`, `ProcessBuilder.start` | `FilePermission "<cmd>","execute"` |
| Sockets / net | `Socket`, `ServerSocket`, `SocketChannel`, `DatagramSocket`, `URL.openConnection`, `HttpClient`, `InetAddress` resolve | `SocketPermission` / `URLPermission` / `NetPermission` |
| System properties / env | `System.getProperty`/`setProperty`/`getProperties`, `System.getenv` | `PropertyPermission` (read/write) |
| Reflection bypass | `setAccessible(true)`, `AccessibleObject`, `Unsafe` access | `ReflectPermission("suppressAccessChecks")` |
| ClassLoader / PD access | `getClassLoader`, `createClassLoader`, `setContextClassLoader`, `getProtectionDomain`, `accessClassInPackage.*`, `accessDeclaredMembers` | `RuntimePermission(...)` |
| VM lifecycle | `System.exit`, `Runtime.halt`, shutdown hooks | `RuntimePermission("exitVM.*")` / `"shutdownHooks"` |
| Security config | `Policy.get/setPolicy`, `Security.get/setProperty`, `getDomainCombiner`, create ACC | `SecurityPermission(...)` |
| Stack inspection | `StackWalker` with class-reference option | `RuntimePermission("getStackWalkerWithClassReference")` |
| **VM control & monitoring** (usually native-backed) | `java.lang.management` / `com.sun.management` / `sun.management` MXBean ops — thread CPU-time / suspend, GC control, heap & thread dumps, diagnostic commands; thin Java wrappers over `native` methods or VM intrinsics | `ManagementPermission("control"` / `"monitor")` |

### 3c. Native-backed operations and native-code gaps

Mediation does **not** all live in Java. Some permission checks are (or should be) made before or
within **native code** (`src/**/native/**`, `src/hotspot/**`). Two consequences the Java-only scan
misses:

- **Native removals are inherently silent (Catalog R, native variant).** A check removed or changed in
  C/C++ never conflicts with DirtyChai's *Java* modifications, so it **always** auto-merges — there is
  no conflict and no Java `-` line. Scan native diffs (`*.c`/`*.cpp`/`*.h`, `JVM_*`, hotspot) for
  changed/removed checks the same way, and treat every hit as silent (S).
- **Native gaps → add a Java-side check (Catalog A, native-gap variant).** Where a native/VM operation
  is reachable from Java with no mediation — because the privileged action happens in native code and
  the SM-free model dropped the Java gate — the only practical place to re-mediate is a **Java-side
  permission check**. For JVM control/monitoring operations these are **generally
  `ManagementPermission`** (`"control"` / `"monitor"`): thread CPU-time / suspend, GC control, heap &
  thread dumps, diagnostic commands, MXBean operations in `java.lang.management` /
  `com.sun.management` / `sun.management`. The signal is a thin Java wrapper over a `native` method or
  VM intrinsic performing a control/monitor action with no guard. (This is a known maintainer pattern,
  not a hypothetical — new `ManagementPermission` checks are added to cover native gaps.)

---

## 4. Catalog B — operations that need a **`doPrivileged`** (C2)

Look for **trusted infrastructure** code (java.base, `jrt:/…`) that performs a *mechanic* requiring a
permission the eventual caller will not hold, where the operation must succeed regardless:

| Pattern in merged trusted code | Why it breaks under DirtyChai | Remediation |
|---|---|---|
| Reads a JDK-internal config / resource file (`*.properties`, `META-INF`, locale/tz data) | a deeper app/untrusted frame lacks `FilePermission` → stack intersection denies | `doPrivileged` the **read only**, limited-privilege with that one `FilePermission` |
| Opens an internal file / socket the runtime needs (logging, temp, internal endpoint) | same stack-intersection denial | limited-privilege `doPrivileged` for the specific file/socket permission |
| Reads a system property the JDK needs internally | caller lacks `PropertyPermission` | limited-privilege `doPrivileged` for that property read |
| Loads an internal class / resource via a loader | caller lacks the loader/PD permission | `doPrivileged` the narrow load |
| Captures context for later async work (`Executors.privilegedThreadFactory` style) | inherited context must be the trusted one, not the caller's | capture ACC at creation; run work under `doPrivileged(..., capturedContext)` (§11.6) |

**Default to limited-privilege.** `doPrivileged(action, context, perms)` grants only the named
permission; full `doPrivileged(action)` elevates to the trusted domain's full grant and is rarely
what the mechanic needs.

### C2b — over-broad `doPrivileged` is itself a finding

Flag every **new or widened** `doPrivileged` in the merge, especially:

- full-privilege (no `perms` argument) on a path reachable from untrusted/lower-trust callers →
  trusted-code **confused-deputy** (§13, design obligation; this rubric cannot rely on the framework
  to catch it);
- a `doPrivileged` wrapping more than the minimal mechanic (it should not span an authority decision);
- a `doPrivileged` that swallows or widens a permission set vs the pre-merge code.

---

## 4c. Catalog R — removed or weakened mediation (the SM-removal blind spot)

> **The most dangerous category in the current era, and the one an added-line scan misses.** Upstream
> OpenJDK is part-way through removing the Security Manager (JEP 411 deprecate → JEP 486 disable in
> JDK 25). The *dominant direction* of upstream change is therefore **deleting** mediation. A removal
> that lands in a file DirtyChai did not modify **auto-merges silently** — no conflict, no added line,
> nothing flags it — and quietly strips a guard, `doPrivileged`, or permission check DirtyChai relies
> on. Worse than a missing guard (Catalog A): Catalog A is at least visible in the diff's `+` lines;
> this is in the `-` lines of a *clean* merge.

**Three triggers — scan the `-` lines and the infrastructure files, not just `+`:**

| trigger | what to look for (removed / changed) | response |
|---|---|---|
| **R1 — removed permission check** | a deleted `sm.checkPermission(...)`, `.checkGuard(...)`, `checkRead/checkWrite/checkConnect/checkExec/checkAccess/checkPackageAccess`, or a deleted `new XxxPermission(...)` guard site | **re-add** the check DirtyChai requires — it was load-bearing in the fork even though SM-free upstream no longer needs it |
| **R2 — removed `doPrivileged`** | a deleted `AccessController.doPrivileged(...)` around a trusted mechanic | re-add (Catalog B logic): without it the mechanic is wrongly denied under stack intersection |
| **R3 — permission/AC class touched** | any change to `java/security/**` (`Permission`, `BasicPermission`, `Permissions`, `Policy`, `ProtectionDomain`, `AccessController`, `AccessControlContext`, `DomainCombiner`, `Guard`), `SecurityManager.java`, or `javax/security/auth/**` | re-validate DirtyChai's model — **its guards `extend BasicPermission<T>`** and the engine builds on `Policy`/`ProtectionDomain`/`AccessController`, so an upstream semantics change here propagates straight into the fork's authorization |

**Detection method (what the rest of the rubric did not cover):**

1. Scan the build delta's **deleted lines** (`-`, excluding `---`) for the precise tokens above. **Use
   tight tokens** — bare `Subject`, `Permission`, or `SecurityManager` produce false positives (e.g.
   `findSubjectCNs(cert)` is an X.509 cert subject, not `javax.security.auth.Subject`). Prefer
   qualified forms: `AccessController.doPrivileged`, `.checkPermission(`, `.checkGuard(`,
   `extends BasicPermission`, `javax.security.auth.Subject`.
2. **Classify every hit S vs C:**
   - **C (conflict-visible):** file is in DirtyChai's divergent set → the merge conflicts → a human
     already sees it. Lower priority.
   - **S (silent auto-merge):** file is *not* DirtyChai-divergent → the removal **lands with no flag**.
     **Highest priority** — this is the category's whole reason to exist; neither conflict review nor a
     `+`-line scan will surface it.
3. Treat the **R3 infrastructure-file** list as a standing per-tag check regardless of `-`-line hits.

**Timing.** The bulk of SM removal predates a jdk-27 base (JDK 24→25), so a walk *within* jdk-27 sees
few genuine removals — but a fork crossing the 24→25 boundary, or tracking upstream as it strips the
*remaining* SM scaffolding, will see many. The scan is cheap; run it every tag.

**Validated (jdk-24-ga → jdk-25-ga).** 89 files carry mediation removals — `doPrivileged` 87 lines,
`@SuppressWarnings("removal")` 80, `AccessControlContext` 60, `SecurityManager` 56, `AccessController`
48, `new XxxPermission` 31 — of which **30 are in files a fork would not have touched (silent)**. The
same scan within jdk-27 found ~0 (both candidates false positives), confirming the timing. *Token
refinement the data forced:* skip resource bundles / comments — `sun/security/util/Resources_*.java`
hold *localized permission strings* that match the tokens but are not code mediation; the genuine
silent removals (e.g. `jdk.internal.vm.ci/.../Services.java`, the Xerces XML parsers) are real.

**Retrospective sweep (one-time, to catch *past* silent misses).** Beyond the per-tag scan, compare a
pre-removal baseline (e.g. `jdk-23-ga`) against current `trunk`: for each file that lost mediation
upstream, compare the mediation-token count baseline-vs-trunk; an **unforked** file whose count
collapsed to the post-removal level inherited the removal silently and was never re-mediated. Sweep
*all* SM-removal boundaries (23→24→25→26→27), not just the current tag. Classify removed **check**
(hole-class) vs removed **`doPrivileged`** (functional/over-denial) — different remediation. *Confirmed
finding from this sweep:* JVMCI gating is **inconsistent** in trunk — `JVMCIServiceLocator` still
enforces `JVMCIPermission`, but `Services.initializeJVMCI` / `openJVMCITo` / `checkJVMCIEnabled` lost
theirs (24→25, inherited and never restored) — candidate to re-mediate.

**Full sweep result (jdk-23-ga → trunk).** Removed across 318 files: checks 148, `doPrivileged` 95, PD
264, SM/AC-infra 702. **222 forked (re-mediated) vs 86 unforked (silent-inherited)** — of the tail,
only 6 removed-check + 11 PD-loss files, mostly expected (the `ProtectionDomainCacheTable` removal
itself, the removed applet API) or false positives. Two refinements the sweep forced:
- **Tighten `check(Read|Write|…)`** — it matched VarHandle *memory bounds-check* method names
  (`X-VarHandleSegmentView.java.template`, 33 spurious hits). Qualify to `sm.check…` / `.checkPermission(`.
- **Rename-aware** — with rename detection off, a wholly-"removed" old path is usually a rename; verify
  path-follow before treating as a silent removal.

**Weight every Catalog-R / §5b finding by upstream trajectory.** A removed check/PD for a capability
upstream is *deprecating or removing* (e.g. JVMCI per its removal JEP; the removed applet API) is
**moot** — you'll inherit the deletion anyway, so don't re-mediate it. It becomes a real must-fix
**only if DirtyChai deliberately keeps that capability as divergent core** (then you maintain it, so
you mediate it). This factor sets remediation priority before any code is written.

---

## 5. Catalog C — behavioural deltas & invariant threats (C3)

Any merge that **touches a §5 security-critical surface** (`System.java`, `AccessController.java`,
`ConcurrentPolicyFile`, `CombinerSecurityManager`, SPIFFE/digest stamping in `SecureClassLoader`,
`DigestCodeSource`/`DigestGrant`, `Uri.java`, the `guards/*Permission` classes) is a C3 finding by
default — produce a behavioural diff vs both stock OpenJDK and the pre-merge fork.

**Always-check known gaps (encode these as standing checklist items):**

- **G-3 proxy-deserialization (§13):** `SerialObjectPermission` guards `readOrdinaryObject()` **not**
  `readProxyDesc()`. Any merge that adds/changes a deserialization surface → note the proxy-desc gap
  and recommend **DER-parse-only** for adversarial input; do not assume the guard covers proxy chains.
- **Finalizer / Cleaner context escape (§13):** new `finalize()` or `Cleaner` registration on a
  trusted object → creator ACC is **not** propagated; finalizer runs unprivileged / `Cleaner` on
  `InnocuousThread`. If finalization must be context-restricted, enforce at construction or via
  `close()`.
- **Reflective / MethodHandle traversal of trusted native wrappers (§12):** merged code that lets a
  reflective/MH call reach a trusted native wrapper without `doPrivileged` leaves the untrusted
  caller PD on the stack — confirm the wrapper's privilege boundary.
- **Bootstrap-method abuse (§12):** changes to `<clinit>`, `invokedynamic`, or `CONSTANT_Dynamic`
  bootstrap of trusted classes (untrusted PD may be on stack).
- **Caller-sensitivity:** any add/remove of `@CallerSensitive` or change to `Reflection.getCallerClass()`
  usage on a privileged path (HC-4).

**Invariant pass (§15).** Run the merge against the 10 invariants; any that *could* be weakened is a
finding. The ones most exposed to upstream churn:

- deny-by-default policy evaluation (4); fail-secure on validation failure (5);
- privileged execution stays caller-sensitive + context-bounded (3);
- `WorkerSubject` never injected via scoped handling; `callAs`/`doAs` reject it (6, 7);
- `DigestGrant` never implies a plain `CodeSource` (8); pdcache stored only after checks (9);
- SPIFFE injection only when booted + SM active + non-null SVID (10).

---

## 5b. ProtectionDomain-propagation inventory (the native authz-context check)

A curated set of authorization methods thread a `ProtectionDomain` (Java) / `protection_domain`
`Handle` (hotspot) through the call chain. The risk is **silent context loss**: a *new* call site uses
a PD-omitting overload or passes `null`/`Handle()`, or a method *body* is refactored to stop
propagating the PD — so the operation runs without its authorization context. The hotspot per-PD
**package-access result cache (`ProtectionDomainCacheTable`) is gone**, but the checks are **not** —
DirtyChai still performs package-access checks, now cached more efficiently at the
`CombinerSecurityManager`/ACC layer (ACC-keyed, not per-PD; §5.1). So tracing whether a given site
threads the right PD is a direct **data-flow** question at that site, no longer complicated by a
per-PD native memo. **These checks now apply only to non-module (classpath / unnamed-module) code** —
named-module access is governed by the module system — so the concern is scoped to non-module paths.

**Two per-tag checks against the inventory (both silent unless the file is DirtyChai-divergent):**
- **R-PD-1 (new use):** a new call to an inventory method that omits the PD — Java: a non-PD overload
  or `null`; hotspot: `Handle()` for `protection_domain`.
- **R-PD-2 (body change):** a change to an inventory method's body that drops, ignores, or stops
  propagating the PD.

**Inventory (verified in tree; extend as found):**

*Java (`java.base`):* `ProtectionDomain.implies(Permission)`; `Policy.implies(PD,Permission)` /
`getPermissions(PD)`; `PolicySpi.engine{Implies,GetPermissions}(PD,…)`;
`DomainCombiner.combine(PD[],PD[])`; `AccessControlContext.create(PD[],boolean)` / `new
AccessControlContext(PD[])`; `SecureClassLoader.defineClass(…,PD)` (all overloads) /
`getProtectionDomain(CodeSource,Principal[])`; `ClassLoader.defineClass(String,byte[],int,int,PD)`;
`jdk.internal.access.JavaSecurityAccess.doIntersectionPrivilege(…)`. *DirtyChai:*
`ConcurrentPolicyFile.implies(PD,Permission)` / `getPermissions(PD)` / `getPermissionGrants(PD)`;
`DomainIdentity`, `DelegateProtectionDomain`.

*hotspot native (highest risk — never conflicts with Java mods, so always silent):*
`SystemDictionary::resolve_or_fail / resolve_or_null / resolve_with_circularity_detection /
check_shared_class_super_types(…, Handle protection_domain, …)` and `find_*` PD overloads; `jvm.cpp`
`JVM_DefineClass*` → `Handle protection_domain(THREAD, JNIHandles::resolve(pd))` →
`SystemDictionary::resolve_or_fail(…, protection_domain, …)`. **Watch:** PD-omitting overloads sit
beside PD-carrying ones — a new caller picking the wrong one, or passing `Handle()`, drops the context.

> **Cache note:** the removed structure is the hotspot native **`ProtectionDomainCacheTable`** (per-PD
> package-access *result* cache). The checks themselves are **retained** in DirtyChai —
> `ClassLoader.checkPackageAccess(Class, ProtectionDomain)` builds an ACC from the PD
> (`Context.create(new ProtectionDomain[]{pd})`) and calls `sm.checkPackageAccess` under
> `doPrivileged` — now cached more efficiently by `CombinerSecurityManager` + the **ACC checked-cache**
> (ACC-keyed, 20s TTL, cleared on `policy.refresh()`; §5.1) instead of a per-PD native table. (Upstream
> dropped both the table *and* the checks — no SM; DirtyChai dropped only the table.) **Scope:
> non-module (classpath / unnamed-module) code only** — named-module access is the module system's job.
> Unrelated caches still in tree: `SecureClassLoader.pdcache` = CodeSource→PD construction
> (invariant 9); legacy `Policy.pdMapping`. The `ProtectionDomainCacheTable` mention in
> `javaClasses.cpp` is now a dead-reference comment.
>
> **Validated (jdk-24-ga → jdk-25-ga):** the boundary removed **33 native `protection_domain` + 14
> Java `ProtectionDomain`** references, concentrated exactly in this inventory —
> `hotspot/ci/ciInstanceKlass.cpp` (12), `java/lang/Class.java` (8), `systemDictionary*.cpp`,
> `prims/jvm.cpp` — all **silent** for a fork (native never conflicts with Java mods). §5b fires
> precisely where designed.
>
> **Triage refinement (verified jdk-23-ga→trunk):** most hotspot PD-drops are **not** on the live
> authz gate — they fed the removed `ProtectionDomainCacheTable`, CDS archiving (`moduleEntry`,
> `metaspaceShared`/`CDSProtectionDomain`), or JIT-time re-resolution (`ciEnv`, `method.cpp` probes), or
> are array-klass accessor consolidations. Before flagging a hotspot PD-drop, confirm it sits on the
> **load-time gate**: `Dictionary::check_package_access` (gated on SM installed) → upcall
> `ClassLoader.checkPackageAccess(cls, pd)` → `sm.checkPackageAccess`, PD sourced from
> `java_lang_Class::protection_domain` (mirror) / `InstanceKlass::protection_domain()`. In the 23→trunk
> sweep that whole chain + PD source were intact, so every non-JVMCI hotspot PD-drop was benign.

---

## 6. Decision heuristics

1. **C1 vs C2 is the dual test in §2.** When both apply, record two findings (guard the API,
   `doPrivileged` the mechanic).
2. **Narrowest everything.** Narrowest permission/target for a guard; narrowest scope + limited-privilege
   form for a `doPrivileged`.
3. **Method boundary, not one call site** (FM-5). A guard belongs where the operation is, so every
   caller is covered.
4. **`doPrivileged` is a liability, not a default** (FM-6 / §13). Adding one is sometimes required
   (C2); widening one is usually a finding (C2b).
5. **When unsure, lower the confidence, don't drop the finding.** Under-reporting a missing guard is a
   silent hole; a low-confidence "investigate" is cheap for the human owner to resolve.
6. **Scan deletions, not just additions (Catalog R).** In the SM-removal era most upstream change is
   *removal* of mediation; a `+`-line scan is blind to it. Scan `-` lines for deleted checks /
   `doPrivileged`, flag the **silent (auto-merge)** removals first, and use tight tokens (bare
   `Subject`/`Permission` match unrelated code).

---

## 7. Cross-check with `polpAudit` (dynamic ↔ static)

The rubric is *static* ("what should be mediated"). `polpAudit` / `SecurityPolicyWriter` (§14, §2) is
*dynamic* ("what permissions the workload actually requests at runtime"). Reconcile them over the
merged code's tests:

- **Rubric flags an op, polpAudit never records its permission** → either a dead/untested path (add a
  test) or the guard is not actually on the path (placement bug — high-value finding).
- **polpAudit records a permission the rubric did not flag** → a catalog gap (add the row) or a
  genuinely benign request (note it).

Neither replaces the other; a merge assessment is strongest when the static punch-list and a
polpAudit run agree.

---

## 8. Finding record schema

One row per finding in the punch-list:

| Field | Content |
|---|---|
| `id` | stable per assessment, e.g. `M<merge>-001` |
| `loc` | `file:line` in the merged code |
| `op` | the operation as it appears in the diff |
| `category` | `C1-guard` / `C2-doPriv` / `C2b-overbroad` / `C3-delta` / `R-removed` (mark `S` silent / `C` conflict) |
| `remediation` | proposed guard (class + target) **or** `doPrivileged` scope (perms + boundary) |
| `target` | narrowest permission target / name |
| `placement` | the method boundary / call sites where it belongs |
| `model_ref` | `SECURITY_MODEL.md` § (and HC-/invariant # where relevant) |
| `confidence` | high / medium / low |
| `notes` | caveats (e.g. "proxy-desc gap applies", "reachable from untrusted") |

**Escalation:** every C3 and every C2b is always escalated to the named human owner regardless of
confidence; §5-surface findings carry the full Phase-3 gate (policy §5). **Every silent (S) Catalog-R
removal is always escalated** — it has no other signal (no conflict, no `+`-line), so if the
assessment misses it, nothing else will.

---

## 9. What this rubric is NOT

- **Not a merge approval.** It surfaces security impact; a human decides.
- **Not Phase 3.** It authors nothing — the `doPrivileged` blocks and guards are written in Phase 3
  (human under (1a); AI-draft-behind-gate under (1b)).
- **Not a substitute for tests or `polpAudit`.** It complements them (§7); the property/differential
  tests in policy §5 remain mandatory for any remediation.

---

## 10. References

- [`AI_POLICY.md`](AI_POLICY.md) — §8 (the three-phase pipeline), §5 (security gate)
- [`SECURITY_MODEL.md`](SECURITY_MODEL.md) — §5.1 guard entry points, §7 privilege boundaries, §9
  class loading, §11 thread creation, §12 threats, §13 limitations, §15 invariants
- [`CLAUDE.md`](CLAUDE.md) — HC-1…HC-7, FM-1…FM-7, per-file security levels
- `SECURITY_ANALYSIS.md`, `STACK_VALIDATION_ANALYSIS.md`, `PROCESS_ISOLATION.md` — deeper findings,
  confused-deputy (N-6) and finalizer (N-9) analyses

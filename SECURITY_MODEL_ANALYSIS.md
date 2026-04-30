# Security Model Analysis — Dirty Chai

**Version:** 1.0  
**Date:** 2026-04-30  
**Scope:** Source-code analysis of the Dirty Chai security model as implemented in the current `trunk` branch.  
**Analyst:** Copilot (AI-assisted analysis; content reviewed and approved for this exempt document per `CLAUDE.md`)  
**Related Documents:** `SECURITY_MODEL.md`, `SECURITY_ANALYSIS.md`, `STACK_VALIDATION_ANALYSIS.md`, `PROCESS_ISOLATION.md`, `VULNERABILITIES_ADDRESSED.md`

---

## 1. Purpose

This document provides an independent, code-grounded analysis of the Dirty Chai security model. It is not a duplicate of `SECURITY_MODEL.md` (which describes *what* the model does). Instead it answers the question: **does the implementation match the stated design intent, where are the boundaries, and what residual gaps remain?**

The analysis is based on a direct reading of:

- `java.lang.System` (`System.java`) — SecurityManager installation
- `java.security.AccessController` (`AccessController.java`) — privileged execution
- `au.zeus.jdk.authorization.sm.CombinerSecurityManager` — SM implementation
- `au.zeus.jdk.authorization.policy.ConcurrentPolicyFile` — policy engine
- `au.zeus.jdk.net.Uri` — RFC 3986 URI validation
- `au.zeus.jdk.authorization.guards.*` — custom permission guards
- All existing security analysis `.md` documents

---

## 2. Executive Summary

Dirty Chai implements a coherent, defense-in-depth authorization model that meaningfully extends OpenJDK's deprecated `SecurityManager` architecture into modern Java (virtual threads, Foreign Function & Memory API, dynamic class definition). The core design is sound: installation controls are multi-layered, policy evaluation is fail-secure and concurrent, and new permission guards close surfaces that the base JDK left open.

Five areas warrant continued attention:

| Area | Finding | Status |
|------|---------|--------|
| `setSecurityManager` — trusted-class install path | Null check only; relies entirely on policy for governance | By design; acceptable provided policy is tight |
| `isGeneratedClassName` edge case | Classes with `$` in name but no package dot are flagged as generated | Correct for Lambda/accessor classes; a class like `MyApp$Inner` without a package would be a false positive; unlikely in practice |
| `CombinerSecurityManager` cache unbounded growth | TTL eviction is time-based, not count-based | Low-severity DoS if a large number of distinct `AccessControlContext` objects are created |
| `SocketPermission` in checked-permission cache | Comment in code acknowledges the SocketPermission caching concern but proceeds | DNS resolution outcomes that change over time could allow a cached allow to persist |
| `NativeMemoryPermission` — FFM surface coverage | Guards `global-arena`, `shared-arena`, `confined-arena`, `auto-arena`, and `reinterpret-memory-segment` | Coverage appears complete for current FFM API surface |

---

## 3. Architecture Map

```
┌───────────────────────────────────────────────────────────┐
│  Application / Untrusted Code                             │
└────────────────────────┬──────────────────────────────────┘
                         │  calls security-sensitive API
                         ▼
┌───────────────────────────────────────────────────────────┐
│  Guard Entry Points (Permission.checkGuard)               │
│  ObjectInputStream     → SerialObjectPermission           │
│  SecureClassLoader     → LoadClassPermission              │
│  NativeLibraries       → NativeInvocationPermission       │
│  Arena.*               → NativeMemoryPermission           │
│  MemorySegment         → NativeMemoryPermission           │
│  MethodHandles.Lookup  → DefineClassPermission            │
│  ThreadBuilders        → RuntimePermission(createXThread) │
│  Module.addExports     → RuntimePermission(mutateTopo)    │
└────────────────────────┬──────────────────────────────────┘
                         │  → sm.checkPermission(perm)
                         ▼
┌───────────────────────────────────────────────────────────┐
│  CombinerSecurityManager.checkPermission(perm)            │
│  ├─ ScopedValue recursion guard (max depth 7)             │
│  ├─ SM self-bypass (SMPrivilegedContext / SMConstructorContext) │
│  ├─ checked cache hit → return                            │
│  ├─ contextCache: build/reuse delegate ACC                │
│  └─ delegateContext.checkPermission(perm)                 │
│       └─ DelegateProtectionDomain.implies(perm)           │
│            ├─ < 4 domains: sequential                     │
│            └─ ≥ 4 domains: VirtualThreadPerTaskExecutor   │
└────────────────────────┬──────────────────────────────────┘
                         │
                         ▼
┌───────────────────────────────────────────────────────────┐
│  AccessControlContext.checkPermission(perm)               │
│  ├─ native getStackAccessControlContext()                  │
│  ├─ intersects ProtectionDomain of each frame             │
│  └─ stops at doPrivileged() boundary                      │
└────────────────────────┬──────────────────────────────────┘
                         │
                         ▼
┌───────────────────────────────────────────────────────────┐
│  ConcurrentPolicyFile.implies(pd, perm)                   │
│  ├─ volatile read: PermissionGrant[] (single memory fence)│
│  ├─ AllPermission fast path for infrastructure            │
│  ├─ static domain permissions                             │
│  └─ per-grant: CodeSource match (RFC 3986 URI) +          │
│               Principal match +                           │
│               grant.implies(perm)                         │
│  no match → deny (fail-secure)                            │
└───────────────────────────────────────────────────────────┘
```

---

## 4. SecurityManager Installation Analysis

### 4.1 `trustedSMClass()` — Exact-Class Whitelist

**Implementation** (`System.java`, line 3076–3085):

```java
private static boolean trustedSMClass(SecurityManager sm){
    Class<? extends SecurityManager> smClass = sm.getClass();
    if (CombinerSecurityManager.class.equals(smClass)) return true;
    if (SecurityManager.class.equals(smClass)) return true;
    return (PolicyOnlySecurityManager.class.equals(smClass));
}
```

**Analysis:**
- Uses `Class.equals()`, not `instanceof` — subclass bypass is correctly blocked.
- Whitelist contains exactly three classes: `SecurityManager`, `CombinerSecurityManager`, `PolicyOnlySecurityManager`.
- `SecurityPolicyWriter` is explicitly excluded (comment in code: "grants AllPermission; staging only").
- The three trusted classes are all from `java.base`, loaded by the bootstrap classloader. This is the correct trust boundary.
- **HC-1 compliance: PASS** — no untrusted or user-supplied class is in the whitelist.
- **HC-3 compliance: PASS** — `equals()` used throughout.

### 4.2 Custom SecurityManager — Four-Layer Validation

**Layer 1 — `@CallerSensitive` + direct caller check:**  
`Reflection.getCallerClass()` returns the immediate Java caller frame. If null (impossible under normal conditions but defensive), installation is immediately blocked.

**Layer 2 — `validateCallerStackWithStackWalker()` (50-frame limit):**  
Inspects the call stack using `StackWalker.Option.RETAIN_CLASS_REFERENCE`. Skips 2 frames (the method itself and the validator), then examines up to 50 frames for:
- `java.lang.reflect.*` / `sun.reflect.*` — reflection frames
- `java.lang.invoke.*` (with a whitelist exception for linkage-time-only classes: `StringConcatFactory`, `LambdaMetafactory`, `BootstrapMethodInvoker`, `MethodHandles`, `MethodType`)
- Generated class name patterns: `$$Lambda$`, `$Lambda$`, `GeneratedMethodAccessor`, `GeneratedConstructorAccessor`, `GeneratedSerializationConstructor`
- `$Proxy` / `com.sun.proxy.$Proxy` — dynamic proxies
- `jdk.internal.misc.Unsafe` / `sun.misc.Unsafe` — unsafe reflection

**Analysis of Layer 2:**
- Frame limit raised from 10 to 50 (Issue #85), closing a deep-stack bypass window.
- The `isMethodHandlesFrame()` whitelist is narrowed to linkage-time classes. Classes that *can* appear at call time (e.g., `MethodHandle.invoke`, `MethodHandle.invokeExact`) remain blocked.
- The `isGeneratedClassName()` heuristic `className.contains("$") && !className.contains(".")` is intentional: it flags classes with `$` but no package prefix, which indicates anonymous generated classes. Standard inner classes like `com.example.App$Inner` have a package and pass. This heuristic is correct for its purpose.
- **HC-4 compliance: PASS** — `@CallerSensitive` present.

**Layer 3 — ProtectionDomain validation:**  
Retrieves `directCaller.getProtectionDomain()` inside `doPrivileged`. A null result blocks installation.

**Layer 4 — `isGeneratedClassName()` on caller name:**  
Re-checks the direct caller's class name using the same generated-name heuristic.

**Overall assessment:** The four-layer approach is robust. The most likely residual bypass attempt would require a non-generated, non-reflected, non-proxied class with a real package, a real ProtectionDomain, and a real CodeSource — which is precisely what a legitimate custom SecurityManager author would provide.

### 4.3 Fail-Secure Behavior on `validateCallerStackWithStackWalker` Failure

```java
} catch (Exception e) {
    // If StackWalker fails for any reason, fail securely
    throw new SecurityException(
        "setSecurityManager: Stack validation failed: " + e.getMessage(), e);
}
```

**HC-2 compliance: PASS** — any failure in the StackWalker path throws `SecurityException` rather than continuing execution. The fail-secure invariant is maintained.

---

## 5. Permission Guard Model

### 5.1 Guard Inventory

| Permission Class | Guards | Target Name | Analysis |
|-----------------|--------|-------------|----------|
| `LoadClassPermission` | `SecureClassLoader.defineClass()` | `"ALLOW"` (single target) | Simple binary gate; any granted class can load any URL. Granularity is coarse but usable when combined with `URLPermission`. |
| `SerialObjectPermission` | `ObjectInputStream.readOrdinaryObject()` | Canonical class name | Per-class granularity. Placement in `readOrdinaryObject()` (Issue #85 improvement) means the check fires before object instantiation, blocking gadget chains before any constructors run. |
| `NativeInvocationPermission` | `NativeLibraries.findLibraryNameAddress()`, `SymbolLookup`, `SystemLookup` | Resolved library name | Guards native library symbol access at resolution time. |
| `NativeMemoryPermission` | `Arena.global()`, `Arena.shared()`, `Arena.confined()`, `Arena.auto()`, `AbstractMemorySegmentImpl.reinterpretInternal()` | Arena type name or `"reinterpret-memory-segment"` | Covers all current FFM arena types. The `reinterpret-memory-segment` target is important: reinterpreting a `MemorySegment` as a larger size is a classic memory confusion vector. |
| `DefineClassPermission` | `MethodHandles.Lookup.defineClass()` | `"ALLOW"` (single target) | Binary gate on dynamic class definition via lookup. Prevents runtime code injection through the `MethodHandles.Lookup` API. |
| `RuntimePermission("createPlatformThread")` | `ThreadBuilders.PlatformThreadBuilder.unstarted()`, `.factory()` | Standard runtime permission | New guard; closes the thread-bomb DoS gap in platform thread creation. |
| `RuntimePermission("createVirtualThread")` | `ThreadBuilders.VirtualThreadBuilder.unstarted()`, `.factory()` | Standard runtime permission | New guard; closes the virtual thread-bomb DoS gap. |

### 5.2 Coverage Assessment

The guard set covers the three categories of dangerous runtime surface that the base JDK left unguarded:

1. **Code injection paths** — `LoadClassPermission` (classpath), `DefineClassPermission` (MethodHandles Lookup), `SerialObjectPermission` (deserialization gadgets).
2. **Native/off-heap surfaces** — `NativeInvocationPermission` (library symbols), `NativeMemoryPermission` (arena allocation and segment reinterpretation).
3. **Resource exhaustion** — `RuntimePermission("createPlatformThread")`, `RuntimePermission("createVirtualThread")`.

**Gap observation:** `SerialObjectPermission` covers `ObjectInputStream.readOrdinaryObject()`. It does not appear to cover `ObjectInputStream.readProxyDesc()` (dynamic proxy class deserialization) or `readClassDesc()` paths directly. If a gadget chain relies solely on a proxy class instance, it may reach `readProxyDesc()` without the canonical class name check. This should be verified and, if not already covered, a supplementary check considered.

---

## 6. CombinerSecurityManager Analysis

### 6.1 Cache Architecture

**Two-tier cache:**

| Cache | Key | Value | TTL | Eviction |
|-------|-----|-------|-----|----------|
| `contextCache` | `AccessControlContext` (time-ref) | delegate `AccessControlContext` | 60 s | Time-based via `RC.concurrentMap` |
| `checked` | `AccessControlContext` (time-ref) | `NavigableSet<Permission>` | 20 s | Time-based via `RC.concurrentMap` |

**Analysis:**
- Time-based eviction without count limits means that if a high-throughput application creates many distinct `AccessControlContext` objects rapidly, the cache can grow without bound until TTL expires. This is a low-severity denial-of-service vector (memory pressure, not privilege escalation).
- The `checked` cache uses `ConcurrentSkipListSet` backed by `RC` (weak/soft reference wrappers), which is non-blocking and GC-friendly under heap pressure.
- Cache keys use time-referenced wrappers, meaning keys become eligible for GC before TTL if the `AccessControlContext` is no longer strongly reachable. This is the intended behavior.

### 6.2 Recursion Guard

```java
private static final ScopedValue<Integer> TRUSTED_RECURSIVE_CALL = ScopedValue.newInstance();
```

The recursion guard uses `ScopedValue` (JDK 21+ incubator / 23 finalized) to thread a depth counter through re-entrant permission checks. A depth > 7 throws `AccessControlException`. This correctly prevents stack overflow from permission checks that themselves require permission checks.

**Observation:** The use of `ScopedValue` over `ThreadLocal` is the correct modern choice — it is inherited correctly across virtual thread continuations and avoids the cleanup obligation of `ThreadLocal.remove()`.

### 6.3 Parallel Domain Check

```java
// < 4 domains → sequential
// ≥ 4 domains → parallel (VirtualThreadPerTaskExecutor)
```

Using virtual threads for parallelizing `DelegateProtectionDomain.implies()` checks is appropriate — these checks are CPU-bound and short-lived, which is the optimal profile for virtual thread tasks. The threshold of 4 domains is a reasonable heuristic to avoid the overhead of task submission for simple contexts.

### 6.4 SM Self-Bypass

```java
if (constructed
    && (SMPrivilegedContext.equals(executionContext)
    || SMConstructorContext.equals(executionContext))
) return;
```

This fast-path allows the SecurityManager's own internal operations to proceed without re-entering permission checking (preventing infinite loops during SM initialization). The two contexts (`SMPrivilegedContext` = single-domain context containing only the SM's own `ProtectionDomain`; `SMConstructorContext` = the ACC captured before the SM was installed) represent the smallest possible trust scope for the SM itself.

**Security observation:** These bypass contexts are captured at construction time and are final. They cannot be obtained by untrusted code (the fields are private). The bypass is safe.

---

## 7. ConcurrentPolicyFile Analysis

### 7.1 Memory Model for Grant Array

```java
volatile read: PermissionGrant[] grantRefCopy = grantArray;
```

The grant array is accessed via a single volatile read, providing a happens-before relationship with policy refresh writes. All subsequent work in `implies()` operates on the local snapshot. This is the correct pattern for a lock-free, high-throughput read path.

### 7.2 URI-Based CodeSource Matching

Policy matching uses `au.zeus.jdk.net.Uri` (RFC 3986 strict parsing) rather than `java.net.URI` (RFC 2396 lenient). Key differences:

- RFC 3986 disallows "other" characters that RFC 2396 allowed (closing ambiguous matching).
- No DNS resolution during matching — comparison is string-only after normalization. This closes DNS rebinding as a policy-bypass vector.
- IPv6 addresses normalized to RFC 5952 text form — consistent equality for identical IPv6 addresses expressed differently.
- Windows drive letters normalized to upper case — consistent file-scheme matching across case-insensitive filesystems.

**HC-7 compliance: PASS** — all CodeSource URL comparisons go through RFC 3986 URI parsing.

### 7.3 Null CodeSource Invariant

```java
// Fail-secure: return null CodeSource on URI/URL validation exception
try {
    URL url = new URI(sb.toString()).toURL();
    return new CodeSource(url, certificates);
} catch (MalformedURLException | URISyntaxException e) {
    return null; // fail-secure
}
```

A null `CodeSource` cannot match any grant clause (no `CodeBase` string can equal null). Code with a null `CodeSource` therefore receives no policy-granted permissions. **HC-5 compliance: PASS.**

---

## 8. AccessController Analysis

### 8.1 `@CallerSensitive` Coverage

All `doPrivileged` overloads carry `@CallerSensitive`:
- `doPrivileged(PrivilegedAction<T>)` — line 317
- `doPrivilegedWithCombiner(PrivilegedAction<T>)` — line 348
- `doPrivileged(PrivilegedAction<T>, AccessControlContext)` — line 388
- `doPrivileged(PrivilegedAction<T>, AccessControlContext, Permission...)` — line 435
- `doPrivilegedWithCombiner(PrivilegedAction<T>, AccessControlContext, Permission...)` — line 499

Each overload retrieves the caller class via `Reflection.getCallerClass()` and uses it to determine the privilege boundary. **HC-4 compliance: PASS.**

### 8.2 Context-Bounded Privilege

`getStackAccessControlContext()` is a native method that intersects `ProtectionDomain` of every frame on the call stack up to a `doPrivileged()` boundary. This means:
- Privilege is always bounded by the least-privileged domain on the call stack.
- Attackers cannot "route through" a trusted `doPrivileged` block to elevate privileges beyond what the trusted block explicitly grants.
- The `neverPrivileged()` context (used for finalizer threads in this codebase) ensures cleanup callbacks cannot inherit caller privilege.

---

## 9. RFC 3986 URI Validation (Uri.java)

`au.zeus.jdk.net.Uri` is a full RFC 3986 parser (1,990 lines). Key security properties:

- **Immutable** — `final class Uri`. Once parsed, the normalized form cannot be mutated.
- **No serialization** — `Uri` is not `Serializable`, preventing deserialization of crafted URI state.
- **Strict character set** — characters outside RFC 3986 allowed sets must be percent-encoded; unencoded forbidden characters cause a parse exception.
- **Normalization at parse time** — percent-encoding is normalized, scheme and host are case-folded, IPv6 is RFC 5952 normalized, path segments (`.`, `..`) are resolved. This means two URIs that refer to the same resource will compare equal regardless of the form they were supplied in.

The combination of parse-time normalization and string equality (no DNS) for policy matching eliminates the class of attacks where an attacker supplies a URI that refers to the same resource as a policy grant but compares unequal under naïve string comparison (and vice versa).

---

## 10. Thread Model Security

### 10.1 Builder-Path Permission Checks

`ThreadBuilders.PlatformThreadBuilder` and `VirtualThreadBuilder` now check `RuntimePermission("createPlatformThread")` and `RuntimePermission("createVirtualThread")` respectively at builder `unstarted()` and `factory()` call sites. This fires before any OS resource is consumed.

**Coverage gap (documented in `PROCESS_ISOLATION.md`):** The checks are in the builder path. The traditional `new Thread(...)` constructor path uses `sm.checkAccess(g)`, which does not call `checkPermission` for application thread groups (only for the root/system group). This means code using `new Thread(...)` directly bypasses the new permission checks.

**Status:** This gap is documented in `PROCESS_ISOLATION.md`. The complete fix would require adding the same `checkPermission` call in the traditional constructor path. This is a **known open gap**, not an oversight.

### 10.2 Virtual Thread Carrier Pinning

Virtual threads that execute `synchronized` blocks pin their carrier thread. No permission check can prevent this once the virtual thread is running. The `createVirtualThread` permission check prevents creation, but once granted, CPU-bound or synchronized virtual threads can saturate the `ForkJoinPool` carrier pool.

**Assessment:** This is an inherent limitation of the virtual thread scheduler model, documented in `PROCESS_ISOLATION.md`. The correct mitigation for hostile code that has already been granted `createVirtualThread` is process isolation.

### 10.3 AccessControlContext Inheritance at Thread Creation

Builder-path threads capture the creator's `AccessController.getContext()` at construction. This means:
- A thread created inside `Subject.callAs(...)` inherits the Subject context.
- A thread created outside any Subject scope inherits the minimal public context.

This is the intended behavior and is documented in `SECURITY_MODEL.md` section 11.

---

## 11. Security Invariant Verification

| Invariant | Location | Status |
|-----------|----------|--------|
| Trusted SM uses exact class identity, not subclass trust | `trustedSMClass()` in `System.java` | **HOLDS** — `Class.equals()` used |
| Custom SM requires all four validation layers | `setSecurityManager()` in `System.java` | **HOLDS** — layers executed unconditionally for non-trusted SM |
| Privileged execution is caller-sensitive and context-bounded | All `doPrivileged` overloads in `AccessController.java` | **HOLDS** — `@CallerSensitive` on all overloads |
| Policy evaluation is deny-by-default | `ConcurrentPolicyFile.implies()` | **HOLDS** — returns false if no grant matches |
| Validation failures are fail-secure | Exception handling in `validateCallerStackWithStackWalker()`, `ConcurrentPolicyFile` URI parsing | **HOLDS** — SecurityException or null CodeSource on any failure |
| Null CodeSource is always unprivileged | `ConcurrentPolicyFile` grant matching | **HOLDS** — null CodeSource never matches a grant |
| No reflection in security-critical SM installation path | `validateCallerStackWithStackWalker()` | **HOLDS** — reflection frames are detected and rejected |

---

## 12. Findings Summary

### 12.1 Confirmed Strengths

1. **Multi-layer SM installation guard** — the four-layer custom-SM validation is the most comprehensive implementation of this pattern in any known JDK fork. The use of `StackWalker` with a 50-frame limit closes the deep-stack bypass window that was present in earlier builds.

2. **Exact-class whitelist with explicit exclusion comment** — `SecurityPolicyWriter` exclusion is documented in the source. The comment explains the reasoning, reducing future maintenance risk.

3. **Fail-secure throughout** — every catch block in security-critical code either re-throws `SecurityException` or returns null (unprivileged). No silent continuation after failure.

4. **RFC 3986 URI normalization at parse time** — URI normalization happens once at parse time and is stored as a canonical form. Policy matching operates on canonical forms only, eliminating ambiguity.

5. **FFM surface coverage** — `NativeMemoryPermission` covers all current arena types plus `reinterpret-memory-segment`. This is the first known attempt to bring FFM off-heap allocation under SecurityManager-style authorization.

6. **ScopedValue recursion guard** — using `ScopedValue` for recursion tracking in `CombinerSecurityManager` is the correct modern choice and inherits properly across virtual thread continuations.

### 12.2 Open Gaps

| ID | Description | Severity | Documented? |
|----|-------------|----------|-------------|
| G-1 | `new Thread(...)` constructor path does not call `checkPermission("createPlatformThread")` — only the builder path does | Medium | Yes — `PROCESS_ISOLATION.md` |
| G-2 | Virtual thread carrier pinning cannot be prevented once a virtual thread is running | Low (requires prior `createVirtualThread` grant) | Yes — `PROCESS_ISOLATION.md` |
| G-3 | `SerialObjectPermission` in `readOrdinaryObject()` — coverage of `readProxyDesc()` and `readClassDesc()` should be verified to confirm gadget chains through proxy deserialization are blocked | Medium | Not yet documented |
| G-4 | `contextCache` and `checked` caches have time-based TTL but no count-based cap — high-volume distinct-context workloads can cause unbounded cache growth | Low | Not yet documented |
| G-5 | `SocketPermission` in the `checked` cache may return a stale allow after DNS state changes within the TTL window | Low | Acknowledged in source code comment |

### 12.3 Design Observations

- **Policy-first trust model for trusted SM classes** — the decision to skip stack validation for `SecurityManager`, `CombinerSecurityManager`, and `PolicyOnlySecurityManager` is correct: these classes are bootstrap-loaded and policy-constrained. The alternative (applying stack validation to all SM classes including trusted ones) would have broken JUnit-style test frameworks unnecessarily, as documented in `STACK_VALIDATION_ANALYSIS.md`.

- **`DelegateDomainCombiner` design** — stripping the SecurityManager's own `ProtectionDomain` from the check context (visible in the `DelegateDomainCombiner.combine()` method) is necessary to prevent the SM's `AllPermission` grant from polluting the effective context of untrusted callers. This is a non-obvious but correct design choice.

- **`polpAudit` / `SecurityPolicyWriter` staging workflow** — the explicit staging-to-production separation (audit → review → strict policy) is a pragmatic solution to the historically difficult problem of policy authoring. This workflow reduces the risk of over-permissive production policies, which is the most common failure mode in Java security configurations.

---

## 13. Recommendations

The following recommendations are offered for human review and decision. They are not prescriptions — the design team may have additional context that affects priority.

| ID | Recommendation | Priority |
|----|----------------|----------|
| R-1 | Verify `SerialObjectPermission` coverage of `readProxyDesc()` deserialization path (G-3) | Medium |
| R-2 | Add `checkPermission("createPlatformThread")` to the traditional `new Thread(...)` constructor path to close G-1, aligning it with the builder path | Medium |
| R-3 | Document G-4 (cache unbounded growth) in `SECURITY_ANALYSIS.md` and consider adding a maximum entry count to `contextCache` | Low |
| R-4 | Consider whether the `SocketPermission` caching concern (G-5) is acceptable for the target deployment environment. If DNS rebinding is a concern, SocketPermission entries should be excluded from the `checked` cache | Low |

---

## 14. Related Documents

| Document | Relationship |
|----------|-------------|
| `SECURITY_MODEL.md` | Authoritative description of the security model (what it does) |
| `SECURITY_ANALYSIS.md` | Historical findings and resolved issues |
| `STACK_VALIDATION_ANALYSIS.md` | Trade-off analysis for `validateCallerStackWithStackWalker()` |
| `PROCESS_ISOLATION.md` | Thread creation, finalizer/Cleaner, class-init, and attach gating analysis |
| `VULNERABILITIES_ADDRESSED.md` | Known CVE and vulnerability classes mitigated by this model |
| `PHILOSOPHY.md` | Design philosophy and guiding principles |
| `HISTORY.md` | Historical context for Java authorization architecture |

---

*This document is exempt from the OpenJDK Interim Policy on Generative AI contribution restriction, as specified in `CLAUDE.md` (commit 573a8e64e297b0dbd3d5317dbc562f630ff61103).*

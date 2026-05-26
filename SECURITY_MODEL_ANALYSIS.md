# Security Model Analysis — Dirty Chai

**Version:** 1.2  
**Date:** 2026-05-13  
**Scope:** Source-code analysis of the Dirty Chai security model as implemented in the current `trunk` branch, including process-isolation necessity analysis: virtual thread pinning, ForkJoinPool carrier-thread saturation, SecurityManager bypass risk, FFM resource-exhaustion surfaces, and process-isolation decision boundaries.  This version adds coverage of the `DigestCodeSource` / `DigestGrant` content-addressed trust feature merged in PR #203, and the `digest` policy-file selector implemented in `DefaultPolicyScanner` / `DefaultPolicyParser`.  
**Analyst:** Copilot (AI-assisted analysis; content reviewed and approved for this exempt document per `CLAUDE.md`)  
**Related Documents:** `SECURITY_MODEL.md`, `SECURITY_ANALYSIS.md`, `STACK_VALIDATION_ANALYSIS.md`, `PROCESS_ISOLATION.md`, `VULNERABILITIES_ADDRESSED.md`, `DIGEST_GRANT_PLAN.md`

---

## 1. Purpose

This document provides an independent, code-grounded analysis of the Dirty Chai security model. It is not a duplicate of `SECURITY_MODEL.md` (which describes *what* the model does). Instead it answers the question: **does the implementation match the stated design intent, where are the boundaries, and what residual gaps remain?**

The analysis is based on a direct reading of:

- `java.lang.System` (`System.java`) — SecurityManager installation
- `java.security.AccessController` (`AccessController.java`) — privileged execution
- `java.security.DigestCodeSource` — content-addressed code source (new in PR #203)
- `java.security.SecureClassLoader` — class loading with automatic `DigestCodeSource` promotion
- `au.zeus.jdk.authorization.sm.CombinerSecurityManager` — SM implementation
- `au.zeus.jdk.authorization.policy.ConcurrentPolicyFile` — policy engine
- `au.zeus.jdk.authorization.policy.DefaultPolicyScanner` / `DefaultPolicyParser` — policy file syntax (including new `digest` selector)
- `org.apache.river.api.security.DigestGrant` — content-hash-based permission grant (new in PR #203)
- `au.zeus.jdk.net.Uri` — RFC 3986 URI validation
- `au.zeus.jdk.authorization.guards.*` — custom permission guards
- All existing security analysis `.md` documents

---

## 2. Executive Summary

Dirty Chai implements a coherent, defense-in-depth authorization model that meaningfully extends OpenJDK's deprecated `SecurityManager` architecture into modern Java (virtual threads, Foreign Function & Memory API, dynamic class definition). The core design is sound: installation controls are multi-layered, policy evaluation is fail-secure and concurrent, and new permission guards close surfaces that the base JDK left open.

The second half of this document (sections 14–17) provides a process-isolation necessity analysis. It answers: which threats are fully stopped by the SecurityManager permission layer alone, which threats can only be *contained* in-process, and which threats require OS-level process isolation regardless of what DirtyChai does.

Five areas from the core-model analysis warrant continued attention:

| Area | Finding | Status |
|------|---------|--------|
| `setSecurityManager` — trusted-class install path | Null check only; relies entirely on policy for governance | By design; acceptable provided policy is tight |
| `isGeneratedClassName` edge case | Classes with `$` in name but no package dot are flagged as generated | Correct for Lambda/accessor classes; a class like `MyApp$Inner` without a package would be a false positive; unlikely in practice |
| `CombinerSecurityManager` cache unbounded growth | TTL eviction is time-based, not count-based | Low-severity DoS if a large number of distinct `AccessControlContext` objects are created |
| `SocketPermission` in checked-permission cache | Comment in code acknowledges the SocketPermission caching concern but proceeds | DNS resolution outcomes that change over time could allow a cached allow to persist |
| `NativeMemoryPermission` — FFM surface coverage | Guards `global-arena`, `shared-arena`, `confined-arena`, `auto-arena`, and `reinterpret-memory-segment` | Coverage appears complete for current FFM API surface |

One area previously listed as a gap has been closed since version 1.1:

| Area | Finding | Resolution |
|------|---------|------------|
| Content-addressed trust / dependency confusion | Attackers could serve a different artifact at a trusted URL and satisfy a `codebase`-only policy grant | **Closed (PR #203)** — `SecureClassLoader` now auto-promotes network `CodeSource` to `DigestCodeSource`; policy `digest` clauses (`DigestGrant`) match only when the artifact hash matches the pinned value |

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
│               Digest match (DigestGrant only —            │
│                 pd.getCodeSource() must be DigestCodeSource│
│                 with matching algorithm + bytes) +        │
│               Principal match +                           │
│               grant.implies(perm)                         │
│  no match → deny (fail-secure)                            │
└───────────────────────────────────────────────────────────┘

SecureClassLoader (class-loading path):
┌───────────────────────────────────────────────────────────┐
│  SecureClassLoader.getProtectionDomain(CodeSource cs)     │
│  ├─ cs already DigestCodeSource? → use as-is              │
│  ├─ pdcache hit? → return cached ProtectionDomain         │
│  ├─ SM active and codebase non-null?                      │
│  │   ├─ check URLPermission("GET:")                       │
│  │   ├─ download artifact; compute SHA-256 digest         │
│  │   ├─ promote cs → DigestCodeSource                     │
│  │   └─ recompute permissions from DigestCodeSource       │
│  ├─ check LoadClassPermission.LOAD_CLASS_ALLOW            │
│  └─ pdcache.putIfAbsent(key, pd)                          │
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

### 7.4 `digest` Policy Selector and `DigestGrant` (PR #203)

**Implementation:** `DefaultPolicyScanner.java` (token `"digest"`), `DefaultPolicyParser.java` (`resolveGrant()`), `DigestGrant.java`.

#### 7.4.1 Policy Syntax

A `grant` block may now include a `digest` clause in addition to the existing `signedby`, `codebase`, and `principal` selectors:

```
grant codebase "https://trusted.example.com/lib.jar",
      digest "SHA-256:3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b"
{
    permission java.io.FilePermission "/tmp/-", "read,write";
};
```

The scanner tokenises `digest` as a keyword and expects a single quoted string in `algorithm:hexValue` form (`DefaultPolicyScanner.java:231–237`). The parser hex-decodes the value, calls `pgb.digest(algorithm, bytes)`, and sets `context(PermissionGrantBuilder.DIGEST)`, producing a `DigestGrant` (`DefaultPolicyParser.java:281–299`).

#### 7.4.2 `DigestGrant` Implication Semantics

`DigestGrant.implies(ProtectionDomain pd)` (and the `CodeSource`-based overload) enforces the following chain:

1. Delegates to `super.implies(pd)` — URI/codebase, signer, and principal checks from `URIGrant` / `CertificateGrant`.
2. Extracts `pd.getCodeSource()`.
3. If the CodeSource is **not** a `DigestCodeSource` → returns `false` immediately. A plain `CodeSource` never satisfies a digest grant, regardless of URL match.
4. Compares `digestAlgorithm` (exact string equality, case-sensitive).
5. Compares `digest` bytes with `Arrays.equals`.
6. Only if all six conditions hold does the grant apply.

**Security property:** A `DigestGrant` is content-pinned. Swapping the artifact at a trusted URL (dependency confusion, supply-chain substitution) produces a different SHA-256 and cannot satisfy the grant. This is fail-secure: any mismatch — wrong type, wrong algorithm, wrong bytes — returns `false`.

#### 7.4.3 `SecureClassLoader` Auto-Promotion to `DigestCodeSource`

`SecureClassLoader.getProtectionDomain(CodeSource cs)` (`SecureClassLoader.java:239+`) is the single point where `ProtectionDomain` objects are created for loaded classes. The updated flow is:

1. **If `cs` is already a `DigestCodeSource`**: use it as-is as the cache key; no re-download.
2. **If SM is active and `cs` has a non-null codebase URL**:
   - Check `URLPermission("GET:")` for the new domain.
   - Download the artifact; compute SHA-256.
   - Promote `cs` → `DigestCodeSource(uri, certs, "SHA-256")`.
   - Recompute permissions from the promoted `DigestCodeSource`.
3. Check `LoadClassPermission.LOAD_CLASS_ALLOW`.
4. `pdcache.putIfAbsent(key, pd)` — only after all checks pass.

The `CodeSourceKey` record distinguishes plain `CodeSource` keys from `DigestCodeSource` keys: a null `digestAlgorithm` key (plain `CS`) is **never equal** to a non-null `digestAlgorithm` key (`DigestCS`). This prevents a cached plain-CS lookup from satisfying a subsequent `defineClass` call that expects a digest-bearing domain.

#### 7.4.4 DOS Defences in `DigestCodeSource`

`DigestCodeSource` enforces hard limits on stream content to prevent resource exhaustion during artifact download and deserialization:

| Limit | Value | Purpose |
|-------|-------|---------|
| `MAX_STREAM_BYTES` | 512 MiB | Abort digest computation on abnormally large artifact downloads |
| `MAX_CERT_COUNT` | 100 | Bound certificate array size during deserialization |
| `MAX_CERT_BYTES` | 64 KiB | Bound per-certificate DER size during deserialization |
| `MAX_DIGEST_BYTES` | 512 bytes | Bound digest field size during deserialization |

#### 7.4.5 Allowed Hash Algorithms

`DigestCodeSource` accepts only:

```
SHA-256, SHA-384, SHA-512, SHA-512/256, SHA3-256, SHA3-384, SHA3-512
```

Any other algorithm string throws `IllegalArgumentException` at construction time. This prevents weak-hash policy grants (MD5, SHA-1) from being expressed.

#### 7.4.6 Assessment

- **HC-5 compliance: PASS** — a `DigestGrant` for a `DigestCodeSource` with `null` URI still requires a non-null `DigestCodeSource` type; no bypass via null CodeSource.
- **HC-7 compliance: PASS** — `DigestCodeSource.equals()` uses `Uri.urlToUri(url)` for DNS-free URI comparison, consistent with the rest of the policy engine.
- **Fail-secure:** Type mismatch (plain `CodeSource` vs. `DigestCodeSource`) returns `false`; byte mismatch returns `false`; algorithm mismatch returns `false`.
- **Dependency-confusion threat: CLOSED** — confirmed by code inspection: `SecureClassLoader` auto-promotes, `DigestGrant` type-guards, and `CodeSourceKey` prevents cache reuse across CS and DigestCS keys.

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

**Coverage:** Both the builder path and the traditional `new Thread(...)` constructor path are covered. Every public `Thread` constructor calls the private helper `canCreatePlatformThread()` (`Thread.java:765–768`) as a constructor argument, which calls `sm.checkPermission(new RuntimePermission("createPlatformThread"))` before the constructor body executes. The builder path additionally checks at `unstarted()` / `factory()` (`ThreadBuilders.java:185, 207`), giving a second gate for the builder path. There is no bypass via the traditional constructor.

### 10.2 Virtual Thread Carrier Pinning

Virtual threads that execute `synchronized` blocks pin their carrier thread. No permission check can prevent this once the virtual thread is running. The `createVirtualThread` permission check prevents creation, but once granted, CPU-bound or synchronized virtual threads can saturate the `ForkJoinPool` carrier pool. JEP 491 has addressed synchronized blocks pinning carrier threads, now only native methods pin threads. https://openjdk.org/jeps/491  "In particular, if a virtual thread calls native code, either through a native method or the Foreign Function & Memory API, and that native code calls back to Java code that performs a blocking operation or blocks on a monitor, then the virtual thread will be pinned."  This narrows the scope significantly, we will need to perform static analysis and look for this pattern in the JDK and either guard these calls or determine if they can be made non blocking.

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
| `DigestGrant` never implies a plain `CodeSource` domain | `DigestGrant.implies(ProtectionDomain)` | **HOLDS** — `instanceof DigestCodeSource` check; plain CS returns false immediately |
| `SecureClassLoader` stores `ProtectionDomain` in `pdcache` only after digest computed | `SecureClassLoader.getProtectionDomain()` | **HOLDS** — `pdcache.putIfAbsent` called only after SHA-256 computation and all permission checks |
| Plain `CodeSourceKey` and `DigestCodeSourceKey` never compare equal | `CodeSourceKey.equals()` in `SecureClassLoader` | **HOLDS** — null vs. non-null `digestAlgorithm` comparison prevents cache reuse across CS/DigestCS |

---

## 12. Findings Summary

### 12.1 Confirmed Strengths

1. **Multi-layer SM installation guard** — the four-layer custom-SM validation is the most comprehensive implementation of this pattern in any known JDK fork. The use of `StackWalker` with a 50-frame limit closes the deep-stack bypass window that was present in earlier builds.

2. **Exact-class whitelist with explicit exclusion comment** — `SecurityPolicyWriter` exclusion is documented in the source. The comment explains the reasoning, reducing future maintenance risk.

3. **Fail-secure throughout** — every catch block in security-critical code either re-throws `SecurityException` or returns null (unprivileged). No silent continuation after failure.

4. **RFC 3986 URI normalization at parse time** — URI normalization happens once at parse time and is stored as a canonical form. Policy matching operates on canonical forms only, eliminating ambiguity.

5. **FFM surface coverage** — `NativeMemoryPermission` covers all current arena types plus `reinterpret-memory-segment`. This is the first known attempt to bring FFM off-heap allocation under SecurityManager-style authorization.

6. **ScopedValue recursion guard** — using `ScopedValue` for recursion tracking in `CombinerSecurityManager` is the correct modern choice and inherits properly across virtual thread continuations.

7. **Content-addressed trust via `DigestCodeSource` / `DigestGrant` (PR #203)** — `SecureClassLoader` automatically promotes every network-loaded `CodeSource` to a `DigestCodeSource` (SHA-256) when a SecurityManager is active. Policy `digest` clauses produce `DigestGrant` objects that match only if the artifact hash matches the pinned value. This is the first known OpenJDK-based implementation that closes the dependency-confusion / content-substitution supply-chain attack vector at the policy-evaluation layer. The policy file scanner (`DefaultPolicyScanner`) and parser (`DefaultPolicyParser`) support the `digest "algorithm:hexValue"` syntax natively, making the feature usable without programmatic grant construction.

### 12.2 Open Gaps

| ID | Description | Severity | Documented? |
|----|-------------|----------|-------------|
| G-2 | Virtual thread carrier pinning cannot be prevented once a virtual thread is running | Low (requires prior `createVirtualThread` grant) | Yes — `PROCESS_ISOLATION.md` |
| G-3 | `SerialObjectPermission` in `readOrdinaryObject()` — `readProxyDesc()` does not have a corresponding guard; gadget chains that reach object creation via `TC_PROXYCLASSDESC` are not blocked by the current guard placement | Medium | Yes — `SECURITY_MODEL.md` section 13, G-3 confirmed |
| G-4 | `contextCache` and `checked` caches have time-based TTL but no count-based cap — high-volume distinct-context workloads can cause unbounded cache growth | Low | Not yet documented |
| G-5 | `SocketPermission` in the `checked` cache may return a stale allow after DNS state changes within the TTL window | Low | Acknowledged in source code comment |
| G-6 | Virtual threads that enter `synchronized` blocks pin their carrier thread; once running, no JVM mechanism can forcibly terminate or unpin them — carrier-thread exhaustion is possible for code already granted `createVirtualThread` | Low (requires prior grant) | Documented in `PROCESS_ISOLATION.md` |

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
| R-2 | Document G-4 (cache unbounded growth) in `SECURITY_ANALYSIS.md` and consider adding a maximum entry count to `contextCache` | Low |
| R-3 | Consider whether the `SocketPermission` caching concern (G-5) is acceptable for the target deployment environment. If DNS rebinding is a concern, SocketPermission entries should be excluded from the `checked` cache | Low |
| R-4 | For deployments that must permit `createVirtualThread` to partially-trusted code, route that code through a bounded, isolated `ForkJoinPool` with a caller-side deadline per the three-step layered defence in `PROCESS_ISOLATION.md` (sections on containment strategy) | Low |

---

## 14. Process Isolation Analysis — Virtual Thread Pinning and DoS Vectors

### 14.1 What Pinning Is

When a virtual thread executes a `synchronized` block or method, or calls `Continuation.pin()` directly, the JVM scheduler cannot unmount the continuation from its carrier (platform) thread. The virtual thread is said to be *pinned*. While pinned, the carrier thread is blocked until the virtual thread exits the `synchronized` region or explicitly parks.

This is not a DirtyChai invention; it is inherent to the OpenJDK virtual-thread design. Evidence in the codebase:

- **`VirtualThread.java:764–780`** — the comment `// park on the carrier thread when pinned` appears at the `park`/`sleep` paths. When `!yielded` (the virtual thread could not yield because it is pinned), `parkOnCarrierThread(false, 0)` is called, which parks the OS thread itself.
- **`VirtualThread.java:1377`** — `Continuation.pin()` is called directly in `disableSuspendAndPreempt()`, used by `VirtualThread` to guard scheduler-start continuations.
- **`VirtualThread.java:359`** — `Continuation.pin()` / `Continuation.unpin()` wraps task submission to the scheduler when the submitting thread is itself virtual, preventing a scheduler deadlock during startup.
- **`VirtualThread.java:859`** — `// Call into VM when pinned to record a JFR jdk.VirtualThreadPinned event`.

### 14.2 DoS Vector: Carrier Saturation by Pinned Virtual Threads

The default `ForkJoinPool` scheduler is created at `VirtualThread.java:1469–1501`:

```java
private static ForkJoinPool createDefaultScheduler() {
    ForkJoinWorkerThreadFactory factory = pool -> {
        PrivilegedAction<ForkJoinWorkerThread> pa = () -> new CarrierThread(pool);
        return AccessController.doPrivileged(pa);
    };
    PrivilegedAction<ForkJoinPool> pa = () -> {
        int parallelism, maxPoolSize, minRunnable;
        // ...property lookups...
        parallelism = Runtime.getRuntime().availableProcessors();     // line 1482
        maxPoolSize = Integer.max(parallelism, 256);                  // line 1488
        minRunnable = Integer.max(parallelism / 2, 1);                // line 1493
        return new ForkJoinPool(parallelism, factory, handler, asyncMode,
                     0, maxPoolSize, minRunnable, pool -> true, 30, SECONDS);
    };
    return AccessController.doPrivileged(pa);
}
```

Key scheduler parameters (defaults, overridable via system properties):

| Parameter | Default | System Property |
|-----------|---------|-----------------|
| `parallelism` | `Runtime.availableProcessors()` | `jdk.virtualThreadScheduler.parallelism` |
| `maxPoolSize` | `max(parallelism, 256)` | `jdk.virtualThreadScheduler.maxPoolSize` |
| `minRunnable` | `max(parallelism / 2, 1)` | `jdk.virtualThreadScheduler.minRunnable` |

The `maxPoolSize` cap (default 256) is the hard carrier-thread ceiling for the entire JVM. A `synchronized` virtual thread holds a carrier for its entire blocked duration and does not release it even when waiting on a monitor. If code pins `maxPoolSize` virtual threads simultaneously — each blocked in a `synchronized` section waiting for each other, or waiting on I/O inside a `synchronized` block — every carrier slot is consumed. The scheduler cannot spawn new carriers beyond `maxPoolSize`. No other virtual thread in the JVM can be scheduled until a pinned thread unblocks.

This attack does not require any SecurityManager permission beyond the permission to *create* virtual threads. `synchronized` entry is not a SecurityManager-gated operation. The DoS arises from consumption of a resource (carrier threads) that the virtual thread already holds legitimately.

`PROCESS_ISOLATION.md` documents this directly (lines 27–30):

> "Carrier thread starvation — Buggy code can pin carrier threads via `synchronized` in virtual threads at scale."
> "Both attacks require the hostile thread to be already running. The new permission checks prevent that thread from being created in the first place, which is the correct defence boundary."

### 14.3 Interrupt-Immunity Compounds the Risk

Once a virtual thread is running inside a pinned `synchronized` block, it is essentially unremovable (`PROCESS_ISOLATION.md` lines 131–171):

- **`Thread.interrupt()`** — sets a flag; code that never polls `isInterrupted()` or never blocks in an interruptible method ignores it.
- **`Thread.stop()`** — permanently removed; throws `UnsupportedOperationException` on virtual threads.
- **`StructuredTaskScope.close()`** — calls `interrupt()` on subtasks; if the subtask swallows `InterruptedException`, `close()` blocks forever.
- **`ExecutorService.shutdownNow()`** — interrupt-based; subject to the same limitation.
- **`ForkJoinPool` shutdown** — sends `interrupt()` to carrier threads; a mounted virtual thread that ignores the flag continues to block its carrier.

No mechanism can forcibly terminate a virtual thread that refuses to cooperate. This is a fundamental property of the Java threading model, not a gap in DirtyChai's design (`PROCESS_ISOLATION.md` lines 133–136).

### 14.4 Compound DoS Scenarios

A thread granted `createVirtualThread` can:

1. Spawn `maxPoolSize` (256 by default) virtual threads.
2. Have each thread enter a wide `synchronized(lock) { busyWait(); }` block.
3. Consume all carrier slots within a bounded window (`minRunnable` triggers expansion up to `maxPoolSize`).
4. Stall the entire JVM's default virtual thread scheduler until the JVM exits.

For platform threads, the analogous attack creates OS threads. Platform threads are heavier, making mass creation slower, but `createPlatformThread` is checked for both the builder and the traditional `new Thread(...)` constructor path, so thread-bomb attacks require the permission to be granted.

---

## 15. ForkJoinPool Carrier-Thread Saturation and SecurityManager Behavior

### 15.1 No SecurityManager Hook on ForkJoinPool Scheduling

`ForkJoinPool` is a `java.util.concurrent` component. Its internal carrier-thread creation (`new CarrierThread(pool)` at `VirtualThread.java:1471`) runs inside a `PrivilegedAction` passed to `AccessController.doPrivileged(pa)`. This drops any caller-context restrictions at creation time. The internal scheduling logic — work-stealing, task submission, thread compensation — contains no `SecurityManager.checkPermission()` calls.

This has two concrete implications:

**Implication A — Carrier thread compensation is not policy-gated.**  
When the `ForkJoinPool` decides to compensate for a blocked carrier (maintaining `minRunnable` running threads), it creates a new carrier thread internally. This creation path does not invoke `RuntimePermission("createPlatformThread")`. The permission check at `ThreadBuilders.java:185` and `207` fires only when application code explicitly calls `Thread.ofPlatform()...unstarted()` or `...factory()`. Even if an operator grants `createVirtualThread` but denies `createPlatformThread`, the `ForkJoinPool` scheduler still creates carrier threads internally as compensation. This is consistent with the documented design: the permission gates *application-level* thread creation; JVM-internal scheduler behavior is separate.

**Implication B — Carrier saturation does not bypass SecurityManager; it starves it.**  
Carrier saturation does not bypass the SecurityManager in the sense of causing incorrect permission decisions. However, if all carrier threads are blocked, new virtual threads submitted to the scheduler are never mounted. Permission checks for those threads never fire — not because the checks are circumvented, but because the threads never reach the point of executing code. Any in-flight or queued work is frozen. This is a denial-of-service against the *availability* of the authorization machinery, not its *integrity*.

### 15.2 Can SecurityManager Checks Be Spoofed via Carrier Thread Context?

When a virtual thread mounts on a carrier thread, it runs on that carrier's OS thread. The `AccessControlContext` used by the virtual thread is the one captured at *creation* time: `AccessController.getContext()` called in `ThreadBuilders.java:260` (virtual thread builder `unstarted()`) and `279` (virtual thread factory `newThread()`). It is not the carrier thread's context.

Therefore: **No.** Carrier-thread saturation cannot cause a virtual thread to run with a different `AccessControlContext` than intended.

`VirtualThread` manages its own `inheritedAccessControlContext` field. This is set explicitly from the caller's context in `ThreadBuilders.newVirtualThread()` and is not overwritten by carrier assignment. When a permission check is triggered inside a virtual thread, `AccessController.getStackAccessControlContext()` (native) walks the *continuation stack* of the virtual thread — not the carrier's stack. The carrier's frames are not included. The untrusted caller's `ProtectionDomain` is therefore correctly intersected even when the virtual thread is executing on a carrier.

### 15.3 Scheduler Injection Risk

`Thread.ofVirtual()` exposes an internal-API hook `.scheduler(executor)` that allows a custom `Executor` to back a virtual thread's scheduling. A caller who has `createVirtualThread` permission and obtains a `VirtualThreadBuilder` reference could pass a custom scheduler that runs on a pool the caller controls. This could cause confusion in context management for threads on that custom scheduler. This is an advanced concern; in practice, the custom scheduler path requires explicit opt-in by the code constructing the virtual thread builder, and the builder checks `createVirtualThread` permission at construction regardless of scheduler choice (`ThreadBuilders.java:258–259, 276–277`).

---

## 16. How Current Guards Handle Virtual Thread and FFM Resource Exhaustion

### 16.1 Creation Gate: `RuntimePermission("createVirtualThread")`

The primary guard is the permission check at creation time. In `ThreadBuilders.java`:

```java
// Line 258–259 — VirtualThreadBuilder.unstarted():
SecurityManager sm = System.getSecurityManager();
if (sm != null) sm.checkPermission(new RuntimePermission("createVirtualThread"));

// Line 276–277 — VirtualThreadBuilder.factory():
SecurityManager sm = System.getSecurityManager();
if (sm != null) sm.checkPermission(new RuntimePermission("createVirtualThread"));
```

If untrusted code lacks `createVirtualThread`, it cannot create virtual threads at all. This is the correct and most effective defense: resource-exhaustion attacks require the resource to be *acquired* first. By denying acquisition, the attack is stopped before any carrier slot is consumed. `PROCESS_ISOLATION.md` (lines 56–80) frames this explicitly as the security contract:

> "The new permission checks prevent that thread from being created in the first place, which is the correct defence boundary."

### 16.2 What the Guards Cannot Do After Creation

The guards offer no runtime enforcement once a virtual thread is running:

| Threat | Guard Available? | Reason |
|--------|------------------|--------|
| Virtual thread entering `synchronized` and pinning carrier | None | Monitor acquisition is not SecurityManager-gated |
| Virtual thread in busy-loop consuming CPU | None | CPU consumption is not gated |
| Virtual thread causing `OutOfMemoryError` by allocating heap objects | None | Heap allocation is not gated |
| Virtual thread holding an open `Arena.ofConfined()` and blocking | None at runtime | FFM operations are gated at *acquisition*, not use |

### 16.3 Containment via Isolated ForkJoinPool

When creation cannot be denied, `PROCESS_ISOLATION.md` (lines 173–189) documents the available containment strategies:

| Strategy | What It Achieves | Limitation |
|----------|------------------|------------|
| Isolated `ForkJoinPool` for untrusted virtual threads | Saturation of that pool does not affect trusted scheduler pools | The stuck thread still consumes its carrier(s) within that pool |
| Bounded parallelism in the isolated pool | Limits the number of carriers that can be monopolised | Does not stop the thread; limits blast radius only |
| Deadline on the caller (`latch.await(timeout)`) | The caller moves on and treats the task as failed | The task thread keeps running, leaking a carrier slot |
| Watchdog that replaces the pool | A new pool can be created for fresh work | Old stuck threads remain alive until JVM exits |
| `Thread.join(Duration)` | Non-blocking wait with timeout | After timeout, the thread is still alive |

The recommended layered defence (`PROCESS_ISOLATION.md` lines 183–189):

1. **Prevention** — use `createVirtualThread` permission check to stop untrusted code from creating virtual threads at all.
2. **Containment** — if creation must be permitted, route untrusted work through a bounded, isolated `ForkJoinPool` with a caller-side deadline.
3. **Acceptance** — document that a stuck thread will consume its carrier slot until JVM exit, and size the isolated pool's parallelism accordingly.

### 16.4 FFM Resource-Exhaustion Guards

The FFM API presents distinct resource-exhaustion risk via off-heap memory allocation. All four `Arena` factory entry points are now gated in `Arena.java`:

| Arena | Guard | Source Line |
|-------|-------|-------------|
| `Arena.ofAuto()` | `NativeMemoryPermission("auto-arena")` | `Arena.java:230–232` |
| `Arena.global()` | `NativeMemoryPermission("global-arena")` | `Arena.java:247–249` |
| `Arena.ofConfined()` | `NativeMemoryPermission("confined-arena")` | `Arena.java:266–268` |
| `Arena.ofShared()` | `NativeMemoryPermission("shared-arena")` | `Arena.java:281–283` |

`AbstractMemorySegmentImpl.reinterpretInternal()` is separately gated by `NativeMemoryPermission("reinterpret-memory-segment")`.

The critical property (`SECURITY_ANALYSIS.md`): off-heap memory is not bounded by `-Xmx`. Exhausting native memory causes `OutOfMemoryError`, JVM process termination, or OS-level failure — all denial-of-service outcomes. The permission gate prevents unauthorized *acquisition*, but once acquired legitimately, the holding pattern is outside the security model's reach:

> "Long-lived leaked arenas: An `Arena.ofShared()` or `Arena.ofConfined()` created but never explicitly closed retains all allocated native memory until the arena itself becomes unreachable and is GC-finalized."

**Virtual thread + FFM interaction:** A virtual thread that holds an open `Arena.ofConfined()` and blocks on a `synchronized` monitor simultaneously causes both carrier-thread starvation (section 14.2) and native memory retention. The arena permission gate prevents unauthorized acquisition, but the double-resource-hold pattern is outside the security model's reach once both grants are held.

---

## 17. Process Isolation Decision Boundaries

### 17.1 Where SecurityManager Alone Is Sufficient

The following threats are fully blocked by the DirtyChai permission layer without requiring OS-level process isolation (`PROCESS_ISOLATION.md` lines 935–949):

| Threat | Guard | Notes |
|--------|-------|-------|
| Unauthorized virtual thread creation | `RuntimePermission("createVirtualThread")` at `ThreadBuilders.java:258–259, 276–277` | `VirtualThread` has no public constructor; builder is the only creation path |
| Unauthorized platform thread creation | `RuntimePermission("createPlatformThread")` at `ThreadBuilders.java:184–185, 206–207` and `Thread.java:765–768` | Both builder path and all public `Thread(...)` constructors covered |
| Reflection-based custom SecurityManager installation | `@CallerSensitive` + `StackWalker` scan in `System.setSecurityManager()` | All known reflection/proxy/lambda bypass vectors blocked |
| Unauthorized native library load | `RuntimePermission("loadLibrary.*")` via `SecurityManager.checkLink()` | `Runtime.load0()` / `loadLibrary0()` |
| Unauthorized native symbol resolution | `NativeInvocationPermission(libName)` at `ClassLoader.findNative()`, `SymbolLookup`, `SystemLookup` | Two independent gates |
| Unauthorized deserialization of arbitrary classes | `SerialObjectPermission(className)` at `ObjectInputStream.readOrdinaryObject()` | Gadget chains blocked before object instantiation |
| Unauthorized class loading | `LoadClassPermission` at `SecureClassLoader.defineClass()` | Guards URL-based class loading |
| Unauthorized dynamic class definition | `DefineClassPermission` at `MethodHandles.Lookup.defineClass()` | Guards Lookup-based runtime class injection |
| Unauthorized off-heap memory allocation | `NativeMemoryPermission(arenaType)` at all four `Arena` factories | Off-heap DoS prevention |
| Unauthorized memory segment reinterpretation | `NativeMemoryPermission("reinterpret-memory-segment")` | Memory confusion prevention |
| Untrusted `<clinit>` loading trusted classes | Untrusted `ProtectionDomain` on stack; intersection enforced | Policy must not grant AllPermission to untrusted PDs |
| Untrusted code triggering `invokedynamic` bootstrap | Untrusted PD on stack; intersection enforced | Same as above |
| Unauthorized runtime attach | `AttachPermission("attachVirtualMachine")` in attach provider path | When SecurityManager policy denies attach |
| Supply-chain content-substitution / dependency-confusion | `digest "SHA-256:…"` policy selector → `DigestGrant` at `ConcurrentPolicyFile` + `SecureClassLoader.getProtectionDomain()` auto-promotion (PR #203) | `SecureClassLoader` downloads the artifact and promotes the plain `CodeSource` to `DigestCodeSource` (SHA-256); `DigestGrant.implies()` requires exact `Arrays.equals` match on digest bytes; a plain `CodeSource` always implies `false` regardless of URL |

### 17.2 Where Process Isolation Is Required

The following residual gaps cannot be fully closed in-process regardless of DirtyChai's guards (`PROCESS_ISOLATION.md` lines 964–975):

| Residual Gap | Why In-Process Guards Are Insufficient |
|--------------|----------------------------------------|
| Virtual thread carrier saturation by `synchronized`-pinned threads — after `createVirtualThread` is granted | Permission checks fire at *creation*, not at `synchronized` entry; JVM has no mechanism to forcibly unpin or terminate a running virtual thread |
| Finalizer / Cleaner context escape — no PoLP deployed | Without PoLP, class-level grants are unconstrained; `neverPrivileged` alone cannot prevent unrestricted `doPrivileged` escalation |
| JVMTI / `-agentlib:` attached at JVM startup | JVMTI agents load before the SecurityManager is installed and can bypass all Java-level checks |
| JNI `CallXxxMethod` re-entrant callbacks from within native code | Re-entrant JNI calls do not pass through Java-side SecurityManager permission checks |
| Shared-memory side-channel attacks (Spectre-class) | Require hardware-level isolation (separate physical cores or memory flushing) |
| Unrestricted `doPrivileged` in trusted code reachable from untrusted code | DirtyChai cannot prevent a trusted class from calling unrestricted `doPrivileged` on a path that untrusted code can reach |

### 17.3 Operator Checklist for Mixed-Trust Deployments

(Reproduced from `PROCESS_ISOLATION.md` operator checklist for convenience)

- Every trusted class callable from untrusted code **must not** use unrestricted `AccessController.doPrivileged(...)` on paths that lead to native calls, sensitive I/O, or class loading.
- Trusted classes must not perform sensitive operations in `finalize()` or `Cleaner` callbacks that should be restricted by the creator's `AccessControlContext`.
- `<clinit>` blocks in trusted classes must not use unrestricted `doPrivileged` to initialize security-sensitive resources.
- For code whose trust level is not fully established, use process isolation (Phoenix activation groups or containers).
- If `createVirtualThread` must be granted to partially-trusted code, route that code's threads through a bounded, isolated `ForkJoinPool` with a caller-side deadline (containment strategy, section 16.3).

---

## 18. Related Documents

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

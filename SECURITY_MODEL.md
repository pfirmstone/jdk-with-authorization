# Dirty Chai - OpenJDK Authorization Security Model: Comprehensive Architecture

**Version:** 1.5  
**Date:** 2026 (Updated April 13, 2026 — Issue #85)  
**Project:** Dirty Chai - OpenJDK with Authorization  
**Repository:** https://github.com/pfirmstone/dirty-chai  
**Base:** https://github.com/openjdk/jdk (trunk)  
**License:** GPL v2 + Classpath Exception

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Project Overview](#project-overview)
3. [Quick Start](#quick-start)
4. [Core Security Architecture](#core-security-architecture)
5. [Design Patterns](#design-patterns)
6. [ContextCache: Weak Reference Optimization for Virtual Threads](#contextcache-weak-reference-optimization-for-virtual-threads)
7. [Authentication & Authorization Framework](#authentication--authorization-framework)
8. [SecureClassLoader Enhancement](#secureclassloader-enhancement)
9. [Virtual Thread Support](#virtual-thread-support)
10. [Subject Context Management](#subject-context-management)
11. [AccessController Integration](#accesscontroller-integration)
12. [AccessControlContext Boundaries](#accesscontrolcontext-boundaries)
13. [Backward Compatibility](#backward-compatibility)
14. [Threat Model & Prevention](#threat-model--prevention)
15. [Configuration & Deployment](#configuration--deployment)
16. [Security Properties](#security-properties)
17. [Implementation Guidelines](#implementation-guidelines)
18. [Performance & Scalability](#performance--scalability)
19. [API Reference](#api-reference)
20. [Troubleshooting](#troubleshooting)
21. [References](#references)
22. [API Stability Contract & Multi-Release JAR Strategy](#api-stability-contract--multi-release-jar-strategy)
23. [Conclusion](#conclusion)

---

## Executive Summary

> **In plain English:** While the standard JDK SecurityManager can enforce policy-based access control, it does not prevent loading of untrusted code. Dirty Chai provides the infrastructure for optional principal-authenticated and code signer verified class loading, to ensure only trusted code is loaded by the VM. The policy file determines how strictly authentication is enforced.

**Dirty Chai** is a comprehensive authorization framework for OpenJDK that implements a **multi-layered security architecture** enforcing the **Principle of Least Privilege (PoLP)** through:

- **Optional Principal-Authenticated Signed Code Loading:** Infrastructure enabling policy-configured Subject context and CodeSigner requirements;
- **Transitive Dependency Lockdown:** Each dependency independently validated; no trust transfer
- **Platform Module Authorization:** Even standard OpenJDK modules require explicit policy grants
- **Virtual Thread Integration:** AccessControlContext inherited immutably; PrivilegedActions fully supported
- **Unified Subject Context:** Subject.callAs() always delegates to Subject.doAs() in Dirty Chai system (allowSecurityManager = true)
- **AccessController Stack Walk:** Native stack walking compatible with virtual threads
- **Essential Authorization APIs:** `Subject.doAs()`, `Subject.doAsPrivileged()`, and `AccessControlContext` retained and fully operational as first-class APIs; not deprecated in Dirty Chai
- **Fail-Secure Design:** All validation failures result in SecurityException; no silent bypasses
- **Non-Blocking Performance:** Lock-free caching with concurrent validation

### Key Security Properties

| Property | Implementation | Guarantee | Why It Matters |
|----------|----------------|-----------|----------------|
| **Fail-Secure** | Exceptions on ALL validation failures | Untrusted code cannot enter JVM | No silent permission grants on error |
| **Principle of Least Privilege** | Independent permission evaluation per dependency | No privilege escalation through chains | Limits blast radius of a compromised component |
| **Authentication** | Policy-configured Subject validation (grants with principals enforce; grants without principals allow unauthenticated) | Administrator-controlled through policy grants | Enables flexible enforcement from optional to mandatory per codebase |
| **Principal-Based Authorization** | Policy grants require (Principal, CodeSource) match | Code alone insufficient; users alone insufficient | Prevents stolen JARs from gaining access |
| **No Trust Transfer** | Each dependency re-validated independently | Transitive dependencies cannot escalate privileges | Evil transitive dependency cannot piggyback on trusted lib |
| **Virtual Thread Compatible** | AccessControlContext + StackWalk | Security context maintained across mounts/unmounts | 1M+ concurrent threads remain fully governed |
| **Subject Management** | callAs() always delegates to doAs() via SecurityManager | Unified access control model | Single predictable code path; no bypass routes |
| **Essential Authorization APIs** | `Subject.doAs()`, `Subject.doAsPrivileged()`, and `AccessControlContext` retained as first-class APIs; not deprecated | Existing code works without modification; `doAsPrivileged(s, a, null)` unique explicit-context capability preserved | No vanilla OpenJDK replacement exists for `doAsPrivileged` null-context use case |
| **Non-Blocking Performance** | ConcurrentHashMap with lock-free reads | High-concurrency throughput maintained | Security does not become the bottleneck |

---

## Project Overview

### What is Dirty Chai?

**Dirty Chai** enhances OpenJDK with rigorous code validation and principal-authenticated CodeSigner class loading, ensuring that every piece of code (whether "clean" from trusted sources or "dirty" from untrusted origins) undergoes comprehensive security validation.

### Design Philosophy

```
"Rigorous validation for every drop of code"
```

Like steeping tea (chai), security flows through multiple layers:
1. **Initial Validation** - CodeSource integrity checks
2. **Authentication Layer** - Subject context verification
3. **Authorization Layer** - Permission policy evaluation
4. **Protection Layer** - Domain creation with principals
5. **Cache Integrity** - Principal-based validation on reuse

### Why OpenJDK?

- ✅ Open source (GPL v2 + Classpath Exception)
- ✅ No TCK restrictions - full modification rights
- ✅ Active upstream community
- ✅ Virtual thread support (Project Loom)
- ✅ ScopedValue integration
- ✅ Perfect foundation for authorization enhancements

### Use Cases

- **Multi-tenant platforms** - Enforce per-tenant code isolation
- **Microservices** - Principal-based service-to-service authentication
- **Plugin systems** - Validate plugins before execution
- **Compliance-heavy environments** - Audit trails and permission enforcement
- **Virtual thread workloads** - Security context propagation across 1M+ concurrent tasks

---

## Quick Start

> **Three steps to enable Dirty Chai security in your application.**

### Step 1 — Install the Security Manager

Add to your JVM launch flags:

```bash
java -Djava.security.manager=default \
     -Djava.security.policy==/path/to/app.policy \
     com.example.Main
```

### Step 2 — Define a Minimal Policy File (`app.policy`)

```
// Grant your application code permission to load classes
grant signedBy "app-cert",
      codeBase "https://company.com/app.jar",
      principal javax.security.auth.x500.X500Principal "CN=Developer,O=Company" {
    permission au.zeus.jdk.authorization.guards.LoadClassPermission "ALLOW";
    permission java.io.FilePermission "/var/app/data/*", "read,write";
};
```

### Step 3 — Wrap Application Code in an Authenticated Subject

```java
// Authenticate the user
LoginContext lc = new LoginContext("MyApp", new SimpleCallbackHandler(username, password));
lc.login();
Subject subject = lc.getSubject();

// Run application inside authenticated context (policy requires this when grants specify principals)
Subject.callAs(subject, () -> {
    // All class loading and privileged operations happen here
    return MyApplication.run();
});
```

### Before vs. After Dirty Chai

| Scenario | Without Dirty Chai | With Dirty Chai |
|----------|--------------------|-----------------|
| Untrusted JAR loads | Loads silently | `SecurityException` thrown |
| Anonymous code execution | Allowed | Blocked when policy grants require principals (policy-driven) |
| Transitive dependency privilege | Inherits caller's trust | Re-validated independently |
| Virtual thread context | No propagation guarantee | consistent context |
| Policy violation | May silently succeed | `SecurityException` always |

### Common Pitfalls

| Mistake | Symptom | Fix |
|---------|---------|-----|
| Missing `LoadClassPermission` in policy | `SecurityException: Permission denied` on every class load | Add `LoadClassPermission "ALLOW"` to the grant block |
| Loading classes outside `Subject.callAs()` | `SecurityException: Code loading requires authenticated Subject` | Wrap the application *entry point* in `Subject.callAs()`—class loading is automatic from there |
| Using a frozen (read-only) Subject | `SecurityException: Subject must remain mutable` | Don't call `Subject.setReadOnly()` before class loading completes |
| Policy file not found | `SecurityException: Unable to locate policy` | Pass `-Djava.security.policy=` with an absolute path |
| Reflection bypasses security | `SecurityException: Reflection detected in stack` | Use direct method calls or `AccessController.doPrivileged()` |

---

## Core Security Architecture

### 1. Security Validation Layers (with Subject Integration)

```
┌─────────────────────────────────────────────────────────────┐
│ APPLICATION CODE ATTEMPT                                    │
│ Subject.callAs(subject, () -> {                             │
│    classLoader.defineClass(name, bytes, codeSource)         │
│ })                                                          │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│ SUBJECT CONTEXT ACTIVATION                                  │
│ • callAs() detected                                         │
│ • allowSecurityManager() → TRUE ✅ (Dirty Chai system)      │
│ • Delegates to doAs()                                       │
│ • Creates AccessControlContext with SubjectDomainCombiner   │
│ • Subject.current() will return subject                     │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│ LAYER 1: CodeSource Validation                              │
│ • Check: CodeSource is not null                             │
│ • Action: Validate URL format and certificates              │
│ • Fail: return null or throw SecurityException              │
│ • Result: Prevents loading without source information       │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│ LAYER 2: Subject Authentication                             │
│ • Check: Subject.current() is non-null ✅ (from doAs)       │
│ • Check: Subject has authenticated principals               │
│ • Check: Subject is mutable (auth in progress)              │
│ • Fail: throw SecurityException                             │
│ • Result: Only authenticated contexts can load classes      │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│ LAYER 3: LoadClassPermission Check                          │
│ • Check: Policy grants LoadClassPermission for pair         │
│ • Context: (Principal, CodeSource) combination              │
│ • Fail: throw SecurityException (permission denied)         │
│ • Result: Authorization based on identity + code source     │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│ LAYER 4: Protection Domain Creation                         │
│ • Create: ProtectionDomain with authenticated principals    │
│ • Include: Principals from Subject context ✅ (via ACC)     │
│ • Evaluate: Independent permissions for this code source    │
│ • Result: Each class has principal-bound permissions        │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│ LAYER 5: Cache Integrity (on reuse)                         │
│ • Check: Cached domain has principals                       │
│ • Validate: Current context matches cached context          │
│ • Fail: Fall through to full re-validation                  │
│ • Result: Prevents cache poisoning attacks                  │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│ CLASS LOADED ✅                                             │
│ • ProtectionDomain attached to class                        │
│ • Permissions bound to authenticated principals             │
│ • Subject context active throughout execution               │
│ • Ready for permission checks during execution              │
└─────────────────────────────────────────────────────────────┘
```

### 2. Trust Boundary Model

```
TRUSTED EXECUTION CONTEXT
┌──────────────────────────────────────────────────────┐
│ INSIDE: Classes with ProtectionDomains               │
│ • Signed code sources                                │
│ • Authenticated subjects                             │
│ • Principal-verified permissions                     │
│ • Limited to PoLP-scoped capabilities                │
│                                                      │
│ • Can access: Only granted resources                 │
│ • Cannot access: Ungrantted resources                │
│ • Cannot load: Untrusted dependencies                │
└──────────────────────────────────────────────────────┘
                    ↑
        DIRTY CHAI SECURECLASSLOADER GATES
                    ↓
┌──────────────────────────────────────────────────────┐
│ OUTSIDE: Untrusted Code (BLOCKED)                    │
│ • Unsigned code sources                              │
│ • No authentication context                          │
│ • Null principals                                    │
│ • Policy denial                                      │
│                                                      │
│ CANNOT: Enter execution context                      │
│ • SecurityException thrown                           │
│ • Class never defined                                │
│ • Memory protection maintained                       │
└──────────────────────────────────────────────────────┘
```

---

## Design Patterns

### 1. Decorator Pattern

**Implementation:** `SecureClassLoader extends ClassLoader`

**Purpose:** Add security capabilities to OpenJDK's base `ClassLoader` without modifying core class loading behavior

**Benefits:**
- Security concerns isolated from core functionality
- Extensibility through `getPermissions()` override
- Backward compatibility with existing `ClassLoader` API

---

### 2. Template Method Pattern

**Implementation:**
```
protected PermissionCollection<Permission> getPermissions(CodeSource codesource) {
    return new Permissions(); // Hook for subclasses
}
```

**Purpose:** Define skeleton in `defineClass()`, defer permission binding to subclasses

**Usage:** Subclasses override `getPermissions()` for custom permission models

---

### 3. Concurrent Cache Pattern

**Implementation:** `ConcurrentHashMap<CodeSourceKey, ProtectionDomain>`

**Characteristics:**
- Thread-safe, non-blocking reads in normal case
- Lazy initialization on cache miss
- `putIfAbsent()` for atomic updates
- Harmless race condition (same ProtectionDomain computed multiple times)

**Benefits:**
- Lock-free performance in high-concurrency scenarios
- No writer locks on cache operations
- Scalability maintained

---

### 4. Key Object Pattern

**Implementation:** `CodeSourceKey` record

**Purpose:** Avoid expensive DNS lookups during cache operations

**Features:**
```
private record CodeSourceKey(CodeSource cs) {
    @Override
    public int hashCode() {
        return Objects.hashCode(cs.getLocationNoFragString());
    }
    
    @Override
    public boolean equals(Object obj) {
        return Objects.equals(cs.getLocationNoFragString(), 
                            other.cs.getLocationNoFragString())
            && cs.matchCerts(other.cs, true);
    }
}
```

- Uses `String` instead of URL (no DNS)
- Fragment-safe comparison (RFC 3986 compliant)
- Certificate-aware matching
- Canonical cache keys

---

### 5. Lazy Initialization Pattern

**Implementation:** `DebugHolder` static class

```
private static class DebugHolder {
    private static final Debug debug = Debug.getInstance("scl");
}
```

**Purpose:** Debug overhead only when requested

**Benefits:** No performance penalty if debugging disabled

---

## ContextCache: Weak Reference Optimization for Virtual Threads

### Overview

`ContextCache` solves a critical performance problem for virtual thread workloads: without caching, each thread would allocate its own `AccessControlContext` instance even when millions of threads share identical security state. With caching, **one `AccessControlContext` instance can be shared by 1,000,000+ virtual threads simultaneously**, reducing memory from ~512 MB to ~512 bytes for homogeneous workloads.

---

### 1. Shared Context Model

**Key Insight:** `AccessControlContext` is immutable. Threads with identical security state (same `ProtectionDomain` array, same `DomainCombiner`, same privilege flag, same `privilegedContext`) can safely share a single cached instance.

```
Single authenticated user (CN=Alice) spawning 1,000,000 virtual tasks:

AccessControlContext.build(domains, privilegedContext, combiner, false)
        │
        ├─ ContextKey created from parameters
        ├─ CONTEXTS.get(key) → returns contextA (cached)
        │
        ├─→ VirtualThread 1          → contextA ✅ (same instance)
        ├─→ VirtualThread 2          → contextA ✅ (same instance)
        ├─→ VirtualThread 3          → contextA ✅ (same instance)
        │             ...
        └─→ VirtualThread 1,000,000  → contextA ✅ (same instance)

Result:
  - 1,000,000 virtual threads
  - 1 AccessControlContext instance
  - Memory: ~512 bytes (one instance shared by all)
  - Zero duplication
```

The `build()` method is the single creation point:

```java
static AccessControlContext build(ProtectionDomain[] context,
                                  AccessControlContext privilegedContext,
                                  DomainCombiner combiner,
                                  boolean isPrivileged) {
    if (CONTEXTS != null) {
        ContextKey key = new ContextKey(context, privilegedContext,
                                        combiner, isPrivileged);
        AccessControlContext acc = CONTEXTS.get(key);   // lock-free read
        if (acc == null) {
            acc = new AccessControlContext(context, privilegedContext,
                                          combiner, isPrivileged);
            AccessControlContext existed = CONTEXTS.putIfAbsent(key, acc);
            if (existed != null) return existed;        // another thread won
        }
        return acc;                                     // cached instance
    } else {
        return new AccessControlContext(context, privilegedContext,
                                        combiner, isPrivileged);
    }
}
```

---

### 2. Weak Reference Strategy

`ContextCache` is initialised with a reference-aware concurrent map provided by the `au.zeus.jdk.concurrent.RC` framework:

```java
ConcurrentMap<AccessControlContext.ContextKey, AccessControlContext> CONTEXTS
    = RC.concurrentMap(
        new ConcurrentSkipListMap<>(),
        Ref.STRONG,   // keys (ContextKey) — held with strong references
        Ref.WEAK,     // values (AccessControlContext) — held with weak references
        2000L,        // key cleanup cycle: 2000 ms
        2000L         // value cleanup cycle: 2000 ms
    );
```

**Reference semantics:**

| Element | Reference Type | Consequence |
|---------|---------------|-------------|
| `ContextKey` (map key) | **STRONG** | Key is never GC'd while the cache exists; used for all future lookups |
| `AccessControlContext` (map value) | **WEAK** | Eligible for GC when no thread holds a strong reference |

**Why STRONG keys / WEAK values?**

- STRONG keys ensure that lookup (`CONTEXTS.get(key)`) always finds existing entries as long as the cache is alive — the key cannot disappear mid-lookup.
- WEAK values allow the GC to reclaim `AccessControlContext` instances that are no longer referenced by any thread. When all threads finish and release their reference, the context is freed automatically.
- A cleanup task runs every 2000 ms to remove stale key–value pairs whose weak value has been collected, preventing indefinite key accumulation.

> **Note (from implementation comments):** A weakly referenced value causes collection of the key–value tuple. If there are contexts with identical hash, only one will be collected at a time.

---

### 3. Memory Impact

The memory benefit is proportional to how many threads share identical security state.

**Without caching (or with strong references):**

| Scenario | Instances | Memory |
|----------|-----------|--------|
| 1,000 virtual threads, unique contexts | 1,000 | ~512 KB |
| 1,000,000 virtual threads, unique contexts | 1,000,000 | **~512 MB** |

**With weak-reference caching and context sharing:**

| Scenario | Cached Instances | Memory | Threads Sharing |
|----------|-----------------|--------|-----------------|
| 1,000 virtual threads, 1 shared context | **1** | **~512 bytes** | 1,000 |
| 1,000,000 virtual threads, 1 shared context | **1** | **~512 bytes** | 1,000,000 |
| 1,000,000 threads, 1,000 unique contexts | **1,000** | **~512 KB** | 1,000 per context |

**Quantified example — fan-out pattern:**

```
Without context sharing:
  1,000,000 tasks × 512 bytes/ACC = 512,000,000 bytes ≈ 512 MB
  + GC pressure from 1M short-lived objects

With ContextCache (1 shared context):
  1 ACC × 512 bytes             = 512 bytes            ≈ 512 B
  Memory saved: 512 MB → 512 B  = 1,000,000× reduction
```

---

### 4. Virtual Thread Integration

All virtual tasks that inherit the same security context from a parent scope automatically resolve to the same cached `AccessControlContext` instance. This is the common case for:

- **Fan-out patterns** — one authenticated request spawns many subtasks, all operating under the same user context.
- **Thread pools / executors** — a `StructuredTaskScope` or `ExecutorService` configured with a fixed security context propagates that same context to every submitted task.
- **ScopedValue propagation** — when a `ScopedValue` binding carries an `AccessControlContext`, all child tasks within the scope receive the same strong reference to the cached instance, keeping it alive until the scope closes.

```
Authenticated request (CN=Alice) with StructuredTaskScope:

try (var scope = StructuredTaskScope.open()) {
    // All forked subtasks inherit Alice's AccessControlContext
    for (int i = 0; i < 1_000_000; i++) {
        scope.fork(() -> processItem(...));  // each subtask → same ACC
    }
    scope.join();
}
// Scope closes → strong references released → ACC eligible for GC
```

While any one of those 1,000,000 virtual threads holds the instance, the weak reference in the cache is kept alive by that strong reference. The cache entry remains valid for the duration of the scope.

---

### 5. Thread Safety and Lock-Free Cache Reads

**Cache reads are completely lock-free.** The underlying `ConcurrentSkipListMap` provides non-blocking reads that scale linearly with CPU count:

```
Cache hit path (common case):
  Thread N calls build(context, ...) 
    → ContextKey created (cheap hash + set construction)
    → CONTEXTS.get(key)          ← lock-free, O(log n) ConcurrentSkipListMap
    → returns cached ACC immediately
    → no allocation, no synchronisation
```

**Race condition handling on cache miss:**

When two threads simultaneously discover a cache miss and both try to insert:

```
Thread A                              Thread B
────────────────────────────────────  ──────────────────────────────────────
CONTEXTS.get(key) → null              CONTEXTS.get(key) → null
acc_A = new AccessControlContext(...) acc_B = new AccessControlContext(...)
existed = putIfAbsent(key, acc_A)     existed = putIfAbsent(key, acc_B)
  → existed == null (A won)             → existed == acc_A (A won)
return acc_A ✅                       return acc_A ✅ (B discards acc_B)
```

Both threads return the **same instance** (`acc_A`). Thread B's newly created object (`acc_B`) is immediately eligible for GC. This is a **safe, harmless race**: both threads receive a functionally identical, correct `AccessControlContext`.

**Non-blocking is an explicit requirement** — as documented in the implementation comments: *"Non-blocking is a requirement."*

---

### 6. Real-World Patterns

#### Multi-Tenant Application

Different tenants have different principals, so each gets a distinct cached context:

```
Tenant A (CN=Alice):   1 ACC instance → shared by all of Alice's 500,000 threads
Tenant B (CN=Bob):     1 ACC instance → shared by all of Bob's 300,000 threads
Tenant C (CN=Carol):   1 ACC instance → shared by all of Carol's 200,000 threads

Total: 3 ACC instances for 1,000,000 threads (~1.5 KB vs ~512 MB without caching)
```

#### Fan-Out / MapReduce Pattern

```
Coordinator thread (ACC = workerContext):
  ├─ spawn 1,000,000 worker tasks, each calling:
  │     AccessControlContext.build(workerDomains, null, null, false)
  │     → all return the same cached workerContext
  └─ all workers execute with identical permissions, zero extra allocation
```

#### Multiple Principal Sets

When users have different role combinations, each unique combination maps to one cached instance:

```
{ROLE_USER}            → 1 ACC, shared by 400,000 threads
{ROLE_USER, ROLE_ADMIN}→ 1 ACC, shared by 50,000 threads
{ROLE_USER, ROLE_AUDIT}→ 1 ACC, shared by 10,000 threads
```

---

### 7. Cache Lifecycle

The lifecycle of a cached `AccessControlContext` entry follows these stages:

```
Stage 1 — Cache Miss (first request for this context):
  build() called with parameters P
  ContextKey K created from P
  CONTEXTS.get(K) returns null
  New ACC created and stored: CONTEXTS.putIfAbsent(K, ACC)
  K held by STRONG reference in map
  ACC held by WEAK reference in map

Stage 2 — Active Use (threads referencing the context):
  N virtual threads each hold a STRONG reference to ACC
  Weak reference in CONTEXTS is kept alive by those strong references
  CONTEXTS.get(K) returns ACC immediately (lock-free)
  All N threads share the single ACC instance

Stage 3 — Cache Hit (subsequent requests):
  Any call to build() with same parameters P
  ContextKey K' created (functionally equal to K)
  CONTEXTS.get(K') returns ACC directly
  No new ACC created

Stage 4 — Release (threads finish, drop strong references):
  All virtual threads complete and release their ACC reference
  Only the weak reference in CONTEXTS remains
  GC marks ACC as eligible for collection

Stage 5 — Garbage Collection:
  GC collects ACC
  Weak reference in CONTEXTS is cleared (nulled by GC)

Stage 6 — Cleanup (every 2000 ms):
  Background cleanup task scans CONTEXTS
  Entries with null weak values (stale K→null pairs) are removed
  Key K is released; ContextKey object is GC-eligible

Stage 7 — Re-entry (if context is needed again):
  build() called again with same parameters P
  CONTEXTS.get(K') returns null (entry was removed)
  New ACC created and cached (returns to Stage 1)
```

---

### 8. Performance Characteristics

**Cache hit vs. individual context creation:**

| Operation | Time | Notes |
|-----------|------|-------|
| Cache hit (lock-free read) | ~0.2 µs | `ConcurrentSkipListMap.get()`, no allocation |
| Cache miss (new context) | ~5 µs | Allocates `ContextKey` + `AccessControlContext`, one `putIfAbsent` |
| **Speedup (hit vs. miss)** | **~25×** | |

**Scaling with virtual thread count:**

| Threads | Without Cache | With Cache (1 shared context) | Improvement |
|---------|---------------|-------------------------------|-------------|
| 1,000 | 5 ms + 512 KB | 5 µs + 512 B | ~1,000× |
| 100,000 | 500 ms + 51 MB | 5 µs + 512 B | ~100,000× |
| 1,000,000 | 5,000 ms + 512 MB | 5 µs + 512 B | ~1,000,000× |

> *Times are first-creation costs. Subsequent lookups benefit from OS-level caching of the `ConcurrentSkipListMap` nodes.*

**GC pressure reduction:** Avoiding allocation of 1,000,000 `AccessControlContext` objects per request cycle eliminates a major source of short-lived heap objects, directly reducing GC pause frequency and duration.

---

### 9. Safety Guarantees

**Why weak references are safe and maintain correctness:**

1. **Immutability** — `AccessControlContext` is fully immutable (`final` fields, defensive copies of `ProtectionDomain[]`). Any number of threads can safely read the same instance concurrently without synchronisation.

2. **Reference liveness** — While any thread holds a strong reference to an `AccessControlContext`, the GC cannot collect it. The weak reference in the cache is kept alive by those strong references. Correctness is never compromised: a thread always holds a strong reference for the duration it needs the context.

3. **Transparent recreation** — If an `AccessControlContext` is GC'd between uses, `build()` recreates a functionally identical instance on the next call. The recreated instance is semantically equivalent because `ContextKey.equals()` is based on the value of the domains, combiner, and privilege flag — not object identity.

4. **Race safety** — Even if two threads simultaneously recreate the same context after a GC event, `putIfAbsent()` ensures only one instance wins and both threads use the winner. No thread ever operates on an inconsistent context.

5. **No false positives** — The `ContextKey` uses value-based equality (`Set<ProtectionDomain>` comparison, `Objects.equals()` for combiner and privilegedContext). Two keys are equal only when the contexts they represent are genuinely equivalent, preventing any security boundary confusion between different contexts that happen to have the same hash.

---

### 10. ContextCache Implementation Reference

**Class:** `java.security.ContextCache`  
**Initialised by:** VM at completion of VM init phase 2 (before application code runs)  
**Backing map:** `ConcurrentSkipListMap` (non-blocking, sorted, O(log n) operations)  
**Key reference:** `Ref.STRONG` — `ContextKey` instances are never GC'd while cache is alive  
**Value reference:** `Ref.WEAK` — `AccessControlContext` instances freed automatically  
**Cleanup cycle:** Every 2000 ms (both key and value cycles)

```java
// ContextCache static initialiser (actual implementation)
static {
    ConcurrentMap<AccessControlContext.ContextKey, AccessControlContext> CONTEXTS
        = RC.concurrentMap(
            new ConcurrentSkipListMap<>(),
            Ref.STRONG,   // ContextKey — strong reference
            Ref.WEAK,     // AccessControlContext — weak reference
            2000L,        // key GC cleanup interval (ms)
            2000L         // value GC cleanup interval (ms)
          );
    AccessControlContext.initCache(CONTEXTS);
}
```

**Cache key class:** `AccessControlContext.ContextKey`

```java
static class ContextKey implements Comparable<ContextKey> {
    private final Set<ProtectionDomain> context;      // domains (value-based)
    private final AccessControlContext privilegedContext;
    private final DomainCombiner combiner;
    private final boolean isPrivileged;
    private final int hashCode;                       // pre-computed

    // equals() uses value semantics — not object identity
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || hashCode() != o.hashCode()) return false;
        if (o instanceof ContextKey that) {
            if (this.isPrivileged != that.isPrivileged) return false;
            if (!Objects.equals(this.combiner, that.combiner)) return false;
            if (!Objects.equals(this.context, that.context)) return false;
            return Objects.equals(this.privilegedContext, that.privilegedContext);
        }
        return false;
    }
}
```

---

## Authentication & Authorization Framework

### 1. Subject-Based Authentication

**Model:** Authenticated principals encapsulated in `Subject`

```
Login Process:
  1. User credentials provided
  2. LoginModule authenticates
  3. Subject populated with Principal(s)
  4. Subject sealed (read-only during execution)
  
Execution Process:
  Subject.callAs(authenticatedSubject, () -> {
      // Code runs with subject context
      // All class loads validated against principals
      return application.run();
  });
  
  // OR legacy API (fully backward compatible):
  Subject.doAs(authenticatedSubject, new PrivilegedAction<Void>() {
      @Override
      public Void run() {
          // Same security context as callAs()
          return null;
      }
  });
```

**Principal Types:**
- `X500Principal` (X.509 certificates, DN-based)
- Custom principals (application-specific roles)
- Multiple principals per Subject (AND semantics)

---

### 2. Authorization Policy Model

**Structure:** (Principal, CodeSource) → Permissions

```
grant principal javax.security.auth.x500.X500Principal "CN=Developer,O=Company"
      codeBase "https://trusted.com/app.jar" {
    permission java.io.FilePermission "/data/*", "read,write";
    permission java.net.SocketPermission "localhost:8080", "listen";
};
```

**Semantics:**
- Both principal AND codebase must match
- Neither alone is sufficient
- Explicit grants only (default-deny)
- Transitive dependencies require separate grants

---

### 3. System.setSecurityManager() Validation

**Conditional Validation Strategy:**

#### **Trusted Implementations (SecurityManager, CombinerSecurityManager)**
- Minimal validation (null check only)
- Rationale: Loaded via bootstrap classloader from java.base
- Permissions controlled through policy files

#### **Custom Implementations**
- Four-layer validation:

| Layer | Check | Purpose |
|-------|-------|---------|
| **1** | Direct Caller | Uses `Reflection.getCallerClass()` |
| **2** | Stack Inspection | StackWalker examines 10 frames for reflection/generated code |
| **3** | Protection Domain | Validates caller's domain is non-null |
| **4** | Generated Code Detection | Blocks lambda, method accessors, proxies |

**Attacks Prevented:**
- Reflection API (`Method.invoke()`, `Constructor.newInstance()`)
- MethodHandles invocation (`invoke()`, `invokeExact()`)
- LambdaMetafactory-generated code
- Dynamic proxies (`Proxy.newProxyInstance()`)
- Generated accessors (`GeneratedMethodAccessor*`)

---

## SecureClassLoader Enhancement

### 1. Core Validation Workflow

```
@SuppressWarnings("removal")
private ProtectionDomain getProtectionDomain(CodeSource cs) {
    // Layer 1: CodeSource validation
    if (cs == null) {
        return null;
    }

    // Cache lookup
    CodeSourceKey key = new CodeSourceKey(cs);
    ProtectionDomain domain = pdcache.get(key);
    if (domain != null) {
        // Layer 5: Validate cached domain has principals
        Principal[] cachedPrincipals = domain.getPrincipals();
        if (cachedPrincipals == null || cachedPrincipals.length == 0) {
            // Fall through to full validation
        } else {
            return domain;
        }
    }

    // Layer 2: Subject authentication
    Subject currentSubject = Subject.current();
    if (currentSubject == null) {
        throw new SecurityException(
            "Code loading requires authenticated Subject context. " +
            "Use Subject.callAs() to establish authentication. " +
            "CodeSource: " + cs.getLocation());
    }

    if (currentSubject.isReadOnly()) {
        throw new SecurityException(
            "Cannot load classes with read-only Subject. " +
            "Subject must remain mutable during authentication: " + cs);
    }

    @SuppressWarnings("unchecked")
    Set<Principal> principals = currentSubject.getPrincipals();
    if (principals == null || principals.isEmpty()) {
        throw new SecurityException(
            "Subject has no authenticated principals. " +
            "Authentication must establish at least one principal. " +
            "CodeSource: " + cs);
    }

    // Debug logging
    if (DebugHolder.debug != null) {
        DebugHolder.debug.println("Class loading with " + 
            principals.size() + " authenticated principal(s)");
        for (Principal p : principals) {
            DebugHolder.debug.println("  - " + p.getClass().getSimpleName() + 
                ": " + p.getName());
        }
    }

    // Layer 4: Create ProtectionDomain with principals
    PermissionCollection<Permission> perms
            = SecureClassLoader.this.getPermissions(key.cs);
    Principal[] principalArray = principals.toArray(new Principal[0]);
    ProtectionDomain pd = new ProtectionDomain(
            key.cs,
            perms,
            SecureClassLoader.this,
            principalArray);  // Include authenticated principals

    // Layer 3: LoadClassPermission check
    SecurityManager sm = System.getSecurityManager();
    if (sm != null) {
        sm.checkPermission(LOAD_CLASS_ALLOW,
                AccessControlContext.build(new ProtectionDomain[]{pd}));
    }

    if (DebugHolder.debug != null) {
        DebugHolder.debug.println(" getPermissions (with " + 
            principalArray.length + " authenticated principal(s)) " + pd);
    }

    // Cache with atomic put-if-absent
    ProtectionDomain existed = pdcache.putIfAbsent(key, pd);
    if (existed != null) return existed;
    return pd;
}
```

### 2. Cache Integrity Protection

**Problem:** Cache poisoning via context escape

**Solution:** Validate principals on cache hit

```
Cached domain: (CodeSource, Principals: [CN=Developer])

New context attempt: (CN=Attacker, no auth)
  ↓
Check: Are cached principals present? YES
Check: Does current context match cached? NO
  ↓
Fall through to full validation
  ↓
New context has no principals → SecurityException
```

### 3. Transitive Dependency Validation

**Each dependency independently validated:**

```
Application (trusted.com/app.jar)
  └─ Depends on Library (trusted.com/lib.jar)
     └─ INDEPENDENT VALIDATION:
        • CodeSource: trusted.com/lib.jar (different from app)
        • Subject: MUST be authenticated (same or different)
        • Principal: MUST match policy
        • Permissions: EVALUATED INDEPENDENTLY
           ├─ Policy grants: FilePermission("/data/lib/*", "read")
           ├─ ONLY read-only, scoped to lib data
           ├─ NO inherit from application permissions
           └─ ✅ Principle of Least Privilege ENFORCED
```

---

## Virtual Thread Support

### Virtual Thread Security Guarantees

The following table summarises how security guarantees differ between platform and virtual threads:

| Guarantee | Platform Thread | Virtual Thread (Dirty Chai) |
|-----------|----------------|------------------------------|
| Subject context propagation | Not inherited by child threads (ThreadLocal-based; each thread must call `Subject.doAs()` independently) | Inherited via `Thread.inheritedAccessControlContext` field (SubjectDomainCombiner); `Subject.callAs()` always delegates to `Subject.doAs()` |
| AccessControlContext inheritance | Inherited via `Thread.inheritedAccessControlContext` field, captured at `new Thread()` | Inherited via `Thread.inheritedAccessControlContext` field, captured at `Thread.ofVirtual()` builder creation |
| PrivilegedAction support | Full | Full (identical semantics) |
| Stack walk for permission checks | OS-level stack | JVM-level stack (carrier frames excluded) |
| Carrier thread domains included? | N/A | No — only virtual thread frames counted |
| Subject modification during execution | Allowed (until `setReadOnly()`) | Allowed (until `setReadOnly()`); identical semantics — no scope-exit restoration because Subject propagates via ACC, not ScopedValue |
| Concurrency | Kernel threads (limited) | Up to millions of virtual threads |

> **Key difference from platform threads:** For `Subject` context propagation in Dirty Chai (`allowSecurityManager = true`), `Subject.callAs()` always delegates to `Subject.doAs()`, which installs a `SubjectDomainCombiner` into the `AccessControlContext`. The Subject therefore travels with the `AccessControlContext` via the `Thread.inheritedAccessControlContext` field — the same mechanism used on platform threads, with the only difference being **when** the context is captured (at `Thread.ofVirtual()` builder creation for virtual threads vs. at `new Thread()` construction for platform threads). The `ScopedValue`-based Subject path in `callAs()` is only active when `allowSecurityManager() == false` (plain JDK with no SecurityManager installed) and is **never taken in Dirty Chai**.

---

### 1. AccessControlContext Inheritance Model

**Architecture:** Virtual threads inherit immutable AccessControlContext

```
AccessControlContext Inheritance Hierarchy:

Platform Thread Model (Traditional):
  AccessControlContext (stored in Thread.inheritedAccessControlContext field)
    └─ Captured by AccessController.getContext() at new Thread() construction
    └─ ProtectionDomains
    └─ DomainCombiner
    └─ Privileged Context

Virtual Thread Model (Enhanced):
  AccessControlContext (stored in Thread.inheritedAccessControlContext field)
    └─ Captured by AccessController.getContext() at Thread.ofVirtual() builder creation
    └─ All threads from the same builder share the same captured context
    └─ ProtectionDomains (snapshot at capture point)
    └─ DomainCombiner (same instance)
    └─ Privileged Context (immutable snapshot)
    
  ✅ Immutable inheritance prevents tampering
  ✅ Child VTs cannot modify parent's context
  ✅ Full stack walk capability maintained
  ✅ Read natively via JVM_GetInheritedAccessControlContext (not via ScopedValue)
```

### 2. PrivilegedAction & PrivilegedExceptionAction Support

**Full Support:** Virtual threads execute PrivilegedActions with complete permission inheritance

```
// Example: Privileged action in virtual thread
// No ScopedValue wrapping needed — the AccessControlContext is automatically
// inherited via Thread.inheritedAccessControlContext, captured at builder creation.

public void executePrivilegedInVirtualThread() throws Exception {
    // The builder captures AccessController.getContext() here, at builder creation time.
    // All threads produced by this builder inherit that context automatically.
    try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
        executor.submit(() -> {
            // Virtual thread executes with inherited context

            // Standard PrivilegedAction
            String property = AccessController.doPrivileged(
                new PrivilegedAction<String>() {
                    @Override
                    public String run() {
                        // Executes with permission checks
                        return System.getProperty("user.name");
                    }
                }
            );

            // PrivilegedExceptionAction
            Integer port = AccessController.doPrivileged(
                (PrivilegedExceptionAction<Integer>) () -> {
                    // Can throw checked exceptions
                    return Integer.parseInt(
                        System.getProperty("server.port"));
                }
            );
        });
    }
}
```

**Characteristics:**
- ✅ Privileged actions execute with inherited AccessControlContext
- ✅ Checked exceptions properly propagated
- ✅ Full permission checking maintained
- ✅ Identical semantics to platform threads

### 3. AccessController Stack Walk Compatibility

**Architecture:** Native stack walking works seamlessly with virtual threads

```
Stack Walk Flow (Virtual Threads):

Virtual Thread executing:
  ├─ User code (frame 1)
  │  └─ Calls: AccessController.checkPermission()
  │
  ├─ AccessController.checkPermission() (frame 2)
  │  └─ Initiates stack walk
  │
  ├─ Security Manager (frame 3)
  │  └─ Requests domain check
  │
  ├─ Stack Walk Process:
  │  ├─ Walk up call stack (works on virtual threads)
  │  ├─ Collect ProtectionDomains
  │  ├─ Check inheritance points (PrivilegedAction)
  │  ├─ Evaluate permissions
  │  └─ ✅ Works correctly on VT (not OS-level thread stack)
  │
  └─ Result: Permission granted/denied based on domain chain
```

**Key Differences from Platform Threads:**
- Stack walk uses JVM-level stack (not OS-level)
- Virtual thread mounts/unmounts transparent to stack walk
- Carrier thread's stack NOT included (correct behavior)
- Privilege boundaries detected correctly

### 4. Subject Context Propagation

**Architecture:** `Subject` security context propagates via `AccessControlContext` which propagates via its own dedicated JVM mechanism

```
Context Propagation Mechanisms:

Platform Thread Model (Traditional):
  Subject.doAs(subject, action) → creates AccessControlContext with SubjectDomainCombiner
  AccessControlContext  → Stored in Thread.inheritedAccessControlContext field,
                          captured at new Thread() construction
  
Virtual Thread Model (Dirty Chai — allowSecurityManager = true):
  Subject.callAs(subject, action) → ALWAYS delegates to Subject.doAs() in Dirty Chai
  → creates AccessControlContext with SubjectDomainCombiner (identical to platform thread path)
  AccessControlContext  → Stored in Thread.inheritedAccessControlContext field,
                          captured at Thread.ofVirtual() builder creation ✅
  
  // Subject propagation example (callAs() → doAs() → ACC with SubjectDomainCombiner):
  Subject.callAs(subject, () -> {
      Thread.ofVirtual().start(() -> {
          // Child VT inherits subject via ACC (SubjectDomainCombiner) ✅
          // Subject.current() calls getSubject(AccessController.getContext())
          Subject current = Subject.current();
      });
  });

  // AccessControlContext propagation (automatic — Thread.inheritedAccessControlContext):
  // The builder captures getContext() once; all threads it creates share it.
  Thread.ofVirtual().start(() -> {
      // Child VT already has inherited ACC via Thread.inheritedAccessControlContext ✅
      AccessControlContext current = AccessController.getContext();
  });
```

> **Note:** The `ScopedValue`-based Subject path inside `Subject.callAs()` is only active when
> `allowSecurityManager() == false` (plain JDK without a SecurityManager). In Dirty Chai that
> condition is never true, so `ScopedValue` plays **no role** in Subject propagation here.

**Advantages:**
- ✅ `Subject` propagation via `AccessControlContext` (SubjectDomainCombiner) — consistent with platform-thread model
- ✅ `AccessControlContext` propagated automatically via builder — no manual wiring needed
- ✅ No memory leaks from `ThreadLocal` cleanup
- ✅ Works seamlessly with structured concurrency

### 5. Virtual Thread Lifecycle Integration

```
Virtual Thread Creation:
┌─────────────────────────────────────────┐
│ Parent VirtualThread (authenticated)    │
│ AccessControlContext: inherited         │
│ Subject: inherited via ACC              │
│   (SubjectDomainCombiner in ACC)        │
└────────────┬────────────────────────────┘
             │
             ├─→ Create child task: VirtualThread.Builder
             │   └─ ACC captured in builder (Thread.inheritedAccessControlContext)
             │   └─ Subject travels with ACC (SubjectDomainCombiner)
             │
             ▼
┌─────────────────────────────────────────┐
│ Child VirtualThread (NEW)               │
│ AccessControlContext: inherited via     │
│   Thread.inheritedAccessControlContext ✅│
│ Subject: inherited via ACC ✅           │
│   (getSubject(AccessController.        │
│    getContext()) returns it)            │
│ Can load classes with inherited auth    │
└────────────┬────────────────────────────┘
             │
             ├─→ defineClass() called
             │
             ▼
┌─────────────────────────────────────────┐
│ SecureClassLoader.getProtectionDomain()│
│ Subject.current() via                  │
│   getSubject(AccessController.         │
│   getContext()) ✅                      │
│ ACC from Thread.inheritedAccessControlContext ✅ │
│ ✅ Principals found (inherited)         │
│ ✅ Context available for permission check│
│ ✅ Class loads successfully             │
└─────────────────────────────────────────┘
```

### 6. Mount/Unmount Security Consistency

**Challenge:** Virtual threads mount/unmount from carrier threads

**Solution:** Security context preserved across transitions

```
Virtual Thread Execution Model:

Sequence 1: VirtualThread mounted on Carrier
┌─────────────────────┐
│ VirtualThread       │
│ (User="CN=Alice")   │
│ (loaded on Carrier) │
└──────────┬──────────┘
           │
    Subject.current()
    AccessController.getContext()
           │
    ✅ Returns correct context
       (From AccessControlContext stored in Thread.inheritedAccessControlContext)

Transition: VirtualThread unmounts (park)
┌──────────────────┐
│ Carrier Thread   │
│ (different user) │
└──────────────────┘
           ↓
    VirtualThread still has
    AccessControlContext in Thread.inheritedAccessControlContext
           ↓
    Later: VirtualThread resumes on different carrier
           ↓
    Subject.current() called
    AccessController.getContext() called
           ↓
    ✅ Still returns correct context
       (Subject via AccessControlContext/SubjectDomainCombiner;
        ACC via Thread.inheritedAccessControlContext)
```

### 7. Structured Concurrency Integration

**Pattern:** Use `StructuredTaskScope` for concurrent tasks

```
// In Dirty Chai (allowSecurityManager = true):
// Subject.callAs() delegates to Subject.doAs(), which installs a
// SubjectDomainCombiner into the AccessControlContext.
// The ACC (carrying the Subject) is then inherited by child virtual threads
// via Thread.inheritedAccessControlContext — no manual ScopedValue<Subject> needed.

// Example: Execute multiple authenticated tasks concurrently
void executeWithContext(Subject subject) throws Exception {
    Subject.callAs(subject, () -> {
        try (var scope = new StructuredTaskScope.ShutdownOnFailure()) {
            var future1 = scope.fork(() -> {
                // Child task 1 — Subject inherited via ACC ✅
                Subject current = Subject.current(); // getSubject(AccessController.getContext())
                return loadAndProcessClasses();
            });
            
            var future2 = scope.fork(() -> {
                // Child task 2 — Subject inherited via ACC ✅
                Subject current = Subject.current();
                return accessResources();
            });
            
            scope.joinUntil(Instant.now().plusSeconds(10));
            
            // Process results...
            return null;
        }
    });
}
```

**Benefits:**
- ✅ Subject context flows to all child tasks
- ✅ AccessControlContext inherited immutably
- ✅ Each child has authenticated context
- ✅ Fail-fast on error propagation
- ✅ Resource cleanup guaranteed (try-with-resources)

### 8. Virtual Thread Performance Characteristics

**Comparison: Platform Threads vs Virtual Threads**

| Aspect | Platform Threads | Virtual Threads | Security Impact |
|--------|------------------|-----------------|-----------------|
| **Creation cost** | ~1MB per thread | ~100 bytes | Enables many concurrent contexts |
| **Context switch** | OS kernel scheduler | JVM scheduler | Security context preserved |
| **Subject storage** | Stored in `AccessControlContext` (SubjectDomainCombiner), set up by `Subject.doAs()`; not automatically inherited by new threads | Stored in `AccessControlContext` (SubjectDomainCombiner), set up by `Subject.callAs()` → `Subject.doAs()`; inherited via `Thread.inheritedAccessControlContext` | ✅ Subject inherits with ACC |
| **ACC storage** | `Thread.inheritedAccessControlContext` field, captured at `new Thread()` | `Thread.inheritedAccessControlContext` field, captured at `Thread.ofVirtual()` builder creation | ✅ Immutable; shared by all threads from the same builder |
| **Stack walk** | OS-level stack | JVM-level stack | ✅ Works correctly |
| **Cache effects** | L1/L2 impact | Minimal | ✅ Better performance |
| **GC pressure** | Long-lived memory | Short-lived, GC-friendly | ✅ Reduced GC pause |

**Security Scalability:**
- **Before (Platform Threads):**
  - 1000 concurrent users = 1000 * 1MB = ~1GB memory
  - Each thread must establish its own Subject context via `Subject.doAs()` — not automatically inherited
  - OS context switch overhead for each
  
- **After (Virtual Threads):**
  - 1,000,000 concurrent virtual tasks = ~100MB memory
  - AccessControlContext-based Subject context efficient and inherited automatically
  - Minimal scheduler overhead per context
  - AccessControlContext inherited, not copied per-thread

### 9. Virtual Thread with SecurityManager Integration

```
// Configure for virtual threads
// -Djava.security.manager=au.zeus.jdk.authorization.sm.CombinerSecurityManager
// -Djava.security.policy=/etc/java.policy

// Application code — In Dirty Chai (allowSecurityManager = true):
// Subject.callAs() delegates to Subject.doAs(), which creates an
// AccessControlContext carrying the Subject via SubjectDomainCombiner.
// Child virtual threads inherit that ACC via Thread.inheritedAccessControlContext.
// No manual ScopedValue<Subject> is needed or correct here.
public class VirtualThreadApp {
    
    public static void main(String[] args) throws Exception {
        // Authenticate user
        Subject subject = authenticateUser(args[0]);
        
        // Establish authenticated context — callAs() → doAs() → ACC with SubjectDomainCombiner
        Subject.callAs(subject, () -> {
            // Create thread pool of virtual threads inside the authenticated scope
            // so each builder captures the ACC containing the Subject
            try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
                
                // Submit 1 million tasks with authenticated context
                for (int i = 0; i < 1_000_000; i++) {
                    executor.submit(() -> {
                        // Each task inherits authenticated Subject via inherited ACC ✅
                        Subject current = Subject.current(); // reads from ACC via getSubject()
                        assert current == subject; // ✅ Inherited
                        
                        // Load classes with authentication
                        ClassLoader cl = new SecureClassLoader();
                        Class<?> appClass = cl.loadClass("com.app.Task");
                        
                        // Execute with security context
                        appClass.getMethod("run").invoke(null);
                    });
                }
                
                executor.shutdown();
                if (!executor.awaitTermination(5, TimeUnit.MINUTES)) {
                    executor.shutdownNow();
                }
            }
            return null;
        });
    }
    
    private static Subject authenticateUser(String username) throws Exception {
        Subject subject = new Subject();
        LoginContext lc = new LoginContext("VirtualThreadApp");
        lc.login();
        return subject;
    }
}
```

### 10. Error Handling in Virtual Thread Context

**Scenario:** Exception in virtual thread with authenticated context

```
// Virtual thread task with error handling
// Subject context is carried in the inherited AccessControlContext ✅
Subject.callAs(subject, () -> {
    try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
        executor.submit(() -> {
            try {
                ClassLoader cl = new SecureClassLoader();
                Class<?> appClass = cl.loadClass("com.app.Task");
                appClass.getMethod("run").invoke(null);
            } catch (SecurityException e) {
                // Security context available even in exception handler
                Subject current = Subject.current();  // ✅ Still available via ACC
                
                // Log with authentication context
                logger.error("Task failed with authenticated user: " + 
                            current.getPrincipals(), e);
                
                // Can initiate remediation with known principal
                notifySecurityAdmin(current.getPrincipals(), e);
            } catch (Exception e) {
                // Standard exception handling
                throw new RuntimeException(e);
            }
        });
        executor.shutdown();
        if (!executor.awaitTermination(5, TimeUnit.MINUTES)) {
            executor.shutdownNow();
        }
    }
    return null;
});
```

**Benefits:**
- ✅ Security context available in exception path
- ✅ Audit trail includes authenticated principal
- ✅ AccessControlContext accessible for remediation
- ✅ Remediation actions can identify actor
- ✅ No context loss on error

---

## Subject Context Management

### 1. Subject.callAs() vs Subject.doAs() Relationship

**Critical Design Point:** In the Dirty Chai Authorization system, `Subject.callAs()` **always delegates to `Subject.doAs()`** because `allowSecurityManager()` will **always return true**.

#### **Architecture Decision**

```
@SuppressWarnings("removal")
public static <T> T callAs(final Subject subject,
        final Callable<T> action) throws CompletionException {
    Objects.requireNonNull(action);
    
    // In Dirty Chai system: allowSecurityManager() is ALWAYS true
    // because CombinerSecurityManager or custom SecurityManager is installed
    if (!SharedSecrets.getJavaLangAccess().allowSecurityManager()) {
        // This path is NOT taken in Dirty Chai context
        // ScopedValue-based path for no-SecurityManager environments
        try {
            return ScopedValue.where(SCOPED_SUBJECT, subject).call(action::call);
        } catch (Exception e) {
            throw new CompletionException(e);
        }
    } else {
        // ✅ THIS PATH ALWAYS TAKEN in Dirty Chai system
        // SecurityManager is installed → use doAs()
        try {
            PrivilegedExceptionAction<T> pa = () -> action.call();
            @SuppressWarnings("removal")
            var result = doAs(subject, pa);  // ← Always delegates here
            return result;
        } catch (PrivilegedActionException e) {
            throw new CompletionException(e.getCause());
        } catch (Exception e) {
            throw new CompletionException(e);
        }
    }
}
```

**Why This Matters:**

| Condition | Path Taken | Context | Dirty Chai System |
|-----------|-----------|---------|------------------|
| **No SecurityManager** | ScopedValue path | Virtual thread context isolation | ❌ NOT applicable |
| **SecurityManager Installed** | doAs() path | AccessControlContext + DomainCombiner | ✅ ALWAYS used |

#### **Dirty Chai System Guarantee**

```
JVM Startup:
  ├─ CombinerSecurityManager installed via -Djava.security.manager=...
  ├─ OR custom SecurityManager subclass installed
  ├─ System.getSecurityManager() != null
  │
  └─ SharedSecrets.getJavaLangAccess().allowSecurityManager()
     └─ ✅ Returns TRUE (SecurityManager allowed)

Runtime:
  ├─ Subject.callAs(subject, callable)
  ├─ allowSecurityManager() check
  │  └─ ✅ TRUE → use doAs() path
  ├─ doAs(subject, PrivilegedExceptionAction)
  ├─ Creates AccessControlContext with SubjectDomainCombiner
  ├─ Executes via AccessController.doPrivileged()
  └─ ✅ Unified access control model
```

### 2. doAs() Execution Flow (Always Used in Dirty Chai)

**Complete Execution Chain:**

```
// Entry point (always taken in Dirty Chai system)
Subject.doAs(subject, action)
    ↓
// Authorization check
SecurityManager.checkPermission(AuthPermission("doAs"))
    ↓
// Capture current context
AccessControlContext currentAcc = AccessController.getContext()
    ↓
// Create Subject-based context
AccessControlContext subjectAcc = 
    createContext(subject, currentAcc)
    ├─ AccessControlContext.build(currentAcc, new SubjectDomainCombiner(subject))
    └─ ✅ Adds Subject principals to domain combiner
    ↓
// Execute privileged action
AccessController.doPrivileged(action, subjectAcc)
    ├─ Stack walk performed
    ├─ SubjectDomainCombiner.combine() called
    ├─ Subject principals combined with domains
    └─ ✅ Subject context active throughout execution
    ↓
// Return result or throw exception
Return T or throw PrivilegedActionException
```

**Key Point:** The entire execution happens under the `subjectAcc` context, which includes the Subject's principals.

### 3. Subject.current() Integration

**Architecture:** `Subject.current()` adapts behavior based on SecurityManager

```
@SuppressWarnings("removal")
public static Subject current() {
    if (!SharedSecrets.getJavaLangAccess().allowSecurityManager()) {
        // NOT taken in Dirty Chai system
        // Uses ScopedValue for no-SecurityManager environments
        return SCOPED_SUBJECT.isBound() ? SCOPED_SUBJECT.get() : null;
    } else {
        // ✅ ALWAYS taken in Dirty Chai system
        // Uses AccessControlContext + DomainCombiner
        return getSubject(AccessController.getContext());
    }
}
```

**In Dirty Chai System:**

```
Subject.current()
    ├─ allowSecurityManager() → TRUE
    ├─ getSubject(AccessController.getContext())
    │  ├─ Retrieves current ACC
    │  ├─ Gets DomainCombiner
    │  ├─ Casts to SubjectDomainCombiner
    │  └─ Returns subject from combiner
    └─ ✅ Returns current Subject from ACC
```

**Guaranteed Properties:**

```
When called inside Subject.doAs(subject, action):
  ├─ AccessControlContext has SubjectDomainCombiner
  ├─ DomainCombiner contains the Subject
  ├─ Subject.current() retrieves it
  └─ ✅ Returns the expected Subject

When called outside Subject.doAs():
  ├─ AccessControlContext has null DomainCombiner
  ├─ Or DomainCombiner is not SubjectDomainCombiner
  ├─ Subject.current() returns null
  └─ ✅ Correctly indicates no active Subject context
```

### 4. callAs() vs doAs() Practical Equivalence in Dirty Chai

**Side-by-Side Comparison:**

```
// Modern API (callAs)
Subject.callAs(subject, () -> {
    // Inside: Subject.current() works ✅
    Subject s = Subject.current();
    return performOperation();
});

// Legacy API (doAs) - ALWAYS USED in Dirty Chai
Subject.doAs(subject, new PrivilegedAction<Object>() {
    public Object run() {
        // Inside: Subject.current() works ✅
        Subject s = Subject.current();
        return performOperation();
    }
});

// In Dirty Chai system: callAs internally calls doAs
// Both paths lead to identical behavior:
// ✅ Subject context active
// ✅ Subject.current() returns subject
// ✅ AccessControlContext includes SubjectDomainCombiner
// ✅ Privileged action executes with subject permissions
```

**Exception Handling Difference:**

```
// callAs() wraps exceptions in CompletionException
try {
    Subject.callAs(subject, () -> {
        throw new IOException("Error");
    });
} catch (CompletionException ce) {
    Throwable cause = ce.getCause();  // IOException
}

// doAs() wraps checked exceptions in PrivilegedActionException
try {
    Subject.doAs(subject, (PrivilegedExceptionAction<Void>) () -> {
        throw new IOException("Error");
    });
} catch (PrivilegedActionException pae) {
    Throwable cause = pae.getCause();  // IOException
}

// But in Dirty Chai context, callAs uses doAs internally
// So both ultimately throw PrivilegedActionException, then wrapped in CompletionException
```

### 5. Impact on SecureClassLoader

**Class Loading with Subject Context:**

```
// In Dirty Chai system
Subject.doAs(subject, (PrivilegedAction<Void>) () -> {
    // Inside: subject is active
    // ✅ Subject.current() returns subject
    
    // Class loading triggered
    Class<?> clazz = Class.forName("com.example.App");
    
    // SecureClassLoader.defineClass() called
    // ├─ getProtectionDomain(codeSource)
    // │  ├─ Subject.current() → ✅ Returns subject
    // │  ├─ Validates principals
    // │  ├─ Creates ProtectionDomain with principals
    // │  └─ ✅ Principals bound to class
    // └─ Class loaded with subject context
    
    return null;
});

// OR using modern API (still uses doAs internally)
Subject.callAs(subject, () -> {
    // Inside: subject is active (via doAs internally)
    // ✅ Identical behavior to doAs
    
    Class<?> clazz = Class.forName("com.example.App");
    // ✅ Same class loading with principals
    
    return null;
});
```

### 6. Virtual Thread Interaction

**Virtual Thread with Subject Context:**

```
// Create authenticated subject
Subject subject = authenticateUser();

// Execute in virtual threads WITH Subject context
Subject.doAs(subject, (PrivilegedAction<Void>) () -> {
    // Inside doAs: subject is active
    // ✅ Subject.current() returns subject
    
    try (ExecutorService executor = 
            Executors.newVirtualThreadPerTaskExecutor()) {
        
        // Each virtual thread task...
        executor.submit(() -> {
            // Child virtual thread
            Subject current = Subject.current();
            // ✅ Returns subject (from ACC + DomainCombiner)
            
            // Class loading in virtual thread
            // ✅ Uses subject context
            ClassLoader cl = new SecureClassLoader();
            Class<?> clazz = cl.loadClass("com.app.Task");
            
            return null;
        });
    }
    return null;
});
```

**Architecture Note:** The Subject context flows through `AccessControlContext`, which is preserved across virtual thread boundaries via inherited `AccessControlContext` immutability.

### 7. Why callAs() Always Uses doAs() in Dirty Chai

**Architectural Rationale:**

| Aspect | Reason |
|--------|--------|
| **SecurityManager Always Present** | JVM started with `-Djava.security.manager=...` |
| **Unified Access Control** | All code uses same ACC-based model |
| **Backward Compatibility** | doAs() API tested for decades |
| **AccessControlContext Integration** | Requires full stack walk + DomainCombiner |
| **Principal Binding** | SubjectDomainCombiner combines principals with domains |
| **Policy Enforcement** | Depends on ACC infrastructure |
| **ScopedValue Not Suitable** | Doesn't integrate with stack walk |

```
Dirty Chai System Design:
  ├─ SecurityManager installed → allowSecurityManager() = true
  ├─ All access control via AccessControlContext
  ├─ All subjects via SubjectDomainCombiner
  ├─ All principals bound to domains
  └─ ✅ callAs() always uses doAs()
```

### 8. Configuration Verification

**How to Verify callAs() Uses doAs():**

```
// Add debug logging
-Djava.security.debug=all
-Xlog:security=debug

// In code
Subject subject = new Subject();
subject.getPrincipals().add(new X500Principal("CN=User"));

Subject.callAs(subject, () -> {
    System.out.println("Current: " + Subject.current());
    // Logs show:
    // - doAs() called ✅
    // - AccessControlContext created ✅
    // - SubjectDomainCombiner active ✅
    
    return null;
});
```

**Log Output (Expected):**

```
[DEBUG] Subject.doAs() invoked
[DEBUG] Creating Subject-based AccessControlContext
[DEBUG] SubjectDomainCombiner initialized with subject
[DEBUG] AccessController.doPrivileged() executing
[DEBUG] Stack walk performed
[DEBUG] Subject principals: [CN=User]
[DEBUG] ✅ All via doAs() infrastructure
```

---

## AccessController Integration

### 1. Stack Walk Execution Model

**Architecture:** AccessController performs stack walk on virtual thread stacks

```
AccessController.checkPermission() Flow (Virtual Threads):

Call Stack:
  Frame N: User Code
    └─ calls AccessController.checkPermission(permission)
    
  Frame N-1: AccessController.checkPermission()
    └─ Invokes doPrivilegedImpl()
    
  Frame N-2: AccessController.doPrivilegedImpl()
    └─ Initiates JVM stack walk
    
  Frame N-3+: Security checks
    └─ Stack walker collects ProtectionDomains
    └─ Evaluates each domain's permissions
    └─ Stops at privilege boundaries (doPrivileged calls)
    └─ Uses inherited AccessControlContext at boundary

Stack Walk Result:
  ✅ All frames collected correctly
  ✅ Privilege boundaries detected
  ✅ Inherited ACC used at boundaries
  ✅ Permission decision made correctly
```

### 2. PrivilegedAction Execution

**Model:** PrivilegedActions execute within inherited security context

```
// PrivilegedAction in virtual thread
// The ACC is already inherited via Thread.inheritedAccessControlContext — no
// ScopedValue wrapping is needed for the JVM mechanism. The ScopedValue pattern
// below is only necessary if the executor was not created from a builder that
// captured the desired context, and you need to pass a specific ACC explicitly.
AccessControlContext context = AccessController.getContext();

ScopedValue.where(ACC_CONTEXT, context).runner(() -> {
    // Virtual thread executes with inherited ACC (via explicit ScopedValue here,
    // or automatically via Thread.inheritedAccessControlContext if the builder was
    // created in the right context)
    
    // Option 1: No explicit context (uses inherited)
    Integer port = AccessController.doPrivileged(() -> {
        // Executes with inherited context
        // Stack walk stops here, uses inherited ACC
        return readPort();
    });
    
    // Option 2: Explicit context override (rare)
    String data = AccessController.doPrivileged(() -> {
        // Executes with provided context
        return readData();
    }, explicitContext);
}).run();
```

**Key Points:**
- ✅ Inherited AccessControlContext used by default
- ✅ Explicit context overrides supported (backward compatible)
- ✅ Stack walk continues below privilege boundary only if explicit context provided
- ✅ Identical semantics to platform threads

### 3. Caller Sensitive Methods

**Pattern:** Caller-sensitive methods work correctly with virtual threads

```
@CallerSensitive
public static Class<?> forName(String className) throws ClassNotFoundException {
    // Uses stack walk to find caller
    Class<?> caller = Reflection.getCallerClass();
    
    // In virtual threads:
    // ✅ Correctly identifies caller class
    // ✅ Not confused by carrier thread
    // ✅ Stack walk finds actual virtual thread frame
    
    return forNameImpl(className, caller);
}
```

**Virtual Thread Stack Walk:**
```
User Code (VirtualThread frame)
  └─ Class.forName() call
     └─ @CallerSensitive method
        └─ Reflection.getCallerClass()
           └─ Stack walk finds User Code frame (not carrier thread)
           └─ ✅ Correct caller identified
```

### 4. AccessController Context Snapshot

**Pattern:** Context snapshots work correctly with virtual threads

```
// Capture current security context
AccessControlContext snapshot = AccessController.getContext();

// On virtual thread:
// ✅ Snapshot includes all ProtectionDomains from VT stack
// ✅ NOT cluttered with carrier thread domains
// ✅ Can be used by other VTs or threads

// Later, in different VT or thread:
Integer result = AccessController.doPrivileged(
    () -> {
        // Executes with SNAPSHOT context, not current context
        return sensitiveOperation();
    },
    snapshot  // Use captured context
);
```

**Benefits:**
- ✅ Context snapshots are clean (no carrier thread domains)
- ✅ Can be safely passed to other threads/VTs
- ✅ Supports asynchronous operations
- ✅ Proper privilege containment

---

## AccessControlContext Boundaries

This section analyses the points at which an `AccessControlContext` (ACC) is captured, stored, and later applied across thread, thread-pool, and executor boundaries in the DirtyChai trunk.  Understanding these boundaries is essential for reasoning about which caller's permissions are actually enforced when a task executes in a pool or a new thread.

### Overview: The `checkPermission` Algorithm

`AccessController.checkPermission()` walks the call stack from the most-recent frame toward the oldest.  After exhausting all stack frames it falls through to check the **inherited** ACC that was stored on the thread at creation time:

```
for each frame on the stack (most recent → oldest) {
    if (frame's domain lacks the permission)
        throw AccessControlException;

    if (frame is doPrivileged with no context)
        return;  // granted — stop here

    if (frame is doPrivileged with context) {
        context.checkPermission(perm);   // intersect with context
        return;                          // stop here
    }
}

// After exhausting all stack frames:
thread.inheritedAccessControlContext.checkPermission(perm);
```

The inherited ACC is the **final safety net**, checked only after the full call stack has been exhausted.  Because a task submitted from low-privilege code runs with that low-privilege code on the call stack, those frames are inspected first and will constrain permission grants normally.  The inherited ACC therefore does not override the submitter's stack-based constraints.

The primary context that *is* lost across an executor boundary is the submitter's **Subject** — specifically the principals and the permissions granted to those principals by the policy.  A `Subject` bound via `Subject.callAs()` or `Subject.doAs()` exists only as a `doPrivileged` frame on the submitting thread's stack; it is absent from the worker thread's stack unless explicitly re-established there.

---

### 1. Thread Creation Boundary

**Files:** `Thread.java`, `ThreadBuilders.java`

When any new thread is created — platform or virtual — the ACC of the *creating thread* at the moment `Thread.Builder.ofPlatform()` / `ofVirtual()` is called is captured and stored as the new thread's `inheritedAccessControlContext`.

```
Thread.Builder.ofPlatform()  ←── ACC captured HERE (at builder construction)
        │
        ├─ start(task1)   → thread inherits builder-time ACC
        ├─ start(task2)   → same ACC
        └─ factory()      → every thread from this factory inherits same ACC
```

Key implementation details:

- `ThreadBuilders.BaseBuilder` stores `AccessController.getContext()` into `inheritedSecurityContext` **at builder construction time**, not at thread-start time.
- All threads and `ThreadFactory` instances produced from the same builder share this one captured context.
- At thread construction, the field is passed to `Thread(…, AccessControlContext acc)` and stored as `Thread.inheritedAccessControlContext`.
- Both platform and virtual threads follow the same path; `VirtualThread(…, AccessControlContext context)` passes the context directly to the `Thread(name, characteristics, bound, inheritedContext)` base constructor.

**Note:** The inherited ACC is consulted only after the call stack is exhausted.  Low-privilege code that submits a task to the pool is present on the call stack during task execution; its domain constraints therefore apply normally through the standard stack-walk algorithm.  What is **not** automatically present in the worker thread is the submitter's **Subject** context — principals and the policy grants tied to those principals are lost unless the task re-establishes them explicitly.

---

### 2. Thread Pool Boundary (`ThreadPoolExecutor`)

**File:** `ThreadPoolExecutor.java`, `Executors.java`

`ThreadPoolExecutor` has no explicit ACC capture or propagation machinery of its own.  Worker-thread ACC is set entirely by the `ThreadFactory` supplied at pool construction time.

#### Default factory (`Executors.defaultThreadFactory()`)

Delegates to `Thread.ofPlatform().factory()`.  The builder — and therefore the ACC snapshot — is captured when `defaultThreadFactory()` is called, i.e., at pool-construction time.

#### `Executors.privilegedThreadFactory()`

Explicitly snapshots `AccessController.getContext()` and the `contextClassLoader` at *factory-creation time*, and wraps each worker's `Runnable` in `doPrivileged(…, acc)`:

```java
// PrivilegedThreadFactory (Executors.java)
PrivilegedThreadFactory() {
    this.acc = AccessController.getContext();   // captured at factory construction
    this.ccl = Thread.currentThread().getContextClassLoader();
}

public Thread newThread(Runnable r) {
    return super.newThread(() ->
        AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
            Thread.currentThread().setContextClassLoader(ccl);
            r.run();
            return null;
        }, acc)                                // replayed at task execution time
    );
}
```

Tasks wrapped with `Executors.privilegedCallable()` or `Executors.privilegedRunnable()` use the same pattern: they snapshot the submitter's ACC at *submission time* and replay it via `doPrivileged` at *execution time*:

```java
// PrivilegedCallable (Executors.java)
PrivilegedCallable(Callable<T> task) {
    this.acc = AccessController.getContext();  // caller's ACC at submission
}
public T call() throws Exception {
    return AccessController.doPrivileged(
            (PrivilegedExceptionAction<T>) () -> task.call(), acc);
}
```

**Key gap:** For tasks submitted without a privilege wrapper, the submitter's code-based permission checks still apply because the submitter is present on the call stack.  What is **not** automatically carried into the worker thread is the submitter's **Subject** context.  If the submitter executed under `Subject.callAs()` or `Subject.doAs()`, that `SubjectDomainCombiner`-backed `doPrivileged` frame exists only on the submitting thread's stack.  The worker thread has no such frame, so `Subject.current()` returns `null` and policy grants conditioned on Subject principals are unavailable.

| Mechanism | When ACC is captured | Effect at execution |
|---|---|---|
| `defaultThreadFactory()` | Pool construction time | Worker inherited ACC is builder-creator's; submitter code constraints apply via stack walk; submitter Subject absent |
| `privilegedThreadFactory()` | Factory construction time | Factory-creator's code ACC replayed via `doPrivileged`; submitter Subject absent |
| `privilegedCallable(task)` | Task submission time | Submitter's code ACC replayed via `doPrivileged`; submitter Subject absent unless explicitly included |
| Plain `submit(task)` | Never | Submitter code constraints apply via stack walk; worker inherited ACC is fallback after stack exhausted; submitter Subject absent |

---

### 3. ForkJoinPool / Common Pool Boundary

**Files:** `ForkJoinPool.java`, `ForkJoinWorkerThread.java`

Three distinct strategies control the ACC of ForkJoin worker threads.

#### `DefaultForkJoinWorkerThreadFactory`

When a `SecurityManager` is installed, workers are created via `doPrivileged` with a statically-built, minimal ACC:

```
regularACC  (non-common pool):
  → RuntimePermission("getClassLoader")
  → RuntimePermission("setContextClassLoader")
  → RuntimePermission("enableContextClassLoaderOverride")

commonACC  (common pool):
  → above plus RuntimePermission("modifyThread")
  → RuntimePermission("modifyThreadGroup")
```

These static ACCs are constructed once (lazy, effectively pinned) and shared by all workers.  The submitter's code-permission stack walk is unaffected (the submitter is on the call stack), but submitter **Subject** context is not propagated; this is intentional for the common pool so that work-stealing tasks cannot assume an authenticated identity.

#### `CallerContextForkJoinWorkerThreadFactory` (DirtyChai extension)

```java
public CallerContextForkJoinWorkerThreadFactory() {
    this.context = AccessController.getContext();   // captured at factory construction
}

public ForkJoinWorkerThread newThread(ForkJoinPool pool) {
    return AccessController.doPrivileged(
        () -> new ForkJoinWorkerThread(null, pool, true, true),
        context                                     // replayed at worker creation
    );
}
```

Used via `new ForkJoinPool(boolean useContext)` (DirtyChai extension):

```java
new ForkJoinPool(true)   // → CallerContextForkJoinWorkerThreadFactory
new ForkJoinPool(false)  // → DefaultForkJoinWorkerThreadFactory
```

This allows the pool-creator's privilege level to flow to all workers, enabling `fork()`/`join()` patterns to operate correctly under a `SecurityManager`.

#### `InnocuousForkJoinWorkerThread`

The strongest sandboxing boundary in the pool hierarchy:

```
innocuousACC → ProtectionDomain(null, null)   // zero permissions
```

Workers carry no permissions.  ThreadLocals are cleared after each task.  Used for the common pool's innocuous threads.

```
ForkJoinPool Boundary Summary:

new ForkJoinPool(true)
  Workers inherit: pool-creator's ACC (via CallerContextFactory)
  Subject context: pool-creator's Subject (if any); submitter Subject lost unless task re-establishes it

new ForkJoinPool(false) / new ForkJoinPool(int parallelism)
  Workers inherit: minimal static ACC (regularACC)
  Subject context: not present; submitter's code constraints still apply via stack walk

ForkJoinPool.commonPool()
  Workers:         InnocuousForkJoinWorkerThread (if SecurityManager present)
  ACC:             innocuousACC (null CodeSource, null permissions)
  Subject context: not present; maximum isolation
```

---

### 4. Virtual Thread / `StructuredTaskScope` Boundary

**Files:** `VirtualThread.java`, `StructuredTaskScopeImpl.java`, `ThreadBuilders.java`

Virtual threads capture their inherited ACC at builder-call time in exactly the same way as platform threads.  `VirtualThread` receives the context as an explicit constructor parameter and stores it via the base `Thread` constructor.

`StructuredTaskScopeImpl.fork()` creates threads through its configured `ThreadFactory`.  The scope itself holds no ACC; ACC inheritance is entirely delegated to the factory.

```java
// StructuredTaskScopeImpl.fork() — simplified
Thread thread = threadFactory.newThread(subtask);   // factory determines ACC
flock.start(thread);
```

If the default `Thread.ofVirtual().factory()` is used, the builder captures the ACC at `ofVirtual()` time (i.e., when the scope or its factory is created), and all forked threads share that snapshot.

**`Subject.callAs()` / `Subject.doAs()` propagation across forks:**

A Subject-bound ACC (wrapping a `SubjectDomainCombiner`) lives only on the calling thread's stack.  It is **not** automatically propagated across a thread or executor boundary.  A new thread created *inside* the `callAs()` call frame will capture that context as its inherited ACC; a pre-existing thread pool will not.

```
callAs(subject, () -> {
    // Subject is bound here via SubjectDomainCombiner in ACC
    
    // Thread created HERE → inherits Subject-bound ACC ✅
    Thread.ofVirtual().start(task);
    
    // Pre-existing pool → does NOT inherit Subject-bound ACC ❌
    existingPool.submit(task);   // must use Subject.callAs() inside task
});
```

---

### 5. `Subject.doAs()` / `Subject.callAs()` Boundary

**File:** `Subject.java`

`Subject.doAs()` creates a new ACC wrapping a `SubjectDomainCombiner` and pushes it via `doPrivileged`:

```java
// Subject.doAs() — simplified
final AccessControlContext currentAcc = AccessController.getContext();
return AccessController.doPrivileged(action, createContext(subject, currentAcc));
```

This ACC is active only for the duration of the `doPrivileged` call on the *current* thread.  It does not propagate automatically to threads created *before* the `callAs()` boundary.

`Subject.current()` (the modern API) retrieves the Subject from the current thread's ACC via its `DomainCombiner`.  In a worker thread that has no Subject in its inherited ACC and no `doAs` on its stack, `Subject.current()` returns `null`.

---

### 6. `AccessController.getContext()` — Snapshot Semantics

`AccessController.getContext()` merges two sources:

```
getContext() = getStackAccessControlContext()   // stack frames
             + getInheritedAccessControlContext()  // thread.inheritedAccessControlContext
             optimized/intersected
```

This means a snapshot taken inside a `doPrivileged` block already carries the restricted context.  A snapshot taken on a worker thread whose inherited ACC is minimal (e.g., innocuous common-pool worker) will itself be minimal, regardless of what the submitter's stack looks like.

---

### 7. Boundary Risk Summary

The primary security boundary concern across threads and pools is **Subject context loss**, not code-permission loss.  Because the submitting code is present on the call stack during task execution, its domain-based permission constraints are applied normally by the stack-walk algorithm.  What is absent from the worker thread is any `Subject` bound by the submitter via `Subject.callAs()` / `Subject.doAs()` — those `SubjectDomainCombiner`-backed `doPrivileged` frames exist only on the submitting thread's stack.

| Boundary | Inherited ACC on worker | Subject context in worker | What action is needed |
|---|---|---|---|
| `Thread.Builder.ofPlatform/ofVirtual()` | Builder-creator's ACC, captured at builder construction | Not present unless thread is created inside a `callAs()` call | Create thread inside `callAs()` block to inherit Subject |
| `ThreadPoolExecutor` (default factory) | Pool-constructor's ACC | Not present | Submit task inside `Subject.callAs()`/`doAs()`, or use `privilegedCallable` wrapping Subject re-establishment |
| `ThreadPoolExecutor` (privilegedThreadFactory) | Factory-creator's ACC, replayed per task via `doPrivileged` | Not present (factory captures code ACC only, not Subject) | Wrap task body in `Subject.callAs()` inside the worker |
| `Executors.privilegedCallable/privilegedRunnable` | Submitter's code ACC, replayed per task | Not present | Combine with `Subject.callAs()` if Subject context is needed |
| `ForkJoinPool(true)` (CallerContextFactory) | Pool-creator's ACC on all workers | Not present unless pool created inside `callAs()` | Create pool inside `callAs()` block |
| `ForkJoinPool(false)` / `new ForkJoinPool(n)` | Minimal static ACC (regularACC) | Not present | Re-establish Subject inside each task |
| `ForkJoinPool.commonPool()` (InnocuousWorker) | Zero permissions (null CodeSource) | Not present | Maximum isolation; must use explicit `doPrivileged` and `Subject.callAs()` per task |
| `StructuredTaskScope` (default factory) | Scope-open-time ACC (builder captured at `ofVirtual()`) | Inherited if scope is opened inside a `callAs()` call | Open scope inside `callAs()` to propagate Subject to forked threads |
| `Subject.callAs()` inside pool task | Stack-scoped only for that task | Present for that task's stack only | Must be called inside every task that requires the Subject |

---

## Backward Compatibility

### 1. Subject.doAs() Full Compatibility

**Model:** `Subject.doAs()` fully operational with virtual threads; retained and maintained as a first-class API in Dirty Chai

```
// Subject.doAs() — fully operational in Dirty Chai (not deprecated)
Subject subject = new Subject();
LoginContext lc = new LoginContext("MyApp");
lc.login();  // Populate subject

// Subject.doAs() — fully operational in Dirty Chai (not deprecated)
Integer result = Subject.doAs(subject,
    new PrivilegedAction<Integer>() {
        @Override
        public Integer run() {
            // Executes in subject context
            return processData();
        }
    }
);

// SAME CODE works in virtual threads:
// ✅ Subject context inherited
// ✅ Permissions checked correctly
// ✅ Privileged action executes
// ✅ Result returned properly
```

**Backward Compatibility Details:**
- ✅ No code changes required
- ✅ Subject.callAs() delegates to Subject.doAs()
- ✅ Virtual threads detect and handle correctly
- ✅ Identical semantics guaranteed

### 2. Subject.doAsPrivileged() — Essential API for Explicit Context Control

**Why Essential:** `Subject.doAsPrivileged()` is the only Subject API that accepts an **explicit `AccessControlContext`**, enabling caller-independent privilege boundaries. Upstream itself acknowledged: *"There is no replacement for the Security Manager or this method."* It is retained, fully operational, and not deprecated in Dirty Chai.

**The unique capability — null-context isolation:**

```
// doAsPrivileged with null ACC:
//   null → AccessControlContext built from empty ProtectionDomain[]
//   The caller's stack domains cannot widen the Subject's privilege.
//   This clean-context isolation has no equivalent in callAs() or doAs().
Subject.doAsPrivileged(subject, action, null);

// doAsPrivileged with explicit ACC:
//   Passes a captured context as the privilege boundary.
//   Stack walk uses acc, not the current thread's ACC.
AccessControlContext context = AccessController.getContext();
Subject.doAsPrivileged(subject, action, context);
```

```
// Concrete example with explicit context
Subject subject = authenticateUser();
AccessControlContext context = AccessController.getContext();

// doAsPrivileged() — essential API, fully operational in Dirty Chai
Integer result = Subject.doAsPrivileged(subject,
    new PrivilegedAction<Integer>() {
        @Override
        public Integer run() {
            // Executes in subject context with provided ACC
            return sensitiveOperation();
        }
    },
    context  // Explicit context
);

// Works in virtual threads with identical semantics:
// ✅ Subject context inherited
// ✅ Explicit ACC used for privilege boundary
// ✅ Stack walk respects boundary
// ✅ Result returned correctly
```

**Why doAsPrivileged is Irreplaceable:**
- ✅ **Unique capability:** Accepts an explicit `AccessControlContext` — no other Subject API does
- ✅ **Null-context isolation:** `doAsPrivileged(subject, action, null)` constructs a context from an empty `ProtectionDomain[]`, isolating the action from the caller's stack; the caller's domains cannot widen the Subject's privilege — `callAs()` and `doAs()` have no equivalent
- ✅ **No vanilla replacement:** Upstream's own deprecation note states "There is no replacement for the Security Manager or this method"
- ✅ **First-class API in Dirty Chai:** Retained and maintained operational; deprecation annotations are commented out in `Subject.java`
- ✅ **Virtual thread compatible:** Explicit context properly applied across mounts/unmounts
- ✅ **Privilege boundaries respected:** Stack walk correctly uses provided ACC as the boundary

### 3. ThreadLocal Subject Access Patterns

**Pattern:** Code accessing Subject from ThreadLocal remains compatible

```
// Pattern 1: ThreadLocal Subject (old pattern — not inherited by child threads)
private static final ThreadLocal<Subject> subjectLocal = 
    new ThreadLocal<>();

// In Dirty Chai (allowSecurityManager = true), the correct replacement is NOT
// a user-defined ScopedValue<Subject>, but Subject.callAs() / Subject.doAs(),
// which stores the Subject in the AccessControlContext via SubjectDomainCombiner.
// Subject.current() then retrieves it via getSubject(AccessController.getContext()).

// Pattern 2: AccessControlContext from SecurityManager (the Dirty Chai approach)
AccessControlContext acc = AccessController.getContext();

// Works in virtual threads:
// ✅ Returns correct context
// ✅ Respects virtual thread stack
// ✅ Ignores carrier thread context
```

**Migration Path (Not Required):**
```
// Old code (still works):
Subject.doAs(subject, new PrivilegedAction<Void>() {
    public Void run() {
        return null;
    }
});

// Alternative API using Callable signature (callAs always delegates to doAs in Dirty Chai):
Subject.callAs(subject, () -> {
    // Same semantics, callAs always uses doAs in Dirty Chai
    return null;
});

// Both work everywhere:
// ✅ Platform threads: identical behavior
// ✅ Virtual threads: both work, callAs delegates to doAs
```

### 4. Legacy Permission Checking

**Pattern:** Legacy permission checks work transparently

```
// Legacy: Direct SecurityManager permission check
SecurityManager sm = System.getSecurityManager();
if (sm != null) {
    sm.checkPermission(new FilePermission("/etc/app.conf", "read"));
}

// In virtual threads:
// ✅ SecurityManager.checkPermission() called
// ✅ Stack walk collects VT frames
// ✅ AccessControlContext inherited
// ✅ Permission evaluated correctly
```

**Transparent Behavior:**
- ✅ No code changes needed
- ✅ Works on both platform and virtual threads
- ✅ Stack walk handles VT correctly
- ✅ Inherited context applies automatically

### 5. Reflection-Based Security Checks

**Pattern:** Reflection within privileged actions

```
// Using Subject.doAs() with reflection (older PrivilegedAction style)
Subject.doAs(subject, new PrivilegedAction<Object>() {
    @Override
    public Object run() {
        try {
            // Reflection within privileged action
            Method method = clazz.getDeclaredMethod("getValue");
            method.setAccessible(true);
            return method.invoke(obj);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
});

// In virtual threads:
// ✅ Subject context active
// ✅ Reflection works correctly
// ✅ Privileged boundary at doAs/doPrivileged
// ✅ Stack walk respects privilege boundary
```

---

## Threat Model & Prevention

### 1. Attack Vectors

| Attack | Vector | Prevention |
|--------|--------|-----------|
| **Reflection-based SM bypass** | `Method.invoke()` on setSecurityManager | Layer 2: Stack inspection detects reflection (limit 50 frames) |
| **Deep-stack reflection bypass** | 10+ wrapper frames hide `Method.invoke` | `limit(50)` makes exhaustion impractical for startup calls |
| **Generated-code SM bypass** | Lambda/Proxy wraps `setSecurityManager()` | Layers 2 & 4 detect generated frames; `isMethodHandlesFrame()` whitelist-based |
| **Untrusted code loading** | Unsigned JAR from attacker.com | Layer 3: LoadClassPermission denied |
| **Privilege escalation via deps** | Trusted code loads evil transitive dep | Layer 4: Each dep independently validated |
| **Cache poisoning** | Unauthenticated context reuses cached domain | Layer 5: Cache validates principals on hit |
| **Null principal exploit** | Load with empty Subject | Layer 2: Principals non-empty check fails |
| **Certificate forgery** | Fake cert for trusted.com | CodeSourceKey: cert must validate for URL |
| **Agent injection** | Load java.lang.instrument without auth | Layer 1: No CodeSource → Layer 2: No Subject |
| **Service loader bypass** | ServiceLoader.load() restricted module | Layer 3: Module not in policy → denied |
| **Read-only subject escape** | Load while subject sealed | Layer 2: isReadOnly() check throws exception |
| **DNS-based cache confusion** | Same IP, different DNS names | CodeSourceKey: String comparison, no DNS |
| **DNS DoS during permission check** | Slow/hanging DNS delays `SocketPermission.implies()` | `SocketPermission.init()` pre-fetches DNS at policy construction |
| **All-invalid-URI wildcard grant** | Typo/injected URI turns grant into wildcard CodeSource | `URIGrant` throws `SecurityException` on `URISyntaxException`; no silent omission |
| **Stale policy on refresh failure** | Exception swallowed in `ConcurrentPolicyFile.refresh()` | `refresh()` now throws `SecurityException`; no silent continue |
| **Virtual thread context escape** | Child VT inherits parent's ACC/Subject without intended restriction | ACC immutability + Subject stored in ACC (SubjectDomainCombiner): child VTs inherit ACC but cannot modify it |
| **Cross-virtual thread pollution** | One VT accesses another VT's Subject context | ACC isolation: each thread's `Thread.inheritedAccessControlContext` is a separate snapshot |
| **ACC tampering in VT** | Modify inherited AccessControlContext | ACC immutability: cannot be modified post-inheritance |
| **Carrier thread stack inclusion** | Carrier domain included in check | Stack walk ignores carrier (only VT frames used) |
| **callAs/doAs bypass** | Attempt to bypass Subject context | allowSecurityManager() = true forces doAs() path |

### 2. Specific Attack Scenarios

#### **Scenario A: Untrusted Dependency Privilege Escalation**

```
Attack:
  evil-lib.jar is a transitive dependency of trusted-app.jar.
  Attacker hopes trusted-app's grant block covers evil-lib too.

  trusted-app.jar  -->  db-lib.jar  -->  evil-lib.jar (attacker-controlled)

Prevention:
  1. SecureClassLoader validates CodeSource independently for each JAR
  2. evil-lib.jar has its own (different) CodeSource URL
  3. Policy has no grant for evil-lib's CodeSource → LoadClassPermission denied
  4. Class is never defined in the JVM
  5. ✅ Privilege escalation through dependency chain blocked

Result: Evil transitive dependency cannot execute regardless of how it was loaded
```

#### **Scenario B: ClassLoader Cache Poisoning**

```
Attack:
  Attacker submits requests that share a cached ProtectionDomain
  from an earlier, authenticated session. Goal: reuse high-privilege
  domain for unauthenticated code.

Prevention:
  1. Cache key includes (CodeSource URL, certificates, Principal set)
  2. On cache hit, principals are re-validated against current Subject
  3. Empty or mismatched Principal set → cache miss → fresh validation
  4. SecurityException thrown if principals don't match
  5. ✅ Cached domain cannot be reused across different subjects

Result: Each authenticated session gets its own domain; no cross-contamination
```

#### **Scenario C: Virtual Thread Context Confusion**

```
Attack:
  High-privilege virtual thread spawns child threads.
  Attacker-controlled child tries to inherit parent's Subject and ACC
  in order to act with elevated privileges outside the parent scope.

Prevention:
  1. Subject propagates via AccessControlContext (SubjectDomainCombiner),
     established by Subject.callAs() → Subject.doAs()
  2. ACC is captured at Thread.ofVirtual() builder creation and is immutable
  3. A thread created OUTSIDE the callAs() scope captures a different
     (or no-Subject) ACC — it does NOT inherit the parent's Subject
  4. Subject.current() reads from the thread's own inherited ACC only
  5. ✅ Context cannot escape its original Subject.callAs() scope

Result: Virtual thread context leaks prevented; principle of containment upheld
```

#### **Scenario D: Malicious callAs() Bypass Attempt**

```
Attack:
  Attacker tries to use callAs() without doAs() path
  
Prevention:
  1. allowSecurityManager() is ALWAYS true in Dirty Chai system
  2. CombinerSecurityManager installed at startup
  3. callAs() detects SecurityManager presence
  4. callAs() delegates to doAs()
  5. ✅ doAs() path always taken
  
Result: Bypass impossible; unified access control enforced
```

#### **Scenario E: Virtual Thread ACC Tampering**

```
Attack:
  Virtual thread tries to modify inherited AccessControlContext
  
Prevention:
  1. AccessControlContext is immutable
  2. Inherited via Thread.inheritedAccessControlContext field (read-only)
  3. Cannot be modified post-inheritance
  4. New context creation requires explicit doPrivileged()
  5. ✅ Tampering attempt fails
  
Result: ACC integrity maintained
```

#### **Scenario F: Subject Context Escape**

```
Attack:
  Child virtual thread tries to access another thread's Subject context
  
Prevention:
  1. Subject is stored in the AccessControlContext (SubjectDomainCombiner),
     established by Subject.callAs() → Subject.doAs()
  2. ACC is immutable once captured in Thread.inheritedAccessControlContext
  3. A new child thread created outside the callAs() scope captures a different
     (or null-Subject) ACC — it does NOT inherit the parent's Subject
  4. Subject.current() reads from the thread's own inherited ACC only
  5. ✅ Context escape prevented
  
Result: Subject isolation maintained per AccessControlContext scope
```

### 3. Fail-Secure Design

```
❌ Silent failures prevented:
   • Code NOT loaded if ANY validation fails
   • SecurityException thrown immediately
   • Calling code must handle (cannot silently continue)
   • No class defined on failure

✅ Exception handling:
   • Missing CodeSource → null (no class)
   • No Subject context → SecurityException
   • No principals → SecurityException
   • Permission denied → SecurityException
   • Invalid certificate → SecurityException
   • Policy mismatch → SecurityException
   • ACC immutable → no corruption possible
   • callAs always uses doAs() → predictable behavior
```

---

## Configuration & Deployment

### 1. Policy File Structure

**Location:** `/etc/java.policy` or system property `-Djava.security.policy=<path>`

**Format:**
```
grant [signedBy "alias"] [, codeBase "URL"]
      [, principal ClassName "name"]
      [, principal ClassName "name"] ... {
    permission PermissionClassName "target" [, "action"];
    permission ...
};

// Default: Deny all not explicitly granted
```

### 2. Example: Multi-Tier Application Policy

```
# Tier 1: Application Layer
grant signedBy "app-cert",
      codeBase "https://company.com/app.jar",
      principal javax.security.auth.x500.X500Principal "CN=Developer,O=Company" {
    permission java.io.FilePermission "/etc/app/config.properties", "read";
    permission java.io.FilePermission "/var/log/app/*", "write";
    permission au.zeus.jdk.authorization.guards.LoadClassPermission "ALLOW";
};

# Tier 2: Database Library (RESTRICTED)
grant signedBy "db-lib-cert",
      codeBase "https://company.com/db-lib.jar",
      principal javax.security.auth.x500.X500Principal "CN=Developer,O=Company" {
    permission java.sql.SQLPermission "setLog";
    permission java.net.SocketPermission "db.company.com:5432", "connect";
    permission au.zeus.jdk.authorization.guards.LoadClassPermission "ALLOW";
};

# Tier 3: Logging Library (SCOPED)
grant signedBy "log-lib-cert",
      codeBase "https://company.com/logging-lib.jar",
      principal javax.security.auth.x500.X500Principal "CN=Developer,O=Company" {
    permission java.io.FilePermission "/var/log/app/*", "write";
    permission au.zeus.jdk.authorization.guards.LoadClassPermission "ALLOW";
};

# Tier 4: Security Library (MINIMAL)
grant signedBy "sec-lib-cert",
      codeBase "https://company.com/security-lib.jar",
      principal javax.security.auth.x500.X500Principal "CN=Developer,O=Company" {
    permission java.security.SecurityPermission "getPolicy";
    permission au.zeus.jdk.authorization.guards.LoadClassPermission "ALLOW";
};

# DENIED: Agents and management
# (NO GRANTS = IMPLICITLY DENIED)
# java.instrument
# java.management
# jdk.attach
# java.desktop
```

### 3. Installation Steps

```
# 1. Install SecurityManager
-Djava.security.manager=au.zeus.jdk.authorization.sm.CombinerSecurityManager

# 2. Specify policy file
-Djava.security.policy=/etc/java.policy

# 3. Optional: Debug logging
-Xlog:security=debug

# 4. Optional: Virtual thread configuration
-Djdk.virtualThreadScheduler.parallelism=8
-Djdk.virtualThreadScheduler.maxPoolSize=256

# 5. Optional: Enable architecture inspection
-Djdk.debug.system.modules=true

# 6. Optional: AccessController tracing
-Djava.security.access.debug=all

# Example command with virtual threads:
java -Djava.security.manager=au.zeus.jdk.authorization.sm.CombinerSecurityManager \
     -Djava.security.policy=/etc/java.policy \
     -Xlog:security=debug \
     -Xlog:jdk.virtual_threads=debug \
     -Djdk.virtualThreadScheduler.parallelism=8 \
     com.example.Application
```

### 4. CDS (Class Data Sharing) Integration

**CDS Archive Handling:**

```
private void resetArchivedStates() {
    if (CDS.isDumpingAOTLinkedClasses()) {
        for (CodeSourceKey key : pdcache.keySet()) {
            if (key.cs.getCodeSigners() != null) {
                // Remove signed classes (certs may be stale)
                pdcache.remove(key);
            }
        }
    } else {
        pdcache.clear();  // Clear unsigned in runtime
    }
}
```

**Rationale:**
- Signed classes NOT archived (certificate chain may be outdated)
- Unsigned classes CAN be archived (permissions stable)
- Runtime always clears cache (fresh policy enforcement)

---

## Security Properties

### 1. Confidentiality

**Not directly addressed** (handled by OpenJDK JVM memory protection)

Properties:
- Class bytecode protected by JVM memory
- Credentials protected in Subject
- Policy files protected by OS file permissions
- Virtual thread context protected by ACC immutability (Subject stored in AccessControlContext)
- AccessControlContext protected by immutability

---

### 2. Integrity

**Enforced through:**
- Certificate validation in CodeSourceKey
- Principal verification in Subject
- Policy-based permission grants
- AccessControlContext immutability (inherited, not modified; Subject travels with ACC via SubjectDomainCombiner)
- AccessControlContext immutability (cannot be tampered)

**Guarantees:**
- Modified code fails certificate check
- Corrupted principals detected by Subject validation
- Policy tampering detected via permission denial
- AccessControlContext context cannot be corrupted by child threads (immutable inheritance via Thread.inheritedAccessControlContext)
- AccessControlContext remains pristine throughout execution

---

### 3. Authentication

**Enforced through:**
- Subject-based principal authentication
- LoginModule-driven authentication process
- Principal presence validation in each class load
- AccessControlContext-preserved authentication across virtual thread boundaries (Subject via SubjectDomainCombiner in inherited ACC)
- AccessControlContext immutable inheritance
- Subject.callAs() always uses doAs() path (allowSecurityManager = true)

**Guarantees:**
- No code loads without authenticated Subject
- Principals must be present and non-empty
- Subject must be mutable during authentication
- Authentication context maintained across mount/unmount
- AccessControlContext cannot be modified during execution
- Unified access control via doAs() enforcement

---

### 4. Authorization

**Enforced through:**
- (Principal, CodeSource) matching in policy
- Permission evaluation independent per class
- Transitive dependency validation
- AccessControlContext-based context inheritance (Subject via SubjectDomainCombiner, propagated via Thread.inheritedAccessControlContext)
- AccessController stack walk with privilege boundary detection

**Guarantees:**
- Principal alone insufficient (CodeSource required)
- CodeSource alone insufficient (Principal required)
- Each dependency independently authorized
- Permissions not inherited through dependency chain
- Virtual thread children inherit authentication context
- Privilege boundaries enforced by stack walk

---

### 5. Non-Repudiation

**Supported through:**
- Principal tracking in ProtectionDomain
- Audit logging via SecurityManager
- Permission check logging
- AccessControlContext context available in exception handlers (Subject.current() reads from inherited ACC)
- AccessController logging with caller information

**Capabilities:**
- Determine which principal executed code
- Log all permission checks
- Trace authorization decisions
- Audit virtual thread task execution with principal
- Track PrivilegedAction execution

---

### 6. Audit Trail

**Available through:**
```
// SecurityManager.checkPermission() calls
if (DebugHolder.debug != null) {
    DebugHolder.debug.println("Class loading with " + 
        principals.size() + " authenticated principal(s)");
    for (Principal p : principals) {
        DebugHolder.debug.println("  - " + p.getClass().getSimpleName() + 
            ": " + p.getName());
    }
}

// Virtual thread context audit
// In Dirty Chai, Subject is retrieved from the inherited ACC — use Subject.callAs() to establish context
Subject.callAs(subject, () -> {
    logger.info("Virtual thread task started for principal: " + 
        subject.getPrincipals());
    return null;
});

// AccessController audit
AccessController.doPrivileged(() -> {
    logger.info("Privileged action by: " + 
        Reflection.getCallerClass());
    return null;
});

// Enable with: -Xlog:security=debug
```

---

## Implementation Guidelines

### 1. For Application Developers

#### **Authentication Setup (Modern)**

```
// Modern approach for virtual threads
Subject subject = new Subject();
LoginContext lc = new LoginContext("MyApp");
lc.login();  // Establishes principals

// Run application in authenticated context
Subject.callAs(subject, () -> {
    // All class loading happens here
    // All code execution with authenticated principals
    // callAs() automatically uses doAs() in Dirty Chai system ✅
    return MyApplication.run();
});
```

#### **Authentication Setup (PrivilegedAction / doAs variant)**

```
// Subject.doAs() — fully operational in Dirty Chai (not deprecated)
Subject subject = new Subject();
LoginContext lc = new LoginContext("MyApp");
lc.login();

// Subject.doAs() with PrivilegedAction — works identically on platform and virtual threads
Subject.doAs(subject, new PrivilegedAction<Void>() {
    @Override
    public Void run() {
        // All class loading happens here
        // Works identically on platform and virtual threads ✅
        return MyApplication.run();
    }
});
```

#### **Virtual Thread Usage (Modern)**

```
// Modern pattern for virtual threads in Dirty Chai (allowSecurityManager = true):
// Subject.callAs() delegates to Subject.doAs(), which creates an
// AccessControlContext carrying the Subject via SubjectDomainCombiner.
// Create the executor *inside* the callAs() scope so that the builder captures
// the authenticated ACC; all submitted tasks inherit it automatically.
public void executeWithVirtualThreads(Subject subject) throws Exception {
    Subject.callAs(subject, () -> {
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            for (int i = 0; i < 10_000; i++) {
                executor.submit(() -> {
                    // Child virtual thread inherits Subject via inherited ACC ✅
                    Subject current = Subject.current(); // reads from ACC
                    assert current == subject;           // ✅ Inherited
                    
                    // All operations use inherited authentication
                    ClassLoader cl = new SecureClassLoader();
                    Class<?> appClass = cl.loadClass("com.app.Task");
                    appClass.getMethod("run").invoke(null);
                });
            }
            
            executor.shutdown();
            if (!executor.awaitTermination(5, TimeUnit.MINUTES)) {
                executor.shutdownNow();
            }
        }
        return null;
    });
}
```

#### **Resource Access**

```
// Request only needed permissions in policy
grant principal "CN=User"
      codeBase "https://company.com/app.jar" {
    // Only what's needed
    permission java.io.FilePermission "/data/user/*", "read";
    permission java.net.SocketPermission "localhost:8080", "listen";
};

// NOT: AllPermission
// NOT: FilePermission "/", "read,write"
// NOT: All RuntimePermissions
```

### 2. For Security Administrators

#### **Policy Definition**

```
1. Identify principals (users, roles, service accounts)
2. Identify code sources (trusted JAR locations, URLs)
3. Define minimum permissions for each (Principal, CodeSource) pair
4. Test with audit logging enabled
5. Deploy with restrictive defaults
6. Configure virtual thread scheduler for expected concurrency
```

#### **Monitoring**

```
# Enable debug logging
-Xlog:security=debug

# Monitor policy files for changes
md5sum /etc/java.policy

# Review SecurityManager logs for denials
grep "Permission denied" /var/log/application.log

# Audit Subject contexts
-Djava.security.auth.debug=all

# Virtual thread monitoring
-Xlog:jdk.virtual_threads=debug

# AccessController tracing
-Djava.security.access.debug=all
```

### 3. For Security Auditors

#### **Validation Checklist**

```
□ Policy files exist and are readable only by authorized users
□ All policies follow (Principal, CodeSource) model
□ Default-deny (no wildcards for principals or codebases)
□ Unsigned code has no grants
□ Agent modules (java.instrument, jdk.attach) not granted
□ Each tier has minimal permissions
□ Debug logging enabled for sensitive deployments
□ Audit trails collected and analyzed
□ Subject authentication required at entry points
□ SecurityManager installation validated
□ Virtual thread scheduler configured appropriately
□ AccessControlContext properly isolated per Subject.callAs() scope
□ No ThreadLocal usage for sensitive context
□ AccessControlContext immutability verified
□ Privileged action boundaries correctly placed
□ Stack walk produces expected results
□ Legacy Subject.doAs() API compatibility verified
□ PrivilegedAction execution auditable
□ callAs() always delegates to doAs() verified
□ allowSecurityManager() = true confirmed
□ Dirty Chai installation properly configured
```

---

## Performance & Scalability

### Expected Overhead

| Operation | Overhead | Notes |
|-----------|----------|-------|
| First class load (cache miss) | ~2–5 ms | Full validation: CodeSource + Subject + policy lookup |
| Subsequent class load (cache hit) | < 0.1 ms | `ConcurrentHashMap` lock-free read + principal re-check |
| `Subject.callAs()` / `doAs()` | < 0.05 ms | AccessControlContext with SubjectDomainCombiner setup |
| `AccessController.checkPermission()` | < 0.01 ms | Single-level permission lookup with cached domain |
| Virtual thread spawn with context | ~0.1 ms | ACC inheritance via `Thread.inheritedAccessControlContext` (captured at builder creation) |

> **Rule of thumb:** Class loading costs are amortised. Most applications load each class once and then benefit from cache hits for the lifetime of the JVM.

### Cache Hit Rate Expectations

- **Long-running services:** > 99% cache hit rate after warm-up (typically < 60 s)
- **Short-lived processes (CLIs):** Cache provides limited benefit; full validation cost applies
- **Hot deployment / OSGi-style reloading:** Clear relevant entries from the `pdcache` explicitly

### Concurrency Tuning

```bash
# Tune virtual thread scheduler parallelism (default: number of CPUs)
-Djdk.virtualThreadScheduler.parallelism=16

# Tune maximum scheduler pool size (default: 256)
-Djdk.virtualThreadScheduler.maxPoolSize=512

# Recommended: keep parallelism ≤ CPU cores to avoid contention
# Recommended: maxPoolSize ≥ expected peak concurrent blocking tasks
```

### Scalability Notes

- The `pdcache` (`ConcurrentHashMap`) scales linearly with unique `(CodeSource, Principal)` combinations.
- For applications with > 10,000 unique combinations, monitor heap usage — each entry is approximately a few hundred bytes (varies with CodeSource URL length, certificate chain size, and Principal set size).
- Virtual thread security context propagation adds zero per-thread allocation (AccessControlContext is an immutable snapshot shared by threads from the same builder).
- Avoid calling `Subject.setReadOnly()` before class loading is complete; it forces re-validation on every check.

---

## API Reference

### Key Method Summary

| Method | Class | When to Use | Signature |
|--------|-------|-------------|-----------|
| `callAs()` | `javax.security.auth.Subject` | Subject context execution with `Callable`/`CompletionException` signature; delegates to `doAs()` in Dirty Chai — not a replacement for `doAs()`, all three Subject APIs are first-class | `static <T> T callAs(Subject subject, Callable<T> action)` |
| `doAs()` | `javax.security.auth.Subject` | Fully operational first-class API; preferred when `PrivilegedAction`/`PrivilegedExceptionAction` signatures are needed | `static <T> T doAs(Subject subject, PrivilegedAction<T> action)` |
| `doAsPrivileged()` | `javax.security.auth.Subject` | Essential when an explicit `AccessControlContext` is required; `null` acc gives clean caller-independent isolation — **no callAs/doAs equivalent** | `static <T> T doAsPrivileged(Subject subject, PrivilegedAction<T> action, AccessControlContext acc)` |
| `defineClass()` | `java.security.SecureClassLoader` | Override to customise class loading; Dirty Chai validation runs here | `protected Class<?> defineClass(String name, byte[] b, int off, int len, CodeSource cs)` |
| `getPermissions()` | `java.security.SecureClassLoader` | Override to provide custom `PermissionCollection` per `CodeSource` | `protected PermissionCollection getPermissions(CodeSource cs)` |
| `doPrivileged()` | `java.security.AccessController` | Elevate to a specific, limited context | `static <T> T doPrivileged(PrivilegedAction<T> action, AccessControlContext context)` |
| `checkPermission()` | `java.lang.SecurityManager` | Called automatically; invoke manually to guard custom resources | `void checkPermission(Permission perm)` |
| `getContext()` | `java.security.AccessController` | Capture current ACC for passing to virtual threads | `static AccessControlContext getContext()` |
| `current()` | `javax.security.auth.Subject` | Retrieve the Subject bound to the current scope | `static Subject current()` |

### `Subject.callAs()` — Usage Guide

```java
// Authenticate
LoginContext lc = new LoginContext("AppLogin", callbackHandler);
lc.login();
Subject subject = lc.getSubject();

// Run code inside authenticated scope
// callAs() delegates to doAs() automatically in Dirty Chai
Result result = Subject.callAs(subject, () -> {
    // All class loading and privileged operations here
    return myService.process(request);
});
```

**Returns:** the value returned by the `Callable`.  
**Note:** The base JDK `Subject.callAs()` may bypass the `doAs()` path when no `SecurityManager` is present. In Dirty Chai, `CombinerSecurityManager` is always installed, so `callAs()` invariably delegates to `doAs()` and full authentication enforcement applies.

### `SecureClassLoader.defineClass()` — Dirty Chai Behaviour

When `defineClass()` is called inside Dirty Chai:
1. `CodeSource` is checked for null — `null` results in a `SecurityException`.
2. `Subject.current()` is checked — no Subject means `SecurityException`.
3. Policy is evaluated for the `(Subject principals, CodeSource)` pair.
4. On success, a `ProtectionDomain` is created and cached with the principals.

### Custom `getPermissions()` Override

```java
public class MyClassLoader extends SecureClassLoader {
    @Override
    protected PermissionCollection getPermissions(CodeSource cs) {
        // Start with base policy permissions
        PermissionCollection base = super.getPermissions(cs);
        
        // Add application-specific permissions
        if (isTrustedSource(cs)) {
            base.add(new RuntimePermission("accessDeclaredMembers"));
        }
        return base;
    }
    
    private boolean isTrustedSource(CodeSource cs) {
        // Only trust code from your own servers
        return cs != null && cs.getLocation() != null &&
               cs.getLocation().getHost().endsWith(".company.com");
    }
}
```

---


## Troubleshooting

### 1. Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| "Code loading requires authenticated Subject" | Class load outside Subject.callAs() | Wrap with Subject.callAs(subject, ...) |
| "Subject has no authenticated principals" | LoginModule didn't create principals | Verify LoginModule adds principals |
| "Permission LoadClassPermission denied" | Policy missing grant for CodeSource | Add grant in policy for (Principal, CodeSource) |
| "Subject must remain mutable" | Subject.freeze() called too early | Don't freeze until after all class loading |
| "Cached domain has no principals" | Race condition in cache | Retry or fall through to revalidation |
| "Certificate chain invalid" | Untrusted or expired certificate | Verify certificate and re-sign if needed |
| "Subject not available in virtual thread" | Virtual thread created outside `Subject.callAs()` scope | Create virtual thread executor **inside** `Subject.callAs()` so the builder captures the authenticated ACC |
| "Virtual thread context not inherited" | Executor or thread builder created before `Subject.callAs()` | Move executor/thread creation inside the `Subject.callAs()` call frame |
| "PrivilegedAction not working" | ACC not inherited properly | Check that `Thread.ofVirtual()` builder is created in the correct security context; `AccessController.getContext()` uses `Thread.inheritedAccessControlContext` automatically — no `ScopedValue` needed |
| "Stack walk returns wrong domains" | Carrier thread domains included | Verify virtual thread stack walk only |
| "callAs not using doAs" | SecurityManager not installed | Verify -Djava.security.manager=... specified |

### 2. Debug Logging

```
# Enable all security logging
-Xlog:security=trace

# Enable module loading trace
-Xlog:class+load=debug

# Enable Subject authentication debug
-Djava.security.auth.debug=all

# Enable policy file parsing
-Djavax.security.debug=policy

# Enable virtual thread tracing
-Xlog:jdk.virtual_threads=trace

# Enable virtual thread scheduler info
-Djdk.virtualThreadScheduler.debug=true

# Enable AccessController tracing
-Djava.security.access.debug=all

# Combine all flags in a single launch command:
java -Xlog:security=debug \
     -Djava.security.auth.debug=all \
     -Xlog:jdk.virtual_threads=debug \
     -Djava.security.access.debug=all \
     -Djava.security.policy=/etc/java.policy \
     com.example.App
```

### 3. Policy File Verification Steps

1. **Check the policy is being read:**  
   Add `-Djavax.security.debug=policy` and look for `"GRANT"` lines in the output.

2. **Verify Principal matching:**  
   The `Subject`'s principal class and name must match *exactly* (case-sensitive) what is in the `grant` block.

3. **Verify CodeSource URL matching:**  
   URLs are compared as strings after normalisation. Trailing slashes matter.  
   Use `Policy.getPolicy().getPermissions(new CodeSource(url, (Certificate[])null))` to test programmatically.

4. **Check for wildcard vs. exact match:**  
   `codeBase "https://company.com/-"` matches all resources recursively.  
   `codeBase "https://company.com/*"` matches only the direct children.

5. **Confirm SecurityManager is installed:**
   ```java
   System.out.println(System.getSecurityManager()); // must not be null
   ```

---

## References

### Key Files

| File | Purpose |
|------|---------|
| `java.lang.System` | SecurityManager installation with conditional validation |
| `java.lang.Thread` | Thread creation; `inheritedAccessControlContext` captured at builder/constructor time |
| `java.lang.VirtualThread` | Virtual thread; inherits ACC via `Thread(name, characteristics, bound, inheritedContext)` |
| `jdk.internal.misc.ThreadBuilders` | `BaseBuilder` captures ACC at `ofPlatform()`/`ofVirtual()` call; shared by all threads from the same builder |
| `java.security.AccessController` | Privileged action execution; `checkPermission` algorithm; `getContext()` / `getInheritedAccessControlContext()` |
| `java.security.AccessControlContext` | Security context snapshot; immutable inheritance in VTs |
| `java.lang.ScopedValue` | Virtual thread-compatible context propagation |
| `javax.security.auth.Subject` | Principal container; `doAs()` pushes Subject-bound ACC via `doPrivileged`; stack-scoped only |
| `java.util.concurrent.Executors` | `privilegedThreadFactory()`, `privilegedCallable()`, `privilegedRunnable()` — snapshot and replay submitter ACC |
| `java.util.concurrent.ThreadPoolExecutor` | No built-in ACC machinery; relies on `ThreadFactory` for worker inherited ACC |
| `java.util.concurrent.ForkJoinPool` | `CallerContextForkJoinWorkerThreadFactory` (DirtyChai); `DefaultForkJoinWorkerThreadFactory` (minimal ACC); common pool (innocuous ACC) |
| `java.util.concurrent.ForkJoinWorkerThread` | `InnocuousForkJoinWorkerThread` — zero-permission sandboxed workers |
| `java.util.concurrent.StructuredTaskScopeImpl` | `fork()` delegates ACC inheritance entirely to configured `ThreadFactory` |
| `java.lang.VirtualThread` | Virtual thread implementation with ScopedValue + ACC support |
| `au.zeus.jdk.authorization.sm.CombinerSecurityManager` | Permission checking with caching |
| `au.zeus.jdk.authorization.policy.ConcurrentPolicyFile` | Policy-based permission enforcement |

### Related Documentation

- **OpenJDK Security Documentation:** https://docs.oracle.com/en/java/javase/
- **Java Authentication & Authorization Service (JAAS):** JAAS Documentation
- **Virtual Threads (Project Loom):** https://openjdk.org/projects/loom/
- **ScopedValues:** https://openjdk.java.net/jeps/446
- **AccessController & Stack Walk:** https://docs.oracle.com/javase/tutorial/security/
- **RFC 3986 URI Specification:** https://tools.ietf.org/html/rfc3986
- **OpenJDK Project:** https://openjdk.org/
- **Dirty Chai Repository:** https://github.com/pfirmstone/dirty-chai

---

## API Stability Contract & Multi-Release JAR Strategy

### 1. Dirty Chai API Stability Commitment

Dirty Chai commits to retaining the following APIs as **permanently operational first-class APIs**, regardless of what upstream OpenJDK does:

| API | Dirty Chai Status | Upstream Status (as of JDK 24) | Notes |
|-----|-------------------|-------------------------------|-------|
| `javax.security.auth.Subject.doAs()` | ✅ Permanent | Disabled by default (JEP 486) | Deprecation annotations commented out in `Subject.java` |
| `javax.security.auth.Subject.doAsPrivileged()` | ✅ Permanent | Disabled by default (JEP 486) | Only API accepting explicit `AccessControlContext`; upstream acknowledged no replacement exists |
| `javax.security.auth.Subject.callAs()` | ✅ Permanent | Present; delegates to `doAs()` in Dirty Chai | Always takes the `doAs()` path when SecurityManager is installed |
| `java.security.AccessController` | ✅ Permanent | Disabled by default (JEP 486) | Central to the privilege execution model |
| `java.security.AccessControlContext` | ✅ Permanent | Disabled by default (JEP 486) | Essential for Subject propagation via SubjectDomainCombiner |
| `java.lang.SecurityManager` | ✅ Permanent | Permanently disabled (JEP 486) | Dirty Chai overrides JEP 486 behaviour in `java.base` |
| `au.zeus.jdk.authorization.sm.CombinerSecurityManager` | ✅ Permanent | N/A (Dirty Chai only) | The recommended SecurityManager implementation |
| `au.zeus.jdk.authorization.policy.ConcurrentPolicyFile` | ✅ Permanent | N/A (Dirty Chai only) | Policy enforcement engine |

### 2. Upstream Removal Timeline

| Milestone | JDK Version | JEP / CSR | Effect |
|-----------|-------------|-----------|--------|
| Deprecated for removal | JDK 17 | JEP 411 | `@Deprecated(forRemoval=true)` annotations added |
| Permanently disabled | JDK 24 | JEP 486 | `System.setSecurityManager()` throws `UnsupportedOperationException` on vanilla JDK; APIs still present as class files |
| **Removal** | JDK 26–28 (est.) | No finalised JEP as of April 2026 | Class files removed; code using these APIs fails to **compile** against vanilla `javac` |

> **Dirty Chai patches `java.base` to reverse the JEP 486 disablement.** On a Dirty Chai JVM all listed APIs are fully functional regardless of the upstream JDK version being tracked.

### 3. The Portability Problem

When upstream removes these APIs, application code that uses `Subject.doAs*`, `AccessControlContext`, or `AccessController` will encounter two distinct problems:

| Problem | When It Occurs | Scope |
|---------|----------------|-------|
| **Compile-time failure** | Developer's build machine uses vanilla JDK N toolchain (after removal) | Affects developers building Dirty Chai applications on vanilla JDK toolchains |
| **Runtime failure** | Application runs on a vanilla JDK N JVM (after removal) | Not a concern for Dirty Chai users — the runtime is always a Dirty Chai JVM |

**Key clarification:** Dirty Chai users always run on a Dirty Chai JVM. Runtime portability to vanilla OpenJDK is therefore not a goal. The problem to solve is **compile-time portability** — allowing application source code to be compiled using vanilla JDK toolchains (`javac`, Maven, Gradle with vanilla JDK) while targeting Dirty Chai as the runtime.

### 4. Multi-Release JAR Strategy for a Compat Shim

A **Multi-Release JAR (MRJAR)**, introduced in JEP 238 (JDK 9), allows a single JAR to contain version-specific class implementations under `META-INF/versions/N/`. The JVM selects the highest-versioned implementation it supports.

The strategy is to publish a **separate `au.zeus.jdk.compat` artifact** (not part of the Dirty Chai JDK fork itself) that exposes the Dirty Chai authorization APIs as a library dependency.

#### MRJAR Layout

```
au.zeus.jdk.compat.jar
├── META-INF/
│   └── MANIFEST.MF               (Multi-Release: true)
├── au/zeus/jdk/compat/
│   ├── SubjectCompat.java         (base tier — compiled against Dirty Chai JDK)
│   └── AccessControllerCompat.java
└── META-INF/versions/
    └── N/                          (N = JDK version that removes the APIs)
        └── au/zeus/jdk/compat/
            ├── SubjectCompat.java  (version-N tier — compiled against vanilla JDK N)
            └── AccessControllerCompat.java
```

#### Base Tier (compiled against Dirty Chai)

The base tier delegates directly to the built-in JDK APIs:

```java
// au/zeus/jdk/compat/SubjectCompat.java (base tier)
public final class SubjectCompat {
    public static <T> T doAs(Subject subject, PrivilegedAction<T> action) {
        return Subject.doAs(subject, action);
    }
    public static <T> T doAsPrivileged(Subject subject,
                                       PrivilegedAction<T> action,
                                       AccessControlContext acc) {
        return Subject.doAsPrivileged(subject, action, acc);
    }
}
```

#### Version-N Tier (compiled against vanilla JDK N after removal)

The upper tier provides best-effort emulation for the compile-time stub. Application code compiled against the compat artifact will continue to compile on vanilla toolchains; at runtime on Dirty Chai the base tier is selected, so full semantics apply.

```java
// META-INF/versions/N/au/zeus/jdk/compat/SubjectCompat.java (version-N tier)
public final class SubjectCompat {
    public static <T> T doAs(Subject subject, Callable<T> action) {
        // On vanilla JDK N: delegates to callAs(), which uses ScopedValue path
        // ⚠ Semantics differ from Dirty Chai (no AccessControlContext/SubjectDomainCombiner)
        try {
            return Subject.callAs(subject, action);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    public static <T> T doAsPrivileged(Subject subject,
                                       Callable<T> action,
                                       Object acc) {
        // ⚠ Explicit-context semantics cannot be replicated on vanilla JDK N.
        // Best-effort: ignore acc and delegate to callAs().
        // Applications must not rely on the acc argument on non-Dirty-Chai JVMs.
        return doAs(subject, action);
    }
}
```

### 5. The Hard Case: doAsPrivileged with null ACC

`doAsPrivileged(subject, action, null)` constructs a fresh `AccessControlContext` backed by an empty `ProtectionDomain[]`. This gives the action a **clean, caller-independent privilege context** where only the Subject's own policy grants apply. No caller domain can widen or narrow this context.

This semantics **cannot be replicated** on a vanilla JDK N JVM after API removal, because:
- `AccessControlContext` no longer exists as a class
- `Subject.callAs()` uses `ScopedValue`, which carries no privilege boundary concept
- There is no standard way to "start with zero caller context"

**Recommended approach for application code using null-ACC:**

1. On Dirty Chai JVM: use `Subject.doAsPrivileged(subject, action, null)` directly — full clean-context semantics apply.
2. If compile-time portability is needed: guard the call with a runtime check or abstract it behind an interface, with a Dirty Chai-specific implementation loaded via `ServiceLoader` or factory pattern.
3. Document clearly that the null-ACC isolation guarantee only holds on Dirty Chai.

### 6. Build Toolchain Guidance for Downstream Application Developers

#### Compiling against a Dirty Chai JDK (recommended)

The simplest approach: set the Dirty Chai JDK as the compile-time and runtime JDK. No MRJAR needed. All APIs are present and fully operational.

```xml
<!-- Maven: point JAVA_HOME at the Dirty Chai JDK installation -->
<properties>
    <maven.compiler.source>21</maven.compiler.source>
    <maven.compiler.target>21</maven.compiler.target>
</properties>
```

#### Using the compat shim with a vanilla JDK toolchain

When a vanilla JDK toolchain is mandated (CI, shared build infrastructure, etc.), add the `au.zeus.jdk.compat` artifact as a `provided`/`compileOnly` dependency. At runtime the Dirty Chai JVM's base tier is used; the version-N tier is only active on vanilla JDK N.

```xml
<!-- Maven -->
<dependency>
    <groupId>au.zeus.jdk</groupId>
    <artifactId>dirty-chai-compat</artifactId>
    <version>${dirty-chai.version}</version>
    <scope>provided</scope>
</dependency>
```

#### MANIFEST.MF entry for MRJARs

Any JAR that uses version-specific class directories must declare:

```
Multi-Release: true
```

This is set automatically by Maven's `maven-jar-plugin` (3.x+) when the `multiRelease` flag is enabled, and by Gradle's `compileJava` with `options.release` per source set.

---

## Conclusion

**Dirty Chai** provides **comprehensive protection** against privilege escalation, code injection, and context escape attacks through:

1. **Multi-layer validation** at class loading time
2. **Principal-based authorization** requiring both identity and code source
3. **Independent evaluation** of each dependency
4. **Fail-secure design** with no silent failures
5. **Virtual thread integration** via immutable ACC (SubjectDomainCombiner) + native stack walk
6. **Unified Subject context** via Subject.callAs() → Subject.doAs() delegation (allowSecurityManager = true)
7. **Essential Authorization APIs** (`Subject.doAs()`, `Subject.doAsPrivileged()`, `AccessControlContext`) retained and fully operational; not deprecated in Dirty Chai
8. **PrivilegedAction support** with inherited and explicit contexts
9. **High-performance caching** without sacrificing security
10. **Clear audit trails** for compliance and monitoring

This architecture successfully enforces the **Principle of Least Privilege** while maintaining compatibility with OpenJDK security APIs and achieving high performance in multi-threaded and virtual-threaded environments.

---

**Document Version:** 1.5
**Last Updated:** April 2026
**Classification:** Technical Documentation
**Project:** Dirty Chai - OpenJDK with Authorization
**Base:** OpenJDK (trunk)
**License:** GPL v2 + Classpath Exception
**Subject Context:** Subject.callAs() always delegates to Subject.doAs() in Dirty Chai system (allowSecurityManager() = true)
**Virtual Thread Support:** Fully Integrated via Immutable AccessControlContext + SubjectDomainCombiner + Native Stack Walk
**Essential Authorization APIs:** `Subject.doAs()`, `Subject.doAsPrivileged()`, and `AccessControlContext` retained and fully operational; not deprecated in Dirty Chai


# Performance Analysis: Dirty Chai vs OpenJDK 21

**Last Reviewed:** 2026-04-22

## Overview

This document provides an in-depth analysis of the performance and scalability
characteristics of Dirty Chai's authorization subsystem relative to the stock
OpenJDK 21 baseline. The focus is on the three components that have historically
shown the greatest gains under concurrent workloads:

1. `ConcurrentPolicyFile` — lock-free policy evaluation
2. `CombinerSecurityManager` — parallel, cached permission checking
3. `AccessControlContext` — immutable, globally cached context objects

---

## Background: Contention Hotspots in the Legacy Implementation

The authorization subsystem that existed before Java 17 (and that OpenJDK 21
inherited, but deactivated) suffered from several well-documented contention
sources that dominated performance under concurrency:

| Hotspot | Root cause |
|---------|-----------|
| `Policy.getPolicyNoCheck()` class lock | Static synchronized method, serialized all policy calls (OpenJDK Bug ID 7093090, fixed in JDK 8b15 but the lock remained until JDK 17 deprecation) |
| `ProtectionDomainCache` per-domain cache | `Collections.synchronizedMap(new WeakHashMap<>())` — one global lock across all policy-checking threads |
| `CodeSource.implies()` DNS resolution | `InetAddress.equals()` could trigger blocking reverse-DNS lookups during every `CodeSource` comparison |
| Serial domain stack evaluation | `AccessController.checkPermission` evaluated each domain sequentially; a `SocketPermission` on any domain blocked the whole stack |
| `AccessControlContext` object churn | A new `AccessControlContext` was allocated per `doPrivileged` call; virtual-thread workloads that create thousands of lightweight threads exacerbate allocation pressure |

Dirty Chai re-activates a fully operational authorization framework while
eliminating every one of these hotspots.

---

## 1. ConcurrentPolicyFile

**Source:** `src/java.base/share/classes/au/zeus/jdk/authorization/policy/ConcurrentPolicyFile.java`

### 1.1 Lock-free hot path

The entire `implies(ProtectionDomain, Permission)` and `getPermissions(ProtectionDomain)`
path holds **no lock**. The grant list is stored as a `volatile PermissionGrant[]` field
(`grantArray`). At the start of every evaluation, the field is captured into a
method-local variable:

```java
PermissionGrant[] grantRefCopy = grantArray;   // single volatile read
int l = grantRefCopy.length;                   // all subsequent access is thread-local
```

After this one-instruction fence, the hot path is entirely stack-allocated and
requires no shared-memory coordination. Concurrent threads can evaluate policy
simultaneously with no mutual interference.

In contrast, the legacy `sun.security.provider.PolicyFile` maintained a
`ProtectionDomainCache` backed by `Collections.synchronizedMap(new WeakHashMap<>())`.
Every `implies()` call first acquired that global lock to look up or populate a
cached `PermissionCollection`. Under high thread counts this became a severe
serialization bottleneck — scalability was essentially capped at single-threaded
throughput for the cache look-up phase.

At the VM layer, Dirty Chai also removed the native protection-domain cache in
commit `20f1c9861a70a357d6f4e316c935a6451f504347` (`#71`), deleting:

- `src/hotspot/share/classfile/protectionDomainCache.hpp`
- `src/hotspot/share/classfile/protectionDomainCache.cpp`

This aligns VM behavior with the Java-layer design: no global per-domain cache
on the permission hot path, and no synchronized cache lookup in front of policy
evaluation.

### 1.2 Intentional absence of a permission cache

The class-level Javadoc explicitly states:

> _"Caching limits scalability and consumes shared memory, so no cache exists."_

A permissions cache may appear to improve throughput for a single thread but
introduces shared mutable state that must be synchronized. At scale, the cache
itself becomes the bottleneck. By computing permissions fresh on each call from
an immutable, already-loaded grant array, every thread operates in private memory
with zero cache-coherency traffic beyond reading the `volatile` grant reference.

### 1.3 RFC 3986 URI comparison — no DNS calls

The legacy `CodeSource.implies(CodeSource)` method called `InetAddress.equals()`
on the location URLs, which could trigger a blocking **reverse-DNS lookup** to
compare an IP address against a hostname. A single slow DNS response could stall
an entire permission-checking thread for hundreds of milliseconds.

`ConcurrentPolicyFile` uses `URIGrant`, which converts all policy URLs to
`au.zeus.jdk.net.Uri` instances at parse time and compares them as normalized
strings. No DNS call is ever made during `implies()`.

### 1.4 Bit-shift case conversion in URI normalization

`Uri.java` includes this noteworthy optimization:

```java
private final static char upperCaseBitwiseMask = 0xdf;
private final static char lowerCaseBitwiseMask = 0x20;

// To uppercase ASCII:
return (char) (c & upperCaseBitwiseMask);

// To lowercase ASCII:
return (char) (c | lowerCaseBitwiseMask);
```

`String.toLowerCase()` allocates a new `String`, performs locale-aware
processing, and is non-trivial for the JIT to inline. The bitwise approach
produces a single CPU instruction per character and allocates nothing. During
profiling of the JGDMS predecessor to this policy implementation, string case
conversion during URI normalization was identified as a measurable hotspot; this
optimization removed it.

### 1.5 PermissionComparator — avoids expensive Permission methods

Permissions are stored and sorted in a `NavigableSet<Permission>` using
`PermissionComparator`, which orders permissions by class name, target name, and
actions without calling `Permission.hashCode()` or `Permission.equals()`.

This matters because some standard permission classes perform expensive work in
those methods. For example:

- `SocketPermission.hashCode()` performs hostname normalization.
- `FilePermission.equals()` on some platforms performs canonical-path resolution.

By routing all set operations through a `Comparator` that uses only string
fields, `ConcurrentPolicyFile` avoids triggering that cost during policy
evaluation.

### 1.6 Early-exit for privileged domains

The `implies()` loop processes privileged grants (those granting `AllPermission`)
before less-privileged grants. If the domain is privileged, the method returns
immediately with `true`, skipping the full grant scan. This is both a correctness
requirement (to prevent infinite recursion when privileged domains participate
in policy evaluation) and a performance optimization for the common case in
server-side code where most infrastructure classes hold `AllPermission`.

---

## 2. CombinerSecurityManager

**Source:** `src/java.base/share/classes/au/zeus/jdk/authorization/sm/CombinerSecurityManager.java`

### 2.1 Architecture overview

`CombinerSecurityManager` operates with two independent, non-blocking caches and
a parallel execution strategy for multi-domain stacks:

```
checkPermission(perm)
    │
    ├─ [already checked for this context?]
    │       checked: ConcurrentHashMap<context, ConcurrentSkipListSet<Permission>>
    │       TTL: 20 seconds (time-based, non-blocking eviction)
    │       └─ YES → return immediately
    │
    ├─ [delegate context cached?]
    │       contextCache: ConcurrentHashMap<ACC, delegate ACC>
    │       TTL: 60 seconds (time-based, non-blocking eviction)
    │       └─ YES → use cached delegate context
    │           NO → build, optimize, and cache
    │
    └─ delegateContext.checkPermission(perm)
           └─ DelegateProtectionDomain.implies(perm)
                  ├─ [< 4 domains?] → sequential check
                  └─ [≥ 4 domains?] → parallel check via VirtualThreadPerTaskExecutor
```

### 2.2 Permission result cache (`checked`)

The `checked` cache stores the set of permissions already verified for each
`AccessControlContext`. On subsequent calls with the same context and the same
permission, the check returns immediately without any policy consultation:

```java
if (checkedPerms.contains(perm)) return; // don't need to check again.
```

The key design choices:

- **`ConcurrentHashMap`** as the outer map — non-blocking reads and lock-striped writes.
- **`ConcurrentSkipListSet`** as the per-context permission set — non-blocking
  concurrent adds and contains checks even under GC pressure. A `synchronized`
  set here would block threads during collection-triggered removals, creating
  latency spikes precisely when the JVM is already under memory stress.
- **Time-based `RC` eviction** (20-second TTL) — stale entries are collected
  asynchronously without holding any lock on the hot path. On a `policy.refresh()`
  call the `checked` map is cleared atomically.

### 2.3 Context optimization cache (`contextCache`)

The `contextCache` stores the optimized delegate `AccessControlContext` derived
from each original context via `DelegateDomainCombiner`. Building this delegate
context is the most expensive step in the first call for a new context (it
involves a `doPrivileged` + `getContext()` round-trip). After the first call,
subsequent threads with the same context pay only a `ConcurrentHashMap.get()`
cost — a few nanoseconds.

TTL is set to 60 seconds, matching the typical lifetime of a server request
processing context.

### 2.4 Parallel domain permission checks

For call stacks with **four or more protection domains**, `DelegateProtectionDomain.implies()`
submits each domain's check as an independent `FutureTask` to a
`Executors.newVirtualThreadPerTaskExecutor()`:

```java
if (l < 4) {
    // Sequential — fast for common privileged cases
    for (int i = 0; i < l; i++) {
        if (!checkPermission(context[i], perm)) return false;
    }
    return true;
}
CountDownLatch latch = new CountDownLatch(l);
// Submit l tasks to the virtual-thread executor in parallel
// Wait on latch; aggregate results
```

**Why this scales:**

- Under sequential evaluation, a single `SocketPermission` check that blocks on
  hostname resolution holds up all subsequent domain checks in the same stack.
  With parallel evaluation, all domain checks proceed concurrently; the total
  latency is bounded by the slowest single check rather than the sum of all
  checks.
- Using `VirtualThreadPerTaskExecutor` means each task runs on a virtual thread.
  If a task blocks on I/O, only that virtual thread is suspended; the underlying
  carrier thread is freed to run other work. Under high concurrency, this avoids
  OS thread starvation that would occur with a fixed-size platform thread pool.
- The threshold of four domains is both a performance optimization (the overhead
  of task creation and latch synchronization is not justified for tiny stacks)
  and a safety precaution against policy-internal recursive checks that could
  cause deadlock if parallelized prematurely.

### 2.5 ScopedValue for recursion depth tracking

Recursive permission check depth is tracked via `ScopedValue<Integer>` rather
than `ThreadLocal`. `ScopedValue` is structured data with a well-defined binding
scope; it avoids the per-`ThreadLocal` map lookup and initialization overhead
that `ThreadLocal` incurs on first access for each new thread (including virtual
threads, which are allocated in large numbers).

### 2.6 Self-bypass for SecurityManager's own context

```java
if (constructed
        && (SMPrivilegedContext.equals(executionContext)
        || SMConstructorContext.equals(executionContext)
        )) return; // prevents endless loop in debug
```

If the context being checked belongs to the security manager itself, the check
short-circuits immediately. This eliminates the potential for infinite recursion
and removes overhead for all internal security manager operations.

---

## 3. AccessControlContext Caching

**Sources:**
- `src/java.base/share/classes/java/security/AccessControlContext.java`
- `src/java.base/share/classes/java/security/ContextCache.java`
- `src/java.base/share/classes/java/security/DomainIdentity.java`

### 3.1 Global interning cache

`ContextCache` (loaded by the VM at the end of VM initialization phase 2)
initializes a `ConcurrentSkipListMap` keyed by `ContextKey` and valued by
`AccessControlContext` with **weak value references** and a 2-second eviction
cycle:

```java
ConcurrentMap<AccessControlContext.ContextKey, AccessControlContext> CONTEXTS
    = RC.concurrentMap(new ConcurrentSkipListMap<>(),
                       Ref.STRONG, Ref.WEAK, 2000L, 2000L);
AccessControlContext.initCache(CONTEXTS);
```

Every `AccessControlContext.create(...)` call path checks this cache before
allocating a new instance. Callers sharing identical domain stacks — which is the
common case for virtual threads running the same task type — receive the same
`AccessControlContext` instance, eliminating redundant heap allocation.

The `CombinerSecurityManager.contextCache` works _on top of_ this: it maps the
original shared `AccessControlContext` to its optimized delegate, so that
optimization cost is paid at most once per unique context, regardless of how many
threads share it.

### 3.2 Pre-computed, immutable hashCode

Every `AccessControlContext` computes its `hashCode` at construction time:

```java
hash = hash * 27 + (context != null ? asSet(context).hashCode() : 0);
hash = hash * 27 + Objects.hashCode(privilegedContext);
hash = hash * 27 + Objects.hashCode(combiner);
hash = hash * 27 + (isPrivileged ? 1 : 0);
```

This means:
- `ConcurrentSkipListMap` and `ConcurrentHashMap` lookups resolve to an O(1)
  integer comparison before any deeper equality check.
- `ContextKey.equals()` performs a hash-code short-circuit guard, avoiding
  expensive set-equality checks for non-matching entries.

### 3.3 DomainIdentity — value-based domain equality without DNS

`DomainIdentity` is a `ProtectionDomain` subclass used for temporary contexts
(e.g. the domain pushed by `doPrivileged` with permission constraints). It
overrides `equals()` and `hashCode()` to be value-based using its fields.

Critically, it wraps `CodeSource` in a `UriCodeSource` that replaces
`CodeSource.equals()` with an RFC 3986 URI comparison:

```java
private static class UriCodeSource extends CodeSource {
    private final Uri uri;
    // hashCode and equals use uri, not CodeSource.equals()
}
```

`CodeSource.equals()` in the JDK calls `InetAddress.getByName()` (another
potential DNS call) when comparing IP-addressed locations. `DomainIdentity`
eliminates this for all temporary domain equality comparisons made by both
`AccessControlContext.ContextKey` and `CombinerSecurityManager.contextCache`.

---

## 4. Summary of Scalability Improvements

| Mechanism | OpenJDK 21 baseline | Dirty Chai |
|-----------|---------------------|------------|
| Policy `implies()` concurrency | Global lock on per-domain permission cache | Lock-free via volatile array reference |
| DNS resolution during policy check | Possible on every `CodeSource.implies()` | Eliminated; RFC 3986 string comparison only |
| String case conversion in URI norm. | `String.toLowerCase()` — allocating, locale-aware | Bitwise `& 0xDF` / `| 0x20` — zero allocation |
| Permission set operations | `Permission.hashCode()` / `equals()` (can trigger I/O) | `PermissionComparator` — string fields only |
| Policy class lock | Static synchronized (Bug 7093090; remained until SM deprecation) | No class lock; policy reference is a volatile read |
| SecurityManager permission check | Per-check policy evaluation, sequential | Two-level non-blocking cache; O(1) for repeated (context, perm) pairs |
| Multi-domain stack evaluation | Sequential per domain | Parallel via `VirtualThreadPerTaskExecutor` for stacks ≥ 4 domains |
| Cache eviction under GC pressure | `synchronized` WeakHashMap — blocks during collection | `ConcurrentSkipListSet` / time-based RC eviction — non-blocking |
| `AccessControlContext` allocation | New object per `doPrivileged` | Global interning cache; shared contexts return same instance |
| Context equality (used in cache lookups) | `CodeSource.equals()` — potential DNS call | `DomainIdentity`/`UriCodeSource` — URI string comparison only |

### Qualitative throughput profile

- **Single-threaded, no SecurityManager** (OpenJDK 21 baseline): No change.
  The SecurityManager-absent code path is not modified.

- **Single-threaded, with SecurityManager**: Small positive improvement for
  repeated `(context, permission)` pairs due to the `CombinerSecurityManager`
  `checked` cache. First-call cost is similar to or slightly higher than a raw
  `AccessController.checkPermission` because of cache lookup overhead.

- **Multi-threaded, moderate contention (4–16 threads)**: Significant
  improvement. `ConcurrentPolicyFile` eliminates global-lock serialization; all
  threads evaluate policy in parallel. The `checked` cache further reduces policy
  evaluations proportionally to how often the same (context, permission) pair
  recurs.

- **Multi-threaded, high contention (16+ threads), policy-heavy workload**: The
  dominant advantage. The old implementation scaled sub-linearly due to
  synchronized cache contention. `ConcurrentPolicyFile` scales near-linearly with
  available CPU cores because every thread operates on thread-private state derived
  from a single volatile read.

- **Virtual thread workloads (thousands of concurrent tasks)**: The
  `AccessControlContext` interning cache and `VirtualThreadPerTaskExecutor`-based
  parallel domain checks are specifically designed for this scenario. The interning
  cache prevents allocation blow-up when thousands of virtual threads share
  identical domain stacks. The virtual-thread executor prevents OS thread starvation
  when some domain checks are I/O-bound (e.g. `SocketPermission` with hostname
  resolution).

- **`SocketPermission` in domain stack**: Previously, a single `SocketPermission`
  check could block the entire sequential domain evaluation for potentially hundreds
  of milliseconds. With parallel domain evaluation (≥4 domains), the I/O-bound
  check runs concurrently with all other domain checks, reducing total check latency
  to the duration of the slowest single check.

### Overhead added by new security guards

Dirty Chai introduces additional permission guards on several formerly unguarded
paths. These add overhead compared to OpenJDK 21 (which had no such checks
active):

| Guard | Path | Per-call cost (SM active) |
|-------|------|--------------------------|
| `LoadClassPermission` | `SecureClassLoader.defineClass()` | One `checkPermission` call per class definition |
| `SerialObjectPermission` | `ObjectInputStream.readOrdinaryObject()` | One `checkPermission` call per deserialized object |
| `NativeInvocationPermission` | `ClassLoader.findNative()`, `SymbolLookup`, `SystemLookup`, `MemorySegment.reinterpret()` | One `checkPermission` call per native symbol invocation / reinterpret call |
| `setSecurityManager` stack validation | Custom SM installation | One-time StackWalker scan (≤50 frames); trusted SMs skip entirely |

For class loading and deserialization these checks are dominated by the I/O and
class resolution work that already occurs on those paths. The marginal cost is
well within the `< 1%` figure cited for authorization overhead in production-like
benchmarks.

---

## 5. Recommended JVM Tuning

Because `CombinerSecurityManager` and the `AccessControlContext` cache create and
discard many short-lived objects (permission sets, context keys), the JVM should
be tuned for a **large young generation**:

```
-Xmn512m        # or larger depending on heap size
-XX:+UseG1GC    # G1's region-based young collection handles short-lived object bursts well
```

The `CombinerSecurityManager` Javadoc notes this explicitly:

> _"This SecurityManager should be tuned for garbage collection for a large young
> generation heap, since many young objects are created and discarded."_

---

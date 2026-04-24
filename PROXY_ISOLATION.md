# Proxy Isolation Architecture for JGDMS ServiceDiscoveryManager

**Last Reviewed:** 2026-04-24

This document describes a complete design for integrating bytecode analysis and
selective process isolation into JGDMS's `ServiceDiscoveryManager` and
`LookupCacheImpl` proxy loading pipeline (Option C: Hybrid — Bytecode Analysis
Gate + Selective Isolation).

> This document focuses on client-side proxy trust boundaries and the
> `ServiceDiscoveryManager` / `LookupCacheImpl` integration layer.  For
> DirtyChai's in-process security model, see `SECURITY_ANALYSIS.md`.  For
> multi-process isolation of service *implementations*, see
> `PROCESS_ISOLATION.md`.

---

## 1) Problem Statement

When a client downloads a smart proxy from a Jini/JGDMS lookup service, that
proxy runs in the client's JVM.  Once loaded, the proxy can access all
client-side resources that the client's policy permits.  The existing trust
model — signed proxy JARs, `Integrity.YES` JERI constraint, `GrantPermission`,
and `SerialObjectPermission` — authenticates *who* supplied the proxy but does
not contain *what* the proxy can do once it is running inside the client
process.

This creates three distinct risks that the existing in-process security controls
do not fully address:

| Risk | Description |
|---|---|
| **Compromised proxy** | A proxy whose JAR was tampered with after signing, or whose service was taken over, can exfiltrate client data or corrupt shared heap state |
| **Malicious proxy** | An adversary who controls a lookup service can install a proxy designed to attack co-located proxies sharing the same client JVM |
| **Cross-service contamination** | A buggy or hostile proxy from Service A can corrupt data structures used by a proxy from Service B if both share the same heap and thread pool |

The goal of this architecture is to interpose an **isolation decision** in the
`ServiceDiscoveryManager` proxy loading pipeline so that:

- Well-behaved proxies (`@AtomicSerial`, stateless, no `synchronized`) run
  with minimal overhead in a bounded thread pool.
- Risky proxies (mutable statics, carrier-thread-pinning `synchronized`,
  non-`@AtomicSerial`, high-entropy native calls) are automatically routed to a
  subprocess or heavier isolation container, transparently to the calling
  application.

---

## 2) Architecture Overview

```
ServiceDiscoveryManager
│
│  (one per lookup discovery)
├─ Extension Point 1: Lookup Service Discovery
│     → Trigger background bytecode analysis of all proxy JARs
│        from this lookup service
│
│  LookupCacheImpl — per-lookup-service cache
│
│  (once per service discovery, on cache ingestion)
├─ Extension Point 2: First-Stage Filter (ServiceItemReg)
│     → Persist analysis result and isolation decision in ServiceItemReg
│     → Assign IsolationMode: NONE / POOL / PROCESS
│
│  (per application lookup call)
├─ Extension Point 3: On-Demand Lookup + Second-Stage Filter
│     → Lazy-create isolation context if IsolationMode != NONE
│     → Wrap proxy in IsolationProxy before returning to caller
│
│  (application-controlled)
└─ Extension Point 4: ServiceItemFilter Pipeline
      → Application filter can inspect analysis results and veto
         or upgrade isolation level before proxy is handed out
```

The architecture intentionally fits inside JGDMS's existing
`ServiceDiscoveryManager` and `LookupCacheImpl` structure.  No new public API
surface is required for the common path; isolation is transparent to application
code that does not opt into configuration.

---

## 3) Complete Proxy Lifecycle

```
1. Lookup service discovered
      └─ [EP1] Schedule background bytecode analysis for all known proxy JARs
             from this lookup service

2. Reggie returns a ServiceItem for a new service
      └─ [EP2] First-stage filter on ingestion into LookupCacheImpl
             └─ If analysis is complete:
                  Store AnalysisResult + IsolationDecision in ServiceItemReg
             └─ If analysis is pending:
                  Mark ServiceItemReg.pendingAnalysis = true
                  Store provisional IsolationMode based on policy default

3. Application calls LookupCache.lookup(template, filter, maxMatches)
      └─ [EP3] For each matching ServiceItemReg:
             └─ If IsolationMode == NONE:
                  Return proxy reference directly (zero overhead)
             └─ If IsolationMode == POOL:
                  Lazy-create bounded VirtualThreadPool executor
                  Wrap proxy in PoolIsolationProxy(proxy, executor, ttl)
             └─ If IsolationMode == PROCESS:
                  Lazy-create ProcessBoundaryContext (subprocess + JERI stub)
                  Wrap proxy in ProcessIsolationProxy(stub)

4. Application calls proxy.method(args)
      └─ IsolationProxy intercepts the call
             └─ Submit to executor / IPC channel with per-call timeout
             └─ Marshal return value back to caller thread
             └─ On timeout: throw IsolationTimeoutException (subtype of RemoteException)

5. Service lease expires or is cancelled
      └─ [PostEventState hook] Cleanup:
             └─ Shutdown isolation context executor
             └─ Terminate subprocess (PROCESS mode)
             └─ Evict ServiceItemReg from LookupCacheImpl
```

---

## 4) Four Extension Points

### 4.1  Extension Point 1 — Lookup Service Discovery

**When:** Once per lookup service registered with `ServiceDiscoveryManager`.

**Where:** Inside the `LookupDiscoveryListener.discovered(...)` callback (or
equivalent internal hook in `ServiceDiscoveryManager`) that fires when a new
Reggie is found.

**What happens:**

```
LookupDiscoveryListener.discovered(DiscoveryEvent)
  └─ for each new lookup service registrar:
        IsolationAnalysisScheduler.schedule(registrar)
          └─ Background task:
               1. Query registrar for all currently registered services
               2. Fetch proxy JAR URLs from each ServiceItem's codebase
               3. Submit to BytecodeAnalyzer (pluggable — see §7)
               4. Store AnalysisResult in IsolationDecisionCache keyed by
                  (codebaseURLs, proxyClassNames)
               5. Update any pending ServiceItemReg entries
```

**Cost:** One background pass per newly discovered lookup service.  Results are
cached long-term (keyed by `(codebase, proxy-class-set)`), so re-discovery of
the same lookup service or re-registration of the same service incurs no
re-analysis cost.

### 4.2  Extension Point 2 — First-Stage Filter (ServiceItemReg ingestion)

**When:** Once per newly discovered service, at the point a `ServiceItem` is
first added to `LookupCacheImpl`'s internal `serviceItemRegs` map.

**Where:** Inside the `PreEventState` handler that processes `ServiceRegistrar`
event notifications for new services.

**What happens:**

```
PreEventState.handle(ServiceEvent)
  └─ Existing: create ServiceItemReg, add to serviceItemRegs
  └─ New hook: IsolationDecider.classifyOnIngestion(ServiceItemReg reg, ServiceItem item)
        1. Look up AnalysisResult in IsolationDecisionCache
           (keyed by codebase attribute + proxy class names)
        2a. Cache hit:
              reg.analysisResult  = cached result
              reg.isolationMode   = policy.decide(analysisResult)
        2b. Cache miss:
              reg.analysisResult  = PENDING
              reg.isolationMode   = policy.defaultMode()
              (background analysis scheduled via EP1 path)
        3. Record decision timestamp (isolationDecidedAt)
```

This step is lightweight: it is a cache lookup plus an enum assignment.  It does
not create any executor or subprocess.

### 4.3  Extension Point 3 — On-Demand Lookup with Second-Stage Filter

**When:** Per `LookupCache.lookup(...)` call from application code.

**Where:** Inside the `getProxies(...)` / `lookup(...)` method of
`LookupCacheImpl`, immediately before the proxy reference is returned to the
application.

**What happens:**

```
LookupCacheImpl.lookup(template, filter, maxMatches)
  └─ Existing: find matching ServiceItemReg entries, apply ServiceItemFilter
  └─ New hook: for each matched reg, before returning:
        IsolationContextProvider.getOrCreateContext(reg)
          └─ If reg.isolationMode == NONE:
               return reg.proxy directly
          └─ If reg.isolationMode == POOL:
               if (reg.isolationContext == null || !reg.isolationContext.isHealthy())
                 reg.isolationContext = executorFactory.createPoolContext(reg)
               return new PoolIsolationProxy(reg.proxy, reg.isolationContext)
          └─ If reg.isolationMode == PROCESS:
               if (reg.isolationContext == null || !reg.isolationContext.isHealthy())
                 reg.isolationContext = executorFactory.createProcessContext(reg)
               return new ProcessIsolationProxy(reg.isolationContext.getStub())
```

The isolation context is lazy-created on first access and health-checked on
every subsequent access.  A dead context is recreated transparently.

### 4.4  Extension Point 4 — ServiceItemFilter Pipeline

**When:** Per application lookup, inside the `ServiceItemFilter.check(...)` call
chain.

**What happens:** Application code provides a `ServiceItemFilter` to
`LookupCache.lookup(...)`.  Before calling the application's filter, the
framework prepares a `FilterContext` that exposes the `AnalysisResult` for the
candidate service item.  The application filter may:

- Accept the proxy as-is (normal case).
- Upgrade the isolation level (`reg.isolationMode = PROCESS`) for a specific
  service it considers high risk.
- Reject the proxy entirely (`return false`) if analysis findings exceed a
  threshold the application defines.

This extension point gives application code full control over the final isolation
decision without requiring the application to know anything about bytecode
analysis internals.

---

## 5) ServiceItemReg as Isolation Hub

`ServiceItemReg` is JGDMS's internal per-service cache entry inside
`LookupCacheImpl`.  It already holds the `ServiceItem`, the lease, and event
registration state.  The proxy isolation architecture extends it with three
optional groups of fields:

### 5.1  Bytecode Analysis Fields (long-term, per service identity)

```java
// Key used to look up cached analysis results:
//   hash of (codebase URL set, proxy class name set)
String             analysisKey;

// Result produced by BytecodeAnalyzer; null until analysis completes
AnalysisResult     analysisResult;   // PENDING | CLEAN | LOW | MEDIUM | HIGH | CRITICAL

// Wall-clock time when analysisResult was last set
long               analysisTimestamp;
```

These fields are set once when the service is first ingested (or updated when
background analysis completes) and do not change unless the proxy JAR codebase
changes.

### 5.2  Isolation Decision Fields (medium-term, per isolation policy version)

```java
// NONE / POOL / PROCESS — derived from (analysisResult, policyVersion)
IsolationMode      isolationMode;

// Policy version at decision time — decision is invalidated if policy is refreshed
int                policyVersion;

// Findings that drove the decision (subset of analysisResult.findings)
List<Finding>      isolationFindings;
```

These fields are recomputed when the `IsolationPolicy` is refreshed or when a
new `AnalysisResult` becomes available.

### 5.3  Isolation Context Fields (short-term, lifetime ≤ service lease)

```java
// Live executor or IPC channel for this service proxy; null in NONE mode
IsolationContext   isolationContext;

// Lease expiry instant used to bound context lifetime
long               leaseExpiresAt;

// Rolling health counters for the context
long               callsSucceeded;
long               callsFailed;
long               callsTimedOut;
```

The `isolationContext` is created lazily on first `lookup(...)` call and is
discarded when the service lease expires or is cancelled.

---

## 6) Configuration Injection

`ServiceDiscoveryManager` is extended with five new optional configuration
entries.  All are backward-compatible: when absent, the manager behaves exactly
as the unmodified JGDMS implementation.

```java
ServiceDiscoveryManager mgr = new ServiceDiscoveryManager(
    discoveryMgr,
    leaseRenewalMgr,
    /* optional new entries: */
    new Entry[] {
        new ProxyIsolationPolicyEntry(ProxyIsolationPolicy.BYTECODE_ANALYSIS_AWARE),
        new BytecodeAnalyzerEntry(new AsmBytecodeAnalyzer()),
        new IsolationExecutorFactoryEntry(new VirtualThreadPoolFactory(maxParallelism)),
        new IsolationDecisionCacheEntry(new ConcurrentHashMapDecisionCache(maxEntries)),
        new IsolationMethodCallTimeoutEntry(Duration.ofSeconds(30))
    }
);
```

### 6.1  `proxyIsolationPolicy`

Controls how the analysis result maps to an `IsolationMode`:

| Policy Enum Value | Behaviour |
|---|---|
| `PERMISSIVE` | Never isolate; return proxy directly regardless of analysis result |
| `STRICT` | Always isolate in PROCESS mode, even for clean proxies |
| `BYTECODE_ANALYSIS_AWARE` | Route by severity: CLEAN → NONE, LOW/MEDIUM → POOL, HIGH/CRITICAL → PROCESS |
| `TRUST_ON_FIRST_USE` | First encounter: POOL until analysis completes; upgrade/downgrade after result |

Default when absent: `PERMISSIVE` (matches unmodified JGDMS behaviour).

### 6.2  `bytecodeAnalyzer`

A pluggable `BytecodeAnalyzer` interface:

```java
public interface BytecodeAnalyzer {
    /**
     * Analyzes all classes accessible from the given codebase URLs.
     *
     * @param codesource  codebase URL set identifying the proxy JAR(s)
     * @param classNames  proxy class names to analyze
     * @return analysis result with severity and individual findings
     */
    AnalysisResult analyze(Set<URL> codesource, Set<String> classNames)
        throws AnalysisException;
}
```

Default when absent: a no-op analyzer that always returns `AnalysisResult.CLEAN`.

The reference implementation uses ASM to detect:

- `synchronized` blocks on non-private objects (carrier-thread pinning risk)
- `static` mutable fields accessed without synchronization (data-race risk)
- Classes not annotated with `@AtomicSerial` (gadget-chain risk)
- Native method declarations not covered by `NativeInvocationPermission`
  (native-code escape risk)

### 6.3  `isolationExecutorFactory`

A pluggable factory that creates `IsolationContext` objects for a given
`ServiceItemReg`:

```java
public interface IsolationExecutorFactory {
    IsolationContext createPoolContext(ServiceItemReg reg);
    IsolationContext createProcessContext(ServiceItemReg reg);
}
```

Two built-in implementations are provided:

**`VirtualThreadPoolFactory`** — creates a bounded `ForkJoinPool`-backed
virtual thread executor for POOL mode.  Each service gets its own pool so a
saturated proxy cannot starve other services.

**`ProcessBoundaryFactory`** — forks a subprocess running a minimal JVM with
`-Djava.security.manager=default` and a tightly scoped policy file, then
creates a JERI stub back to that subprocess for PROCESS mode.

### 6.4  `isolationDecisionCache`

An L1 cache of `AnalysisResult` values keyed by `(codebase, proxy-class-set)`.
Decouples the per-service lifecycle from the expensive bytecode analysis pass.

```java
public interface IsolationDecisionCache {
    Optional<AnalysisResult> get(String analysisKey);
    void put(String analysisKey, AnalysisResult result);
    void invalidate(String analysisKey);
    void invalidateAll();  // called on full policy refresh
}
```

Default when absent: a `ConcurrentHashMap`-backed unbounded cache (analysis
results are small and stable, so unbounded growth is not a concern in practice).

### 6.5  `isolationMethodCallTimeout`

A `Duration` applied as a per-call deadline inside `PoolIsolationProxy` and
`ProcessIsolationProxy`.  Calls that do not complete within this duration receive
an `IsolationTimeoutException` (extends `RemoteException`), and the caller thread
is not blocked beyond the deadline.

Default when absent: no timeout (matches unmodified JGDMS behaviour).

---

## 7) Caching Strategy

The caching design separates two concerns with different lifetimes:

### 7.1  Analysis result cache (long TTL — days to weeks)

- **Key:** `SHA-256(sort(codebase URLs) + sort(proxy class names))`
- **TTL:** Long (default: 7 days, or until proxy JAR codebase changes)
- **Location:** `IsolationDecisionCache` (configurable, typically off-heap or
  persistent)
- **Invalidation:** Triggered by:
  - Change to the proxy JAR codebase attribute for a service
  - Manual `IsolationDecisionCache.invalidateAll()` call (e.g. after analyzer
    upgrade)
  - Policy refresh (isolation *decision* is recomputed from the cached *result*)

Analysis is expensive (ASM class-file walk over proxy JARs) and the result for a
given JAR version is stable.  It is never repeated unless the JAR changes.

### 7.2  Isolation context (short TTL — subordinate to service lease)

- **TTL:** Bounded by the service lease expiry (`leaseExpiresAt`)
- **Location:** `ServiceItemReg.isolationContext` (in-memory only)
- **Lazy-creation:** On first `lookup(...)` call after the service is discovered
- **Health check:** On every `lookup(...)` call (`isolationContext.isHealthy()`)
- **Eviction:** When the lease expires, the `PostEventState` handler disposes
  the context:

```
PostEventState.handle(ServiceRemovedEvent)
  └─ Existing: evict ServiceItemReg from serviceItemRegs
  └─ New hook: IsolationContextDisposer.dispose(reg)
        └─ reg.isolationContext.shutdown()   // graceful drain
        └─ reg.isolationContext = null
        (PROCESS mode: also terminates the subprocess)
```

### 7.3  Decision cache vs. context cache

```
                    ┌──────────────────────────────────────────┐
                    │         IsolationDecisionCache            │
                    │   (long-lived, keyed by JAR fingerprint)  │
                    │                                          │
                    │  "This proxy class is HIGH severity"     │
                    └──────────────────┬───────────────────────┘
                                       │ feeds
                                       ▼
                    ┌──────────────────────────────────────────┐
                    │         ServiceItemReg.isolationMode      │
                    │   (medium-lived, per policy version)      │
                    │                                          │
                    │  "Route this service via PROCESS"        │
                    └──────────────────┬───────────────────────┘
                                       │ drives lazy creation of
                                       ▼
                    ┌──────────────────────────────────────────┐
                    │         ServiceItemReg.isolationContext   │
                    │   (short-lived, lifetime ≤ lease)         │
                    │                                          │
                    │  "ForkJoinPool / subprocess handle"      │
                    └──────────────────────────────────────────┘
```

The layered design means:
- Bytecode analysis is never repeated for the same JAR version.
- Isolation contexts are not created until they are actually needed.
- A service that expires and re-registers inherits the cached analysis but
  starts a fresh isolation context.

---

## 8) State Machine Integration

`LookupCacheImpl` manages service lifecycle through a set of internal
`BiFunction` handlers keyed by event type (loosely: `PreEventState` for
additions, `TransitionEventState` for attribute changes, `PostEventState` for
removals).  The isolation hooks attach to three of these states.

### 8.1  PreEventState — analyze proxy on discovery

```
PreEventState.apply(ServiceRegistrar reg, ServiceEvent evt)
  Existing responsibilities:
    - validate event sequence numbers
    - add ServiceItem to serviceItemRegs
    - schedule lease renewal
  New responsibility:
    - call IsolationDecider.classifyOnIngestion(serviceItemReg, serviceItem)
      (see §4.2 — lightweight cache lookup + enum assignment)
```

### 8.2  TransitionEventState — recheck on attribute change

```
TransitionEventState.apply(ServiceRegistrar reg, ServiceEvent evt)
  Existing responsibilities:
    - update ServiceItem attributes in serviceItemRegs
  New responsibility:
    - if proxy JAR codebase attribute changed:
        invalidate IsolationDecisionCache entry for old codebase
        reset reg.analysisResult = PENDING
        reset reg.isolationMode  = policy.defaultMode()
        schedule re-analysis via EP1 path
    - else (non-codebase attribute change):
        no isolation action needed
```

### 8.3  PostEventState — cleanup isolation context on removal

```
PostEventState.apply(ServiceRegistrar reg, ServiceEvent evt)
  Existing responsibilities:
    - remove ServiceItem from serviceItemRegs
    - cancel lease renewal
  New responsibility:
    - call IsolationContextDisposer.dispose(serviceItemReg)
      (graceful executor drain + optional subprocess termination)
```

### 8.4  On-lookup — lazy context creation and proxy wrapping

```
LookupCacheImpl.getProxies(template, filter, maxMatches)
  Existing: filter serviceItemRegs by template + ServiceItemFilter
  New (after filter passes):
    for each matched reg:
      wrappedProxy = IsolationContextProvider.getOrCreateContext(reg)
                                                 .wrapProxy(reg.proxy)
      (NONE mode: wrapProxy is identity — zero overhead)
```

---

## 9) Package Hierarchy

The new types introduced by this architecture live in a sub-package of
`org.apache.river` (or equivalent JGDMS package) to keep the isolation
infrastructure clearly separated from the discovery cache core:

```
org.apache.river.lookup.isolation
├── IsolationMode                (enum: NONE, POOL, PROCESS)
├── IsolationDecision            (record: mode + severity + findings)
├── IsolationContext             (interface: isHealthy, shutdown, wrapProxy)
├── IsolationContextProvider     (lazy context factory, stateful)
├── IsolationContextDisposer     (cleanup helper)
├── IsolationDecider             (policy + cache + analysis → IsolationMode)
├── IsolationDecisionCache       (interface + ConcurrentHashMap default impl)
├── IsolationExecutorFactory     (interface)
├── IsolationProxy               (base class for PoolIsolationProxy + ProcessIsolationProxy)
├── IsolationTimeoutException    (extends RemoteException)
├── PoolIsolationProxy           (VirtualThreadPool-backed wrapper)
├── ProcessIsolationProxy        (JERI-stub-backed subprocess wrapper)
└── ProxyIsolationPolicy         (enum: PERMISSIVE, STRICT, BYTECODE_ANALYSIS_AWARE,
                                       TRUST_ON_FIRST_USE)

org.apache.river.lookup.isolation.analysis
├── BytecodeAnalyzer             (interface)
├── AnalysisResult               (enum + findings list)
├── AnalysisSeverity             (enum: CLEAN, LOW, MEDIUM, HIGH, CRITICAL)
├── Finding                      (record: type, className, description)
├── FindingType                  (enum: SYNCHRONIZED_BLOCK, MUTABLE_STATIC,
                                        NON_ATOMIC_SERIAL, NATIVE_METHOD, OTHER)
└── AsmBytecodeAnalyzer          (ASM-based reference implementation)

org.apache.river.lookup.isolation.config
├── ProxyIsolationPolicyEntry    (Entry for SDM configuration)
├── BytecodeAnalyzerEntry        (Entry for SDM configuration)
├── IsolationExecutorFactoryEntry (Entry for SDM configuration)
├── IsolationDecisionCacheEntry  (Entry for SDM configuration)
└── IsolationMethodCallTimeoutEntry (Entry for SDM configuration)
```

All new types in `org.apache.river.lookup.isolation` depend downward on
`org.apache.river.lookup.isolation.analysis` and
`org.apache.river.lookup.isolation.config`, but neither sub-package depends on
the core `LookupCacheImpl` internals.  This allows the analysis and config
layers to be unit-tested independently.

---

## 10) Implementation Roadmap

### Phase 1 — Non-breaking plumbing (no behaviour change)

Goal: introduce the new package hierarchy with all interfaces, enums, and
placeholder implementations, without touching `ServiceDiscoveryManager` or
`LookupCacheImpl`.

Tasks:
1. Create `org.apache.river.lookup.isolation` and sub-packages.
2. Define `IsolationMode`, `IsolationDecision`, `IsolationContext` (interface),
   `IsolationProxy` (abstract), `IsolationTimeoutException`.
3. Define `BytecodeAnalyzer` (interface) + `AnalysisResult`, `AnalysisSeverity`,
   `Finding`, `FindingType`.
4. Implement `AsmBytecodeAnalyzer` using the ASM library already present in the
   JGDMS classpath.
5. Implement `ConcurrentHashMapDecisionCache` (default `IsolationDecisionCache`).
6. Implement `VirtualThreadPoolFactory` (POOL mode context).
7. Implement `ProcessBoundaryFactory` (PROCESS mode context) — stub only in this
   phase; subprocess launch deferred to Phase 3.
8. Write unit tests for `AsmBytecodeAnalyzer`, `ConcurrentHashMapDecisionCache`,
   `IsolationDecider.decide(...)`.

Backward compatibility: Phase 1 introduces no new dependencies on
`ServiceDiscoveryManager`.  Existing JGDMS applications are unaffected.

### Phase 2 — Configuration injection (backward-compatible extension)

Goal: wire the five new `Entry` configuration types into
`ServiceDiscoveryManager` so that an application can opt into analysis and
isolation without any behaviour change when the entries are absent.

Tasks:
1. Define the five `Entry` subtypes in
   `org.apache.river.lookup.isolation.config`.
2. In `ServiceDiscoveryManager` constructor, scan the `Entry[]` array for
   isolation config entries.  Store them in optional fields (null when absent).
3. Construct `IsolationDecider`, `IsolationContextProvider`, and
   `IsolationContextDisposer` if any isolation config entry is present.
4. Pass `IsolationDecider` to `LookupCacheImpl` as an optional constructor
   parameter (null → disabled).
5. Write integration tests that construct a `ServiceDiscoveryManager` with and
   without isolation config and verify no behavioural regression.

Backward compatibility: all isolation fields are null-guarded.  Absent entries
→ no-op.  Existing JGDMS applications are unaffected.

### Phase 3 — Integration with discovery and caching

Goal: hook the isolation decision and context machinery into the four extension
points described in §4.

Tasks:
1. **EP1 (Lookup Service Discovery):** in `LookupDiscoveryListener.discovered`,
   submit background analysis tasks via `IsolationDecider.scheduleAnalysis(...)`.
2. **EP2 (ServiceItemReg ingestion):** in `PreEventState.apply(...)`, call
   `IsolationDecider.classifyOnIngestion(reg, item)` after `ServiceItemReg` is
   created.
3. **EP2b (attribute change):** in `TransitionEventState.apply(...)`, call
   `IsolationDecider.reclassifyOnAttributeChange(reg, oldItem, newItem)` when
   the codebase attribute changes.
4. **EP3 (on-demand lookup):** in `LookupCacheImpl.getProxies(...)`, call
   `IsolationContextProvider.getOrCreateContext(reg)` and wrap the proxy before
   returning it.
5. **EP4 (ServiceItemFilter):** expose `reg.analysisResult` through
   `FilterContext` so application `ServiceItemFilter` implementations can
   inspect findings.
6. **PostEventState cleanup:** call `IsolationContextDisposer.dispose(reg)` in
   `PostEventState.apply(...)` before evicting the `ServiceItemReg`.
7. **ProcessBoundaryFactory** — complete the subprocess launch path: fork a JVM,
   export a JERI `BasicJeriExporter`, write the subprocess's stub URL into a
   `Pipe` so the parent can construct the `ProcessIsolationProxy`.
8. Write end-to-end tests:
   - `PERMISSIVE` policy: verify proxy is returned without wrapping.
   - `BYTECODE_ANALYSIS_AWARE` policy + CLEAN proxy: verify NONE mode.
   - `BYTECODE_ANALYSIS_AWARE` policy + HIGH-severity proxy: verify PROCESS mode
     and that a method call crosses the subprocess boundary.
   - Lease expiry: verify `IsolationContext.shutdown()` is called and the
     subprocess is terminated.
   - Timeout: verify `IsolationTimeoutException` is thrown after the configured
     deadline.

Backward compatibility: all hooks are null-guarded.  When `IsolationDecider` is
null (no config entries supplied), every code path falls through to the existing
behaviour without branching overhead beyond a single null check.

---

## 11) Security Properties of the Isolation Architecture

### 11.1  Fail-secure isolation decision

If `BytecodeAnalyzer.analyze(...)` throws an exception, the
`IsolationDecider` treats the result as `AnalysisSeverity.HIGH` and routes the
proxy to POOL mode (not NONE).  The safe default is containment, not trust.

The exception is logged with the codebase URL and class names so operators can
investigate.

### 11.2  Isolation context health and self-healing

`IsolationContext.isHealthy()` returns `false` if:

- The backing `ForkJoinPool` has been shut down or its carrier threads have been
  exhausted (POOL mode).
- The subprocess has exited or stopped responding to its JERI liveness probe
  (PROCESS mode).

On an unhealthy context, `IsolationContextProvider` creates a new context before
returning the wrapped proxy.  This is transparent to the caller.

### 11.3  PROCESS mode trust model

The subprocess created by `ProcessBoundaryFactory` runs with a minimal policy
file that grants only:

- `SocketPermission` for the JERI return channel to the parent JVM
- `SerialObjectPermission` for the proxy's own parameter and return types
- `RuntimePermission("createVirtualThread")` (if the proxy uses virtual threads)
- No `FilePermission`, no `RuntimePermission("exec")`, no `AllPermission`

The parent JVM communicates with the subprocess through a JERI export over
loopback.  The subprocess does not inherit the parent's file descriptors
(except `stdin`/`stdout`/`stderr` for logging) or security context.

### 11.4  Per-call timeout and thread leakage

In POOL mode, a timed-out call leaves the proxy method still running on its
virtual thread inside the pool's `ForkJoinPool`.  This is unavoidable (see the
virtual-thread termination analysis in `PROCESS_ISOLATION.md`).  The caller
receives `IsolationTimeoutException` at the configured deadline and is not
blocked.

To bound the number of stuck threads, the `VirtualThreadPoolFactory` caps the
underlying `ForkJoinPool`'s parallelism.  A service whose calls consistently
time out will exhaust only its own pool's parallelism, leaving other services'
pools unaffected.

In PROCESS mode, a timed-out call results in an interruption of the JERI I/O
channel.  The subprocess continues running and is reused for subsequent calls
unless it becomes unhealthy.

### 11.5  Interaction with DirtyChai's in-process security model

Proxy isolation is **additive** to, not a replacement for, DirtyChai's existing
in-process controls.  The isolation layer applies first (routing the proxy to a
pool or subprocess), and DirtyChai's `SecurityManager` / `ConcurrentPolicyFile`
controls apply inside the isolated execution context:

- POOL mode: the virtual threads in the pool run under the same
  `SecurityManager` and policy as the parent JVM.  The containment benefit is
  blast-radius reduction (heap separation by pool) and carrier-thread isolation,
  not a privilege boundary.
- PROCESS mode: the subprocess runs under a stricter `SecurityManager` and a
  minimal policy.  This is a genuine privilege boundary: the proxy cannot access
  client-side file system, network beyond its JERI channel, or other in-process
  state.

---

## 12) Related Documents

- `PROCESS_ISOLATION.md` — Multi-process isolation of service *implementations*;
  thread-creation permission analysis; virtual-thread termination analysis;
  `@AtomicSerial` and JERI security model
- `SECURITY_ANALYSIS.md` — DirtyChai's in-process security model and historical
  findings
- `SECURITY_MODEL.md` — Consolidated DirtyChai security invariants and
  deployment guidance
- `JGDMS_COMPATIBILITY.md` — JGDMS compatibility contracts re-exported from
  `java.base`

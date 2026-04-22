# Process Isolation in DirtyChai and JGDMS
**Last Reviewed:** 2026-04-22

This document consolidates the analyses produced during the investigation into
runtime permission checks for thread creation, atomic serialization, and the
inherent limits of in-process isolation in a Java security manager environment.
---
## Analysis: RuntimePermission("createPlatformThread") and RuntimePermission("createVirtualThread")
### The Gap
`Thread.java` calls `sm.checkAccess(g)` when a new thread is created.
`SecurityManager.checkAccess(ThreadGroup g)` only performs a real permission
check when `g == rootGroup` (the system thread group).  For every normal
application thread — which belongs to a child group, not the root — the method
returns silently without calling `checkPermission`.
Similarly, `VirtualThread.java` does not perform any `checkPermission` call at
creation time.
Untrusted code running under a `SecurityManager` can therefore freely create
unlimited platform and virtual threads with no policy enforcement.
### Impact
| Threat | Detail |
|---|---|
| **Thread-bomb DoS** | Buggy code can exhaust the OS thread pool by spawning unbounded platform threads |
| **Carrier thread starvation** | Buggy code can pin carrier threads via `synchronized` in virtual threads at scale |
| **Policy bypass** | `RuntimePermission("modifyThreadGroup")` is documented as the thread-creation guard, but is never checked for application threads |
| **Privilege escalation vector** | Thread creation can be used to outlive a restricted `AccessControlContext`, gaining a new inherited context |
### Proposed Fix
Add unconditional `checkPermission` calls at the point of thread construction:
1. In `Thread.java`, within the platform-thread creation path, check
   `RuntimePermission("createPlatformThread")` when a `SecurityManager` is active.
2. In `VirtualThread.java`, within the virtual-thread creation path, check
   `RuntimePermission("createVirtualThread")` when a `SecurityManager` is active.
3. Register both permissions in `SecurityConstants` and document them in
   `RuntimePermission.java`'s permission table.
This replaces the ineffective `checkAccess(g)` delegation (which fires a no-op
for all application threads) with a direct, unconditional `checkPermission` call
that the policy can explicitly grant or deny.
### Benefits
- **Checks actually fire** — coverage goes from near-zero to 100% of thread
  creation calls.
- **Granular least-privilege** — policy authors can grant `createVirtualThread`
  to a plugin without granting the more dangerous `createPlatformThread` (OS
  threads are a finite, kernel-managed resource).
- **Thread-bomb DoS prevention** — a `SecurityException` is thrown at
  construction time, before any OS resources are consumed.
- **Policy expressibility** — a `grant` block can now precisely scope which code
  bases may create which thread types.
- **Consistency** — aligns with every other security-sensitive API in the JDK
  (`createClassLoader`, `exitVM`, `setSecurityManager`, etc.) which all use
  unconditional `checkPermission` at the entry point.
### What Permission Checks Can and Cannot Protect Against
Permission checks are the right tool for *access-control* (preventing untrusted
code from acquiring resources), but they are the wrong tool for
*resource-consumption* (preventing untrusted code from burning resources it
already holds).
**What the new checks protect:**
| Attack Path | Permission Check | Guard |
|---|---|---|
| Unbounded platform thread bomb | `RuntimePermission("createPlatformThread")` | NEW — `Thread.java` |
| Unbounded virtual thread bomb | `RuntimePermission("createVirtualThread")` | NEW — `VirtualThread.java` |
| `System.exit()` | `RuntimePermission("exitVM.*")` | `SecurityManager.checkExit()` |
| Thread priority / name tampering | `RuntimePermission("modifyThread")` | `SecurityManager.checkAccess(Thread)` |
| All stack traces | `RuntimePermission("getStackTrace")` + `modifyThreadGroup` | `Thread.getAllStackTraces()` |
| Native library load | `RuntimePermission("loadLibrary.*")` | `SecurityManager.checkLink()` |
| SecurityManager replacement | `RuntimePermission("setSecurityManager")` | `System.setSecurityManager()` |
**What the new checks cannot protect against once a thread is running:**
1. **Carrier-thread starvation** — a virtual thread that uses `synchronized`
   pins its carrier thread to a platform thread and cannot be unscheduled by the
   JVM scheduler.
2. **CPU-bound busy loop** — a tight `while(true)` loop in a virtual thread
   consumes CPU without ever yielding to the JVM, so the virtual thread never
   unmounts from its carrier.
Both attacks require the hostile thread to be *already running*.  The new
permission checks prevent that thread from being *created* in the first place,
which is the correct defence boundary.
### Affected Files
- `src/java.base/share/classes/java/lang/Thread.java`
- `src/java.base/share/classes/java/lang/VirtualThread.java`
- `src/java.base/share/classes/java/lang/SecurityManager.java` (documentation update)
- `src/java.base/share/classes/java/lang/RuntimePermission.java` (permission table entries)
- `src/java.base/share/classes/sun/security/util/SecurityConstants.java` (new constants)
---
## Analysis: modifyThreadGroup is only checked if the group is rootGroup
### Current Behaviour
`SecurityManager.checkAccess(ThreadGroup g)` (lines 596–604 of `SecurityManager.java`):
```java
public void checkAccess(ThreadGroup g) {
    if (g == null) {
        throw new NullPointerException("thread group can't be null");
    }
    if (g == rootGroup) {
        checkPermission(SecurityConstants.MODIFY_THREADGROUP_PERMISSION);
    } else {
        // just return   ← silent no-op for all non-root groups
    }
}
```
`Thread.java` (line ~804):
```java
if (sm != null) {
    sm.checkAccess(g);   // ← fires the no-op path for every normal thread
    ...
}
```
### Why This Matters
`RuntimePermission("modifyThreadGroup")` is the documented permission for
thread-group operations.  The JDK specification implies it is checked whenever
code interacts with a thread group in a privileged way.  In practice the check
only fires for modifications to the *root* (system) thread group, leaving the
entire application thread-group hierarchy unguarded.
Every thread that an application creates belongs to a child of the root group,
not the root group itself.  Therefore:
- The permission check that *looks* like it guards thread creation actually
  guards only operations on the system thread group (e.g., attempts to enumerate
  or modify system-level threads).
- Thread creation in normal application code has passed through
  `checkAccess(g)` since Java 1.1 while achieving exactly zero enforcement.
### Consequence
The semantic gap cannot be closed by tightening `checkAccess(ThreadGroup)`.
Changing the else-branch to call `checkPermission` would break every application
that creates threads without holding `modifyThreadGroup` — i.e., virtually
every Java program.  The correct fix is to introduce dedicated permissions
(`createPlatformThread`, `createVirtualThread`) checked unconditionally at the
thread constructor, as described in the preceding analysis.
---
## Analysis: Forcibly Abandoning a Virtual Thread That Swallows Interrupts
### The Blunt Answer
**You cannot.**  There is no JVM mechanism that can forcibly terminate an
individual thread — platform or virtual — that is actively running and refuses
to cooperate.  This is a fundamental property of the Java threading model, not a
gap in DirtyChai's design.
### Why Nothing Works Against a Fully Hostile Thread
#### `Thread.interrupt()` — cooperative, not forcible
`interrupt()` sets a flag and wakes the thread if it is blocked in an
interruptible method.  Hostile code defeats it in three ways:
1. **Flag polling ignored** — code that never calls `Thread.interrupted()` or
   `isInterrupted()` never sees the signal.
2. **InterruptedException swallowed** —
   `catch (InterruptedException e) { /* ignore */ }` discards the signal without
   restoring the flag.
3. **Busy loop without blocking calls** — a tight `while(true)` loop never
   yields to any interruptible method, so the flag is set but never acted upon.
#### `Thread.stop()` — permanently removed for virtual threads
`Thread.stop()` was the only forcible mechanism.  It injected an asynchronous
`ThreadDeath` exception, which was dangerous (could silently corrupt shared
data) and was deprecated since Java 1.2.  It was definitively disabled: calling
`stop()` on any thread in modern Java throws `UnsupportedOperationException`.
`VirtualThread` inherits this.  There is no equivalent replacement.
#### `StructuredTaskScope` cancellation — interrupt-based, same limitation
When a scope is cancelled, it calls `interrupt()` on forked threads.  The
`close()` method is explicitly documented:
> "Subtasks that do not respond to interrupt, e.g. block on methods that are not
> interruptible, may delay the closing of a scope indefinitely.  The `close`
> method always waits for threads executing subtasks to finish, even if the scope
> is cancelled."
A scope whose forked task swallows interrupts causes `close()` to block forever.
The owner thread is trapped.
#### `ExecutorService.shutdownNow()` — interrupt-based, same limitation
`shutdownNow()` calls `interrupt()` on all running tasks.  Tasks that swallow
interrupts continue running.  `awaitTermination()` will block forever.
#### `ForkJoinPool` shutdown — same
Shutting down the backing `ForkJoinPool` sends `interrupt()` to its workers (the
carrier threads).  The virtual thread, if CPU-bound, is mounted on a carrier.
The carrier itself receives the interrupt, but the virtual thread's frame is
executing — and if the virtual thread code does not check the flag, it continues.
The carrier cannot be independently stopped while a virtual thread is running on
top of it.
### What Is Available: Containment, Not Termination
Since termination is impossible without cooperation, the only viable strategies
shift to *containing the damage*:
| Strategy | What It Achieves | Limitation |
|---|---|---|
| Isolated `ForkJoinPool` for untrusted VTs | Saturation of that pool does not affect trusted pools | The stuck thread still consumes its carrier(s) within that pool |
| Bounded parallelism in the isolated pool | Limits the number of carriers that can be monopolised | Does not stop the thread; it limits blast radius only |
| Deadline on the caller (`latch.await(timeout)`) | The caller moves on and treats the task as failed | The task thread keeps running, leaking a carrier slot |
| Watchdog that replaces the pool | A new pool can be created for fresh work | The old stuck threads remain alive until the JVM exits |
| `Thread.join(Duration)` | Non-blocking wait with timeout | After timeout, the thread is still alive |
The correct layered defence is therefore:
1. **Prevention** — use the new `createVirtualThread` permission check to stop
   untrusted code from creating virtual threads at all.
2. **Containment** — if virtual thread creation is permitted, route untrusted
   work through a bounded, isolated `ForkJoinPool` with a caller-side deadline.
3. **Acceptance** — document that a stuck thread will consume its carrier slot
   until the JVM exits, and size the isolated pool's parallelism accordingly.
---
## Analysis: Atomic Serialization and JERI — Architecture, Security Model, and Integration with DirtyChai
### Background
Standard Java serialization (`ObjectInputStream` / `ObjectOutputStream`) has a
long history of security vulnerabilities.  Its deserialization path invokes
arbitrary user code (`readObject`, `readResolve`, `validateObject`) during stream
reading — before the caller has had any opportunity to validate what class is
being reconstructed.  This is the root cause of gadget-chain attacks (ysoserial
et al.).
JGDMS addresses this with two complementary mechanisms:
1. **`@AtomicSerial`** — an annotation-driven serialization framework that
   replaces the implicit `readObject` / `writeObject` callback model with an
   explicit, immutable-by-construction deserialization contract.
2. **JERI (Jini Extensible Remote Invocation)** — the transport/marshalling
   layer that uses `@AtomicSerial` for all remote method parameter and return
   value encoding.
### @AtomicSerial Framework
A class annotated with `@AtomicSerial` must provide a public or protected
constructor of the form:
```java
public MyClass(GetArg arg) throws InvalidObjectException {
    // All fields set in a single constructor call — no mutable intermediate state
    this.field1 = arg.get("field1", 0);
    this.field2 = Valid.notNull(arg.get("field2", null), "field2 must not be null");
}
```
Key security properties:
| Property | Standard Java Serialization | @AtomicSerial |
|---|---|---|
| Deserialization entry point | `readObject()` (private, called by reflection) | Public constructor (regular Java call) |
| Object state during construction | Mutable intermediate state possible | All-or-nothing: fully valid or exception |
| Validation timing | `readResolve()` / `validateObject()` after construction | Inline in constructor — construction itself is validation |
| Circular object graphs | Supported | Not supported — eliminates reference cycles as an attack vector |
| `readObject` magic method abuse | Yes — gadget chains exploit this | Eliminated — no `readObject` callback mechanism |
| Input validation enforcement | Opt-in (`readObject` must validate) | Enforced by constructor contract |
`AtomicMarshalInputStream` / `AtomicMarshalOutputStream` are complete
reimplementations of the Java serialization protocol that use the
`@AtomicSerial` constructor contract instead of the reflection-based
`readObject` invocation.  They are wire-format compatible with standard Java
serialization for non-circular graphs.
### JERI Architecture and Serialization Layer
JERI is the transport layer for JGDMS remote services.  It sits between the
client proxy and the server implementation, handling:
- **Connection management** — TCP/SSL/HTTP transports
- **Marshalling** — encoding method arguments and return values to a byte stream
- **Unmarshalling** — decoding the byte stream back to Java objects on the
  receiving side
- **Authentication** — Kerberos, TLS mutual auth, anonymous
- **`AccessControlContext` propagation** — the caller's security context travels
  with the call
The JERI marshalling layer uses `AtomicMarshalInputStream` for all
unmarshalling, which means every object crossing a JERI boundary is
reconstructed through an `@AtomicSerial` constructor.  Gadget chains that depend
on `readObject` callbacks cannot fire because `readObject` is never called.
### Integration with DirtyChai
DirtyChai adds `SerialObjectPermission` as a JDK-level backstop check that fires
at the entry to `ObjectInputStream.readObject()` and
`ObjectOutputStream.writeObject()`.  When a `SecurityManager` is active, the
calling code must hold:
```
permission au.zeus.jdk.authorization.guards.SerialObjectPermission
    "com.example.MyClass";
```
for each class it wishes to serialize or deserialize via standard Java
serialization.
For JERI-marshalled calls using `AtomicMarshalInputStream`, `SerialObjectPermission`
is never checked: `@AtomicSerial` deserialization is performed through a normal
constructor call, not through `ObjectInputStream`.  The two mechanisms are
therefore complementary:
| Path | Deserialization Mechanism | SerialObjectPermission checked? |
|---|---|---|
| Standard Java `ObjectInputStream` | JDK default (`readObject` callbacks) | Yes — JDK-level check |
| JERI `AtomicMarshalInputStream` | `@AtomicSerial` constructor | No — check not needed; `readObject` is never called |
| Mixed (`ObjectInputStream` used by application code in a JERI-hosted service) | JDK default | Yes — backstop still fires |
This layering ensures that even code running inside a JGDMS service that falls
back to standard Java serialization (e.g., for legacy data formats) is covered
by the `SerialObjectPermission` check.

**Activation-group deserialization scope (undocumented boundary):**

The `SerialObjectPermission` enforcement described above applies to the calling JVM. It is not currently documented whether a group JVM (in an RMI activation scenario) re-enforces this permission when it reconstructs activatable objects from `ActivationDesc` descriptors passed by the JGDMS Phoenix activation daemon. Three specific gaps exist:

- **Descriptor integrity** — Current JGDMS/Phoenix documentation does not state whether activation-daemon-stored `ActivationDesc` objects are integrity-protected (e.g., with a signature or HMAC). A compromised or malicious JGDMS Phoenix activation daemon could inject arbitrary descriptors, causing the group JVM to deserialize objects that would have been blocked by `SerialObjectPermission` in the originating JVM.
- **Policy authority on re-activation** — it is undefined whether the group JVM applies its own policy file or the registering administrator's policy when evaluating `SerialObjectPermission` during activation reconstruction. If the group's policy is weaker, the permission check may be ineffective.
- **`AccessControlContext` freshness on restart** — when a group JVM crashes and restarts, it is unspecified whether it receives a fresh `AccessControlContext` or inherits state from the previous run. Stale context could carry permissions that were valid before a policy change, enabling escalation after a policy tightening event.

See residual N-13 under "Residual N-13: Activation Deserialization Authority Trust Boundaries" in this document.
---
## DirtyChai: SerialObjectPermission as the JDK-level Backstop for JGDMS Atomic Serialization — and Why Process Isolation Remains Essential
### SerialObjectPermission as Backstop
`au.zeus.jdk.authorization.guards.SerialObjectPermission` is a
`BasicPermission` whose name is the canonical class name of a serializable type.
It is checked at the entry to standard Java serialization and deserialization.
**What it does:**
- Forces policy authors to explicitly whitelist every class that may be
  serialized or deserialized via `ObjectInputStream` / `ObjectOutputStream`.
  This covers all `Serializable` classes — not just those with a custom `readObject`.
- Prevents gadget-chain attacks by default: a class not in the policy cannot be
  deserialized even if it appears in the stream.
- Works as a policy-file declaration, making the serialization surface auditable
  using the `SecurityPolicyWriter` tool.
**What it does not do:**
- It does not apply to JGDMS `AtomicMarshalInputStream` paths (see the
  preceding analysis).
- It does not validate the *content* of the deserialized object, only whether
  the class is permitted.  Content validation is the responsibility of the
  `@AtomicSerial` constructor or the application's own validation logic.
- It does not prevent a whitelisted class from executing logic in its
  `readResolve()` or `readObject()` callback.  For classes that implement these
  callbacks the behaviour of those callbacks remains the responsibility of the
  class author.
**The combined defence:**
```
Untrusted byte stream
        │
        ▼
┌─────────────────────────────────────────────────┐
│ SerialObjectPermission check (DirtyChai)        │
│  → SecurityException if class not in policy     │
└────────────────────────┬────────────────────────┘
                         │ class is whitelisted
                         ▼
┌─────────────────────────────────────────────────┐
│ ObjectInputStream / AtomicMarshalInputStream    │
│  Standard path: readObject() called             │
│  AtomicSerial path: @AtomicSerial ctor called   │
└────────────────────────┬────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────┐
│ @AtomicSerial constructor validation            │
│  → InvalidObjectException if inputs invalid     │
└─────────────────────────────────────────────────┘
```
### Why Process Isolation Remains Essential
All of the controls described above — `SerialObjectPermission`, `@AtomicSerial`,
`createVirtualThread`, `SecurityManager` — operate *inside a single JVM
process*.  In-process isolation has fundamental limits that no permission check
or deserialization framework can overcome:
#### 1. Shared memory
All threads and objects in a JVM process share a heap.  A hostile thread that
has already been scheduled can read or corrupt shared data structures without
any permission check, because memory access does not pass through the
`SecurityManager`.

**Java Memory Model (JMM) guarantees and limits in this context:**

- **Visibility is conditional, not isolated.**  The JMM guarantees visibility
  across threads only when there is a proper *happens-before* edge (for example:
  monitor enter/exit, `volatile`, thread start/join, or classes in
  `java.util.concurrent`).  This improves correctness, but does not prevent
  untrusted code from reading or writing any object graph it can reference.
- **Data-race freedom gives predictability, not protection.**  Correctly
  synchronized code gets well-defined behavior, but there is no policy check on
  field reads/writes.  A malicious in-process thread can still mutate shared
  state if it obtains references to that state.
- **Atomicity scope is limited.**  The JMM guarantees atomic reads/writes for
  references and 32-bit primitives (and, in modern JDKs, `long`/`double` as
  well), but compound actions are still non-atomic unless synchronized.  This
  enables race-based corruption of invariants even when individual reads/writes
  are atomic.
- **Ordering rules are semantic, not access control.**  The JMM constrains
  legal reorderings by compilers/CPUs, but it is not a sandbox boundary.
  Nothing in the model routes ordinary memory access through
  `SecurityManager.checkPermission()`.

Therefore, JMM guarantees help reason about *correctness* under concurrency, but
they do not provide a security boundary between mutually untrusted threads in
the same JVM process.
#### 2. Side-channel attacks
Timing attacks, cache-flush attacks, and speculative-execution side channels
(Spectre, Meltdown class) operate below the Java security model.  A hostile
thread running in the same process can leak secrets from other threads via these
channels regardless of permission grants.  Moving to separate OS processes (via
JGDMS Activation) reduces but does not eliminate these channels, because two
processes on the same physical CPU core still share microarchitectural state such
as L1 cache, branch predictor tables, and Translation Lookaside Buffers (TLBs).
Full mitigation requires hardware-level isolation; see
[Hardware-Level Isolation Against Spectre/Meltdown-Class Attacks](#hardware-level-isolation-against-spectremeltdown-class-attacks)
later in this document.
#### 3. JVM internals access
Despite module encapsulation and permission checks, the JVM exposes internal
state that can be exploited to escape the security model entirely:
- **`sun.misc.Unsafe` / `jdk.internal.misc.Unsafe`** — allows arbitrary memory
  reads and writes at native-pointer offsets.
- **JNI / FFM** — native code runs outside the JVM and is invisible to
  `StackWalker`; it can call back into the JVM impersonating any class.
- **JVMTI** — a `-agentlib:` agent attached at startup can intercept or
  redefine any class before the SecurityManager is installed.
- **`java.lang.instrument.Instrumentation`** — a `-javaagent:` can redefine
  classes at runtime, including security-critical classes, after the JVM is
  running. Runtime attach (`VirtualMachine.attach()`) is gated by
  `AttachPermission` when the SecurityManager is active; `-XX:+DisableAttachMechanism`
  remains a VM-level defense-in-depth option.
#### 4. Resource exhaustion
As analysed above, a running thread cannot be forcibly terminated.  Even if all
creation guards are in place, code that has been granted `createVirtualThread`
can still exhaust carrier threads, fill the heap, or cause GC storms.
#### 5. Class loader confusion
Multiple class loaders in a single JVM can define classes with the same name in
different `ProtectionDomain`s.  Confusion between identically-named classes in
different loaders has historically led to type-confusion vulnerabilities.
### The Correct Architecture
DirtyChai and JGDMS together provide the strongest *in-process* isolation
available on the JVM.  For truly untrusted code — code whose origin or intent is
unknown — the correct architecture combines in-process controls with
OS-level process isolation:
| Layer | Mechanism | Provided By |
|---|---|---|
| Class whitelist | `SerialObjectPermission` | DirtyChai |
| Deserialization safety | `@AtomicSerial` constructors | JGDMS |
| Thread creation control | `createPlatformThread` / `createVirtualThread` | DirtyChai (implemented) |
| Permission enforcement | `SecurityManager` + `ConcurrentPolicyFile` | DirtyChai |
| Blast-radius containment | Isolated `ForkJoinPool` + deadline | JGDMS service layer |
| Memory isolation | Separate OS process | OS / GraalVM Espresso / container |
| Network isolation | Firewall / namespace | OS / container runtime |
> **Scope of DirtyChai**: DirtyChai provides the *in-process* layer of the
> combined confinement architecture.  Its core goals are user authorisation —
> ensuring principals have access only when using approved, policy-controlled
> code — least-privilege enforcement, and tooling to audit third-party code
> before deployment.  When combined with JGDMS activation groups and OS-level
> process and network isolation (as described in this document), DirtyChai's
> in-process permission layer becomes one tier of a full defence-in-depth
> posture that can confine untrusted code.  Neither DirtyChai alone nor JGDMS
> alone is sufficient for that goal; the layers described in "The Correct
> Architecture" table above are all required.
In practice, the recommended deployment model for JGDMS services that handle
untrusted remote input is:
1. Each service runs in its own OS process.
2. DirtyChai `SecurityManager` + `ConcurrentPolicyFile` enforces least-privilege
   within that process.
3. JGDMS `@AtomicSerial` ensures unmarshalled objects are fully validated at
   construction time.
4. `SerialObjectPermission` provides a policy-auditable whitelist for any
   remaining use of standard Java serialization.
5. Untrusted-proxy invocations are dispatched through a bounded, isolated
   `ForkJoinPool` with a caller-side timeout.
6. The OS process boundary provides the final containment layer: if the JVM
   process is compromised, the attacker is confined to that process and cannot
   directly access other services or the host OS without an additional
   privilege-escalation step.

---

## Analysis: Preventing Native Code Loaded by Untrusted Jars from Escaping the SecurityManager

### Background — Why Native Code Is a Special Threat

Java's security model operates entirely inside the JVM: every permission check,
every `AccessControlContext` evaluation, and every `SecurityManager.checkPermission`
call is Java code, running in managed memory, subject to the class and module
systems.

Native code — machine code loaded via JNI (`System.loadLibrary`) or invoked via
the Foreign Function & Memory (FFM) API — runs at the OS level, in unmapped
virtual address space outside the JVM's control.  Once native code is executing:

- It can read and write arbitrary JVM heap memory directly.
- It can make raw system calls, bypassing every Java security check.
- It can call back into the JVM (`AttachCurrentThread`, `NewGlobalRef`,
  `CallObjectMethod`, etc.) impersonating any class or protection domain it
  chooses.
- It is invisible to `StackWalker` — it does not appear in the Java call stack,
  so caller-identity checks cannot see it.

The consequence is that a single successful native library load by untrusted
code **collapses the entire DirtyChai security model** for that JVM process.

### What DirtyChai Already Does — Two Independent Loading Gates

DirtyChai closes the *loading* attack surface through two independent permission
checks that both fire before any native code executes.

#### Gate 1 — `NativeInvocationPermission` at native symbol resolution

`ClassLoader.java`, `SymbolLookup.java`, and `SystemLookup.java` have been
modified to call `NativeInvocationPermission.checkGuard(null)` (or
`SecurityManager.checkPermission(new NativeInvocationPermission(libName))`) at
the point where a native symbol address is resolved from a loaded library.  The
permission name is the name of the native library that contains the symbol.

Library name resolution is performed by `NativeLibraries.findLibraryNameAddress()`,
which applies a three-level null-safe fallback: (1) the map key for the native library
entry, (2) `NativeLibrary.name()`, (3) the symbol name itself.  This ensures that
`NativeInvocationPermission` is always constructed with a non-null name even when a
loaded library's path metadata is incomplete, avoiding any possibility of an
unintended `NullPointerException` reaching the caller before the security check fires.

```java
// ClassLoader.java — findNative() (DirtyChai modification)
// Fires when a JNI native method is being linked to its native implementation.
static long findNative(ClassLoader loader, Class<?> clazz,
                       String entryName, String javaName) {
    ...
    if (addr != 0 && loader != null) {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null)
            sm.checkPermission(new NativeInvocationPermission(libraryName));
        ...
    }
    return addr;
}

// SymbolLookup.java / SystemLookup.java — symbol-lookup lambdas (DirtyChai modification)
// Fires when an FFM symbol lookup resolves a symbol address from a named library.
return name -> {
    ...
    if (addr != 0L) {
        new NativeInvocationPermission(libraryName).checkGuard(null);
        return Optional.of(MemorySegment.ofAddress(addr)...);
    }
};
```

`Permission.checkGuard(null)` calls `SecurityManager.checkPermission(this)` when
a SecurityManager is active.  The calling code's `ProtectionDomain` must have
`NativeInvocationPermission` granted in the policy file for the specific library
name, or a `SecurityException` is thrown before the symbol address is returned.

The entry points covered by this gate:

| API | Check location |
|-----|----------------|
| JNI native method binding | `ClassLoader.findNative()` |
| `SymbolLookup.loaderLookup()` symbol find | lambda returned by `SymbolLookup.loaderLookup()` |
| `SymbolLookup.libraryLookup(...)` symbol find | lambda returned by `SymbolLookup.libraryLookup()` |
| System/platform library symbol find | `SystemLookup.lookup()` lambda |

Every one of these is blocked for untrusted code unless the policy explicitly
grants `NativeInvocationPermission` for the target library to that code's
`ProtectionDomain`.

#### Gate 2 — `RuntimePermission("loadLibrary.*")` via `SecurityManager.checkLink()`

`Runtime.load0()` and `Runtime.loadLibrary0()` additionally call
`security.checkLink(filename/libname)`, which translates to
`checkPermission(new RuntimePermission("loadLibrary." + lib))`.

This provides a second, independent block for the classic JNI loading path that
is distinct from the FFM API gate.  A policy can therefore apply fine-grained
controls:

```
// Allow loading only the specific library "mylib", not arbitrary natives
grant codeBase "file:/trusted/app/-" {
    permission java.lang.RuntimePermission "loadLibrary.mylib";
};
```

#### How the Two Gates Compose

For JNI native method access via `System.loadLibrary("foo")`:

```
System.loadLibrary("foo")                  ← loads the library
    │
    └─ Runtime.loadLibrary0(fromClass, libname)
             └─ security.checkLink("foo")
                     └─ checkPermission(RuntimePermission("loadLibrary.foo"))
                             ← GATE 2: SM policy check (library loading)

nativeMethod()                             ← later, when native method is first linked
    │
    └─ ClassLoader.findNative(loader, clazz, entryName, javaName)
             └─ SecurityManager.checkPermission(NativeInvocationPermission("foo"))
                     ← GATE 1: SM policy check (symbol invocation)
```

Both gates must pass.  A policy that grants one but not the other still blocks
the call.

#### Module-System Layer (Not Policy-Controlled)

After the SecurityManager checks, `ensureNativeAccess()` also evaluates the
module system's `enableNativeAccess` flag and the JVM startup mode
(`ModuleBootstrap.IllegalNativeAccess`).  The modes are:

| Mode | Behaviour | JVM Flag |
|------|-----------|----------|
| `ALLOW` | No module restriction enforced | `--enable-native-access=ALL-UNNAMED` |
| `WARN` | Warning printed, access granted (default) | (none) |
| `DENY` | `IllegalCallerException` if module not listed | `--illegal-native-access=deny` |

For DirtyChai deployments the SecurityManager check fires *before* this module
check, so `WARN` mode does not weaken the policy enforcement — the SM will have
already thrown a `SecurityException` for untrusted code.  The recommended startup
configuration adds `--illegal-native-access=deny` as a defence-in-depth measure
so that the module system also blocks any path not covered by the SM check.

### Remaining Residual Gaps

The loading gates (Gate 1 + Gate 2) fully protect against untrusted jars *loading
new* native libraries or *directly binding* their own native method declarations
to symbols in already-loaded libraries (see "Direct binding" below).  The
following narrower scenarios remain partially or fully outside Java-side control:

#### 1. Direct binding of untrusted native method declarations to already-loaded symbols

If a trusted class loaded `mylib.so` earlier in the JVM session, that library's
symbols are permanently searchable via `ClassLoader.findNative()`.  Untrusted
code could declare its own `native` methods whose JNI mangled names match symbols
already present in `mylib.so`.

**Protection provided by DirtyChai:** `ClassLoader.findNative()` checks
`NativeInvocationPermission("mylib")` against the class whose native method is
being linked.  Untrusted code holds no such permission, so the binding is blocked
before the symbol address is returned.  **This attack path is now closed.**

#### 2. Confused-deputy: trusted class calls native on behalf of untrusted caller

If a trusted class has already linked its own native methods (binding cached by
the JVM), and a trusted class's *public Java API* internally invokes those native
methods, `ClassLoader.findNative()` does **not** re-fire on each invocation —
the binding is cached.  The security gate on this path is `SecurityManager`
stack-intersection: as long as the untrusted caller's `ProtectionDomain` remains
on the stack, its absence of `NativeInvocationPermission` blocks any
`checkPermission` call on that execution path.

**Implication:** This confused-deputy attack only succeeds when the trusted
class uses **unrestricted** `AccessController.doPrivileged` (i.e. without
supplying a restricted `AccessControlContext`).  Unrestricted `doPrivileged`
tells the access-control stack walk to stop at that frame, dropping all caller
`ProtectionDomain`s above it from the intersection.  Once the caller's domain
is absent, the trusted class's own `NativeInvocationPermission` is sufficient and
the check passes even though the ultimate caller holds no such permission.

Without any `doPrivileged`, the untrusted caller's `ProtectionDomain` remains
on the call stack.  `SecurityManager.checkPermission` computes the intersection
of every domain on the stack, so the untrusted domain's absence of
`NativeInvocationPermission` blocks the call automatically — no additional pattern
is required from the trusted class.

**Mitigation:** Trusted library code must **not** use unrestricted
`AccessController.doPrivileged` when calling native methods on behalf of
caller-supplied inputs.  The normal call path — without any `doPrivileged` —
allows the security policy's call-stack intersection to enforce the restriction
automatically.  This is a design obligation for trusted library code; DirtyChai
cannot detect and prevent a trusted class from using unrestricted `doPrivileged`
on its own behalf.

#### 3. JNI callbacks from within native code

Native code that has already been loaded by a trusted class can call back into
the JVM via the JNI `CallXxxMethod` family without any Java-side permission
check.  The JVM executes those calls in whatever thread is current, which may
not have the restricted `AccessControlContext` the Java caller intended.

**Mitigation:** `doPrivileged` with a limited context in the Java wrapper method,
combined with explicit input validation before any JNI call.  DirtyChai's
`SerialObjectPermission` guards the deserialization path; native method wrappers
must apply analogous input validation.

#### 4. JVMTI and JVM agents

A `-javaagent:` or `-agentlib:` loaded at JVM startup runs as a JVMTI agent
and can intercept, modify, or bypass any Java-level security check.  There is
no JVM mechanism by which the SecurityManager can block a JVMTI agent — the
agent was attached before the SecurityManager was installed.

**Mitigation:** Process isolation (OS process per service) and OS-level controls
on the JVM command line (e.g., launch wrappers that reject `-agentlib:` for
untrusted service processes).

### Summary — What the Guards Protect

| Attack Path | Guarded By | Status |
|-------------|-----------|--------|
| Untrusted jar calls `System.loadLibrary()` | `RuntimePermission("loadLibrary.*")` at load time; `NativeInvocationPermission("<libname>")` at JNI method binding | **Blocked by DirtyChai** |
| Untrusted jar uses FFM `SymbolLookup.libraryLookup()` symbol find | `NativeInvocationPermission("<libname>")` at symbol lookup | **Blocked by DirtyChai** |
| Untrusted jar uses FFM `SymbolLookup.loaderLookup()` symbol find | `NativeInvocationPermission("<libname>")` at symbol lookup | **Blocked by DirtyChai** |
| Untrusted jar uses `MemorySegment.reinterpret()` | `NativeInvocationPermission("reinterpret")` in `AbstractMemorySegmentImpl.reinterpretInternal()` + module `enableNativeAccess` flag | **Blocked by DirtyChai** (when SM active) |
| Untrusted jar uses FFM `Linker.downcallHandle()` | Module `enableNativeAccess` flag; symbol address sourced via `SymbolLookup` (gated by `NativeInvocationPermission`) | **Blocked by DirtyChai** |
| Untrusted jar declares `native` methods binding to symbols in already-loaded library | `NativeInvocationPermission("<libname>")` at `ClassLoader.findNative()` binding time | **Blocked by DirtyChai** |
| Confused-deputy: trusted class calls native on behalf of untrusted caller | Call-stack intersection (SM checks all `ProtectionDomain`s); only fails if trusted code uses unrestricted `doPrivileged` | **Protected by default — trusted code must avoid unrestricted `doPrivileged`** |
| JNI `CallXxxMethod` callbacks from within native code | No Java-side gate on re-entrant JNI calls | **Residual gap — use process isolation and input validation** |
| JVMTI / `-agentlib:` attached at startup | OS / JVM launch controls | **Out of scope for DirtyChai** |

---

## Implementation Plan: Native Code Isolation in DirtyChai

The `NativeInvocationPermission` class and its integration into `ClassLoader.findNative()`,
`SymbolLookup`, `SystemLookup`, and `AbstractMemorySegmentImpl` (`MemorySegment.reinterpret()`)
are already implemented.  The following tasks remain for
a complete, policy-auditable native isolation story.

### Task N-4 — Document `NativeInvocationPermission` in `RuntimePermission.java`'s Permission Table

**Priority:** Medium  
**Files:** `src/java.base/share/classes/java/lang/RuntimePermission.java`

**Description:**  
Add a row to the JavaDoc permission table in `RuntimePermission.java` that
cross-references `NativeInvocationPermission` so that users who look up
`loadLibrary.*` also discover the companion DirtyChai permission.

This is a human implementation task (JavaDoc in a shipped source file).

---

### Task N-5 — Add `--illegal-native-access=deny` to Recommended JVM Flags

**Priority:** Low  
**Files:** `README.md`, `SECURITY.md`, deployment documentation.

**Description:**  
Document that DirtyChai deployments should launch the JVM with
`--illegal-native-access=deny` (or the equivalent for the target JDK version)
as a defence-in-depth measure.  This ensures the module system's native access
gate independently blocks any path not covered by the SecurityManager policy,
so that a hypothetical bug in the SecurityManager installation cannot be
exploited to load native code through the module-system path.

---

### Task N-6 — Confused-Deputy Guidance for Trusted Library Authors

**Priority:** Medium  
**Files:** `CONTRIBUTING.md`, `SECURITY_MODEL.md`.

**Description:**  
Document the obligation that trusted library code must honour when it calls
native methods that may be triggered by caller-supplied inputs.

The Java security model protects against the confused-deputy attack
automatically: `SecurityManager.checkPermission` walks the entire call stack
and computes the *intersection* of the `PermissionCollection`s held by every
`ProtectionDomain` on the stack.  As long as the untrusted caller's domain
remains on the stack, its absence of `NativeInvocationPermission` prevents the call
from succeeding — no special coding pattern is required in the trusted class.

The attack only becomes possible when the trusted class uses **unrestricted**
`AccessController.doPrivileged` (without supplying a restricted
`AccessControlContext`).  Unrestricted `doPrivileged` tells the stack walk to
stop at that frame, removing the untrusted caller's domain from the intersection.
With the caller's domain gone, the trusted class's own `NativeInvocationPermission`
is sufficient and the permission check passes incorrectly.

**The obligation for trusted library authors is therefore:**

> Do **not** use unrestricted `AccessController.doPrivileged` on code paths
> that lead to native method calls when those paths can be triggered by
> caller-supplied inputs.  The normal call path (no `doPrivileged`) lets the
> security policy enforce the restriction through stack-intersection automatically.

If a trusted class genuinely needs to perform privileged pre-processing while
still honouring the caller's restrictions, it must reduce privileges to the
minimum scope and preserve any active `DomainCombiner` (for example,
authenticated-principal context) while parsing and sanitizing caller input:

```java
// Preserve DomainCombiner and run with the smallest scope.
AccessControlContext callerContext = AccessController.getContext();
SanitizedInput sanitized = AccessController.doPrivilegedWithCombiner(
    () -> parseAndSanitize(callerSuppliedInput),
    callerContext,
    new Permission[0]   // policy decides; no explicit extra permissions added
);

// For confused-deputy-sensitive native calls, do not use unrestricted doPrivileged.
nativeMethod(sanitized);
```

Methods that support explicit privilege restriction, grouped by whether a special
permission is required to invoke them:

**No special permission required — any domain may call these**

The methods below require no `SecurityPermission` or `AuthPermission` because
they can only *reduce* the effective permission set of the code running inside
them.  Stack-intersection semantics make this inherently safe: the intersection
of the caller's `ProtectionDomain` with a restricted `AccessControlContext` or
an explicit `Permission` list is always a *subset* of what the caller already
holds.  A less-privileged domain therefore cannot exploit these methods to
acquire permissions it does not already possess.

Note that while *using* these methods requires no special permission,
*constructing* an `AccessControlContext` to pass to them may require
`SecurityPermission("createAccessControlContext")`.  If the caller does not
hold that permission, `AccessControlContext.build()` automatically adds the
calling context's own domains to the supplied array to prevent privilege
escalation.  The context passed by `AccessController.getContext()` is always
safe to re-use without that permission.

- `AccessController.getContext()` — takes a read-only snapshot of the current
  calling context; it does not alter any privilege and cannot be used to
  escalate.
- `AccessController.doPrivileged(PrivilegedAction<T>, AccessControlContext)` —
  runs the action with the *intersection* of the caller's domain and the
  supplied context.
- `AccessController.doPrivileged(PrivilegedExceptionAction<T>, AccessControlContext)` —
  same intersection semantics, for checked-exception actions.
- `AccessController.doPrivileged(PrivilegedAction<T>, AccessControlContext, Permission...)` —
  constructs a synthetic `ProtectionDomain` scoped to the *calling class's*
  `CodeSource` but seeded with the listed permissions, then intersects that
  with the supplied context.  Policy grants matching the caller's `CodeSource`
  can *expand* the effective permissions beyond what was explicitly listed,
  so the final privilege scope is the intersection of the supplied context and
  the union of the listed permissions plus any applicable policy grants.
  Passing an **empty** `Permission` array (rather than an explicit list)
  delegates permission determination entirely to policy: the synthetic domain
  will hold exactly what policy grants to the caller's `CodeSource`, no more
  and no less.  This is both more performant (no explicit permission objects
  to allocate or compare) and, when the policy is generated by
  `SecurityPolicyWriter`, guarantees the minimum permissions the caller needs.
- `AccessController.doPrivileged(PrivilegedExceptionAction<T>, AccessControlContext, Permission...)` —
  same semantics and empty-array optimisation, for checked-exception actions.
- `AccessController.doPrivilegedWithCombiner(PrivilegedAction<T>, AccessControlContext, Permission...)` —
  same policy-expansion and empty-array mechanics, additionally preserving the
  current `DomainCombiner` (e.g. `SubjectDomainCombiner`) across the call
  boundary.
- `AccessController.doPrivilegedWithCombiner(PrivilegedExceptionAction<T>, AccessControlContext, Permission...)` —
  same, for checked-exception actions.

**Explicit `AuthPermission` required — gated because they can change identity**

The methods below associate running code with a `Subject`'s *principals*.
Policy grants keyed on principals (e.g. `Principal "CN=Admin"`) can unlock
permissions that the calling domain does not otherwise hold.  Executing code
under a different Subject identity can therefore *expand* the effective
permission set, not merely restrict it.  A security manager check gates each
call to prevent an unprivileged domain from elevating itself by adopting a
more powerful identity.

- `Subject.doAsPrivileged(Subject, PrivilegedAction<T>, AccessControlContext)` —
  requires `AuthPermission("doAsPrivileged")`; runs the action under the
  supplied Subject's identity.  When `acc` is `null`, an empty
  `AccessControlContext` (no code-source domains) is used, so the only
  permissions available are those granted by the policy to the Subject's
  *principals* — an intentionally unprivileged starting point that then grows
  solely through principal-keyed grants.
- `Subject.doAsPrivileged(Subject, PrivilegedExceptionAction<T>, AccessControlContext)` —
  same permission requirement and null-context semantics, for checked-exception
  actions.

Failing to avoid unrestricted `doPrivileged` creates a confused-deputy
vulnerability where untrusted code exploits the trusted class's
`NativeInvocationPermission` to invoke native functionality it could not invoke
directly.

This guidance is for documentation files only and is therefore within scope for
this session.

### Task N-7 — Add `NativeInvocationPermission` Grant to `CombinerSecurityManager` Policy

**Priority:** High  
**Files:** Policy files used by `CombinerSecurityManager` tests and the
`SecurityPolicyWriter` default output.

**Description:**  
`CombinerSecurityManager` intersects permission sets.  If neither the caller's
policy nor the `CombinerSecurityManager`'s own policy grants
`NativeInvocationPermission`, a `checkPermission` call for that permission will
correctly fail.  Confirm that the test policy files explicitly enumerate which
trusted modules receive `NativeInvocationPermission` so that the intersection logic
is exercised in tests.

This is a human implementation task (policy file changes and test additions).

---

> **Footnote — Recommended Policy Authoring Workflow**
>
> The wildcard grants (`"*", "*"`) used for trusted platform-loader modules are a safe
> starting point for trusted platform-loader modules, but they are deliberately
> broad.  For application code and any module whose actual permission requirements
> are not yet known, the recommended workflow is:
>
> 1. **Generate first with polpAudit.**  Run the application (or its test suite)
>    under [`polpAudit`](https://github.com/pfirmstone/JGDMS/tree/trunk/tools/polpAudit)
>    (or the equivalent `SecurityPolicyWriter` instrumentation built into
>    DirtyChai).  polpAudit observes every
>    `SecurityManager.checkPermission()` call that occurs during the run and
>    emits a least-privilege policy file containing only the permissions that
>    were actually checked.
>
> 2. **Review and widen if needed.**  Inspect the generated policy file.  If a
>    legitimate code path was not exercised during the capture run (e.g., an
>    error-recovery branch or a rarely-used feature), add the missing permission
>    entries manually after verifying that granting them is intentional.
>
> This two-step approach — *capture then widen* — avoids both under-granting
> (which causes `SecurityException` at runtime) and over-granting (which enlarges
> the attack surface unnecessarily).  The wildcard entries in the platform-module
> policy blocks above were applied only after confirming that every platform module
> listed there is fully trusted and loaded by the platform class loader; the same
> shortcut must **not** be applied to application-classpath or plugin code.

---

## Analysis: Reflection and MethodHandle Invocation in the Permission-Check Path (N-8)

This security-model analysis has moved to `SECURITY_ANALYSIS.md`:
**"Analysis: Reflection and MethodHandle Invocation in the Permission-Check Path (N-8)"**.
See that section for full details.

---

## Analysis: Finalizer and Cleaner Thread Execution Contexts (N-9)

This security-model analysis has moved to `SECURITY_ANALYSIS.md`:
**"Analysis: Finalizer and Cleaner Thread Execution Contexts (N-9)"**.
See that section for full details.

---

## Analysis: Constant-Pool and Class-Initialization Security (N-10)

This security-model analysis has moved to `SECURITY_ANALYSIS.md`:
**"Analysis: Constant-Pool and Class-Initialization Security (N-10)"**.
See that section for full details.

---

## Analysis: Consolidated Invocation and Lifecycle Security Posture (N-11)

This section ties together the analyses in N-8, N-9, N-10, and the earlier
"Remaining Residual Gaps" section to give operators a single reference for what
is blocked, what is residual, and what requires process isolation.

### What DirtyChai Blocks Automatically

| Invocation / Lifecycle Path | Guard | Status |
|----------------------------|-------|--------|
| `Method.invoke()` used to install custom `SecurityManager` | `java.lang.reflect.*` frame detection in `validateCallerStackWithStackWalker()` | **Blocked** |
| `MethodHandle.invoke*()` used to install custom `SecurityManager` | Non-whitelisted `java.lang.invoke.*` frame detection | **Blocked** |
| `Method.invoke()` calling trusted class native method (no `doPrivileged`) | Untrusted caller PD on stack; intersection enforced | **Blocked** |
| `MethodHandle.invoke()` calling trusted class native method (no `doPrivileged`) | Untrusted caller PD on stack; intersection enforced | **Blocked** |
| Runtime attach via `VirtualMachine.attach()` from untrusted code | `AttachPermission("attachVirtualMachine")` check in attach provider path | **Blocked** (when SecurityManager policy denies attach) |
| Untrusted class finalizer calling native method | Untrusted finalizer class PD on stack; intersection enforced | **Blocked** |
| Untrusted Cleaner callback calling native method | Untrusted Runnable class PD on stack; intersection enforced | **Blocked** |
| Untrusted code loading a class (which would trigger `<clinit>`) | `LoadClassPermission` gate at class loading | **Blocked** |
| Untrusted code triggering `<clinit>` of already-loaded trusted class | Untrusted PD on stack; intersection enforced at any permission check | **Blocked** |
| Untrusted code triggering `invokedynamic` bootstrap method | Untrusted PD on stack; intersection enforced | **Blocked** |
| Untrusted code triggering `CONSTANT_Dynamic` bootstrap method | Untrusted PD on stack; intersection enforced | **Blocked** |

### Residual Gaps Requiring Trusted-Code Discipline

These gaps cannot be closed by DirtyChai alone because they arise from deliberate
use of privilege-escalation APIs by *trusted* code.  They require design
discipline in trusted library authors.

| Gap | Condition | Mitigation |
|-----|-----------|------------|
| Reflection / MethodHandle + unrestricted `doPrivileged` | Trusted target uses unrestricted `doPrivileged`; untrusted PD dropped from intersection | Trusted code must use `doPrivileged` with limited context on caller-controlled paths |
| `<clinit>` unrestricted `doPrivileged` | Trusted static initializer uses unrestricted `doPrivileged` | Trusted code must not use unrestricted `doPrivileged` inside `<clinit>` |
| `invokedynamic` bootstrap + unrestricted `doPrivileged` | Trusted bootstrap method uses unrestricted `doPrivileged` | Same obligation as above |
| Finalizer context escape | Trusted finalizer/Cleaner callback performs operation blocked by creator's limited context | Avoid sensitive ops in finalizers; use explicit `close()`; apply process isolation |

### What Requires Process Isolation

The following residual gaps cannot be fully closed in-process and require OS-level
process isolation (each service in its own JVM/container):

| Residual Gap | Why In-Process Guards Are Insufficient |
|--------------|----------------------------------------|
| Finalizer / Cleaner thread context escape | Creator's restricted `AccessControlContext` is not carried to the finalizer/Cleaner thread; no in-process mechanism propagates it |
| JVMTI / `-agentlib:` attached at startup | JVMTI agents run before the `SecurityManager` is installed and can bypass all Java-level checks |
| JNI `CallXxxMethod` callbacks from within native code | Re-entrant JNI calls do not go through Java-side permission checks |
| Shared-memory side-channel attacks (Spectre-class) | Require hardware-level isolation (separate physical cores or core flushing) |
| Unrestricted `doPrivileged` in trusted code (structural) | DirtyChai cannot prevent a trusted class from using unrestricted `doPrivileged` |

### Operator Checklist

For deployments that handle untrusted code in the same JVM:

- [ ] Every trusted class that is callable from untrusted code **must not** use
      unrestricted `AccessController.doPrivileged(...)` on paths that lead to
      native calls, sensitive I/O, or class loading.
- [ ] Trusted classes must not perform sensitive operations in `finalize()` or
      `Cleaner` callbacks that should be restricted by the creator's
      `AccessControlContext`.
- [ ] `<clinit>` blocks in trusted classes must not use unrestricted
      `doPrivileged` to initialize security-sensitive resources.
- [ ] Use process isolation (Phoenix activation groups or containers) for
      code whose trust level is not fully established.
- [ ] Apply `--illegal-native-access=deny` (N-5) as a defence-in-depth measure.
- [ ] Deny `AttachPermission("attachVirtualMachine")` (and where needed
      `AttachPermission("createAttachProvider")`) to untrusted code; optionally
      add `-XX:+DisableAttachMechanism` for defense in depth.

---

## Implementation Plan: Invocation and Lifecycle Gap Verification (N-12)

The analyses in N-8, N-9, and N-10 describe the expected security behaviour of
DirtyChai across reflection, MethodHandle, finalizer, and class-initialization
invocation paths.  The following test inventory defines the verification coverage
needed to confirm these properties hold and to guard against regressions.

All test code must be **human-written** in compliance with the OpenJDK Interim
Policy on Generative AI adopted by DirtyChai.

### Test Inventory

#### Reflection Path (N-8)

| Test ID | Description | Expected Outcome | Guard Layer |
|---------|-------------|-----------------|-------------|
| R-1 | `Method.invoke(null, customSM)` attempts to install a custom `SecurityManager` via reflection | `SecurityException` thrown before installation | Stack-walk reflection-frame detection |
| R-2 | `Method.invoke()` calling trusted class public method that internally calls native (no `doPrivileged`) with untrusted caller on stack | `SecurityException` thrown (untrusted PD lacks `NativeInvocationPermission`) | Stack-intersection in `checkPermission` |
| R-3 | `Method.invoke()` calling trusted class method that uses unrestricted `doPrivileged` internally — untrusted caller on outer stack | **Allowed** (documents residual gap) | n/a — expected-fail test documenting trusted-code obligation |
| R-4 | `MethodHandle.invoke*()` targeting `System.setSecurityManager` with a custom SM | `SecurityException` thrown | Stack-walk `java.lang.invoke.*` frame detection |
| R-5 | `MethodHandle.invoke()` calling trusted class method that checks `NativeInvocationPermission`, untrusted caller on stack | `SecurityException` thrown | Stack-intersection in `checkPermission` |
| R-6 | `MethodHandles.lookup().in(TrustedClass.class)` from untrusted code to access private member | `IllegalAccessException` or `SecurityException` | `Lookup.in()` access check and `checkPackageAccess` |
| R-7 | Linkage-time `MethodHandle` frames (`LambdaMetafactory`, `StringConcatFactory`) during SM installation | Allowed — whitelisted linkage-time classes do not block installation of trusted SM implementations | F-10 whitelist |

#### Finalizer and Cleaner Path (N-9)

| Test ID | Description | Expected Outcome | Guard Layer |
|---------|-------------|-----------------|-------------|
| F-1 | Object with untrusted class `finalize()` calls native method via trusted wrapper (no `doPrivileged` in target) | `SecurityException` thrown (untrusted PD on finalizer stack lacks `NativeInvocationPermission`) | Stack-intersection during `checkPermission` |
| F-2 | Object with trusted class `finalize()` calls native method the class is permitted to call | **Allowed** | Policy grant |
| F-3 | Cleaner callback (`Runnable` implementation in untrusted class) calls `checkPermission`-protected resource | `SecurityException` thrown (untrusted Runnable PD on Cleaner thread stack) | Stack-intersection during `checkPermission` |
| F-4 | Trusted object created inside `doPrivileged(action, limitedContext)` whose `finalize()` performs an operation blocked by `limitedContext` | **Allowed** (documents context-escape residual gap) | n/a — expected-behavior test documenting process-isolation obligation |

#### Class Initialization and Constant-Pool Path (N-10)

| Test ID | Description | Expected Outcome | Guard Layer |
|---------|-------------|-----------------|-------------|
| C-1 | Untrusted code directly references new class (not yet loaded) that requires `LoadClassPermission` | `SecurityException` thrown at class load time | `LoadClassPermission` gate |
| C-2 | Untrusted code triggers `<clinit>` of already-loaded trusted class that checks a permission the untrusted code does not hold | `SecurityException` thrown (untrusted PD on `<clinit>` stack) | Stack-intersection during `<clinit>` permission check |
| C-3 | Trusted `<clinit>` uses unrestricted `doPrivileged` on a sensitive operation; triggered from untrusted code | **Allowed** (documents residual gap and trusted-code obligation) | n/a — expected-behavior test documenting library-author obligation |
| C-4 | `invokedynamic` call site with custom bootstrap method that checks a permission; called first from untrusted code | `SecurityException` thrown (untrusted PD on bootstrap method stack) | Stack-intersection |
| C-5 | `CONSTANT_Dynamic` bootstrap method checking a permission; first `ldc` from untrusted code | `SecurityException` thrown (untrusted PD on bootstrap stack) | Stack-intersection |

### Suggested File Locations

```
test/jdk/au/zeus/jdk/authorization/
  reflection/
    ReflectiveSmInstallBlockedTest.java        (R-1)
    ReflectiveNativeCallIntersectionTest.java  (R-2, R-3)
    MethodHandleSmInstallBlockedTest.java      (R-4, R-7)
    MethodHandleNativeCallIntersectionTest.java (R-5, R-6)
  lifecycle/
    FinalizerPermissionTest.java               (F-1, F-2)
    CleanerPermissionTest.java                 (F-3, F-4)
  classinit/
    LoadClassPermissionTest.java               (C-1)
    ClinitStackIntersectionTest.java           (C-2, C-3)
    InvokeDynamicBootstrapPermissionTest.java  (C-4)
    ConstantDynamicBootstrapPermissionTest.java (C-5)
```

---

## In-depth Analysis: JGDMS Activation for Process Isolation of Untrusted Code

### Background — The Java Activation Framework and JGDMS Phoenix

The Java RMI Activation system (`java.rmi.activation`) allowed remote objects to be
instantiated on demand in a managed, monitored JVM process.  The standard activation
daemon was `rmid`; JGDMS ships its own replacement, **Phoenix**, which adds a
SecurityManager policy, logging, and fault recovery.

Java removed `java.rmi.activation` from the JDK in Java 17 (JEP 407).  JGDMS
maintains its own preserved and hardened copy of the Activation API and Phoenix daemon,
making JGDMS the only actively maintained path for using the Activation pattern on a
modern JVM.

### Activation Groups as OS Process Boundaries

The key architectural primitive is the **activation group**:

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Phoenix Activation Daemon (OS process 1)                                │
│  ActivationSystem — manages all groups                                  │
│  ActivationMonitor — watches group health                               │
│  ActivationInstantiator — launches group JVMs on demand                 │
└────────────────────────────┬────────────────────────────────────────────┘
                             │  forks on first request
          ┌──────────────────┼──────────────────┐
          │                  │                  │
  ┌───────▼──────┐  ┌────────▼─────┐  ┌────────▼─────┐
  │ Group JVM A  │  │ Group JVM B  │  │ Group JVM C  │
  │ (OS proc 2)  │  │ (OS proc 3)  │  │ (OS proc 4)  │
  │ ServiceImpl1 │  │ ServiceImpl2 │  │ ServiceImpl3 │
  │ ServiceImpl4 │  │              │  │              │
  └──────────────┘  └──────────────┘  └──────────────┘
```

Each activation group runs in a **separate OS process**, configured by an
`ActivationGroupDesc` that specifies:

| Parameter | Purpose |
|---|---|
| `codebase` | URL from which the service's classes are loaded |
| `policy` | Path to the policy file governing the group's JVM |
| JVM arguments | `-Djava.security.manager`, heap size, module flags, etc. |
| `ActivationGroupID` | Stable identifier used to re-activate the group after a crash |

Because each group is a separate OS process, it has its own:

- **Heap** — no shared memory with other groups or the Phoenix daemon.
- **Class loader hierarchy** — no class-loader confusion across groups.
- **SecurityManager and policy** — fully independent permission set.
- **File descriptors and sockets** — OS-level resource accounting per process.

### DirtyChai SecurityManager Inside Each Activation Group

The recommended deployment pattern is to install the DirtyChai SecurityManager inside
every activation group JVM.  The group's JVM arguments include:

```
-Djava.security.manager=au.zeus.jdk.authorization.sm.CombinerSecurityManager
-Djava.security.policy=/etc/myservice/group-a.policy
```

This means that every service implementation class running inside the group JVM is
subject to the full DirtyChai permission model:

- `SerialObjectPermission` controls what classes may be deserialized.
- `NativeInvocationPermission` blocks unauthorized native library loading.
- `LoadClassPermission` gates class loader creation.
- `ConcurrentPolicyFile` evaluates grants without DNS lookups.
- `createVirtualThread` / `createPlatformThread` (implemented) limit thread creation.

The combination of an OS process boundary **and** a DirtyChai SecurityManager means
that even if an attacker successfully exploits a deserialization bug or logic flaw
inside one service, the damage is contained to:

1. The memory of that single OS process (OS boundary).
2. The permissions explicitly granted in that group's policy file (DirtyChai boundary).

### Activation Lifecycle and Trust

**Service registration:**

A trusted administrator calls `ActivationSystem.registerObject(ActivationDesc)` to
register a service.  The `ActivationDesc` records the group, the implementation class
name, the serialized data needed to reconstruct the service, and the codebase URL.
Registration requires `java.rmi.activation.ActivationPermission "registerGroup"` in
the administrator's policy, preventing untrusted code from registering new services.

**On-demand activation:**

When a client invokes a method on an activatable proxy, the proxy detects that the
remote service is not running and calls `ActivationSystem.activate(ActivationID, ...)`.
Phoenix forks a new group JVM (or reconnects to an existing one), the service is
instantiated in that JVM, and the proxy's stub is updated to point to the live
endpoint.  Subsequent calls go directly to the group JVM without involving Phoenix.

**Crash recovery:**

If a group JVM crashes (out-of-memory, killed by the OS OOM killer, unhandled
exception in a finalizer thread), Phoenix detects the broken connection and will
re-activate the group on the next client call.  The service implementation receives a
fresh `ActivationID` and is reconstructed from the stored `ActivationDesc` data.
The client proxy retries the call transparently.

**Trust boundary between Phoenix and group JVMs:**

Phoenix communicates with group JVMs over a local-loopback RMI connection.  Both
ends must present credentials accepted by the other's SecurityManager policy.  Because
Phoenix runs under its own DirtyChai policy (separate from the group's policy), a
compromised group JVM cannot escalate privileges into Phoenix — it can only make calls
that Phoenix's policy permits.

### Residual N-13: Activation Deserialization Authority Trust Boundaries

This section expands the residual N-13 entry in `SECURITY_ANALYSIS.md` with a
focused trust-boundary analysis for DirtyChai + JGDMS + Phoenix activation flows.

**Cross-reference:** `SECURITY_ANALYSIS.md` → Residual risk 11 (**N-13**),
**"Activation deserialization authority (N-13)"**.

#### Integration points in scope

- `SharedActivatableServiceDescriptor` (JGDMS service-registration path and `ActivationDesc` creation)
- `TlsRMIClientSocketFactory` / `TlsRMIServerSocketFactory` (JGDMS TLS transport/authentication path)
- Phoenix activation daemon persistence and re-activation path
- Group JVM bootstrap and `ActivationDesc` deserialization/reconstruction path

#### Trust-boundary gaps (documented residuals)

| Boundary | Documented gap | Exploitation consequence |
|---|---|---|
| 1. Calling JVM → group JVM deserialization boundary | `SerialObjectPermission` is enforced in the active deserializing JVM; activation reconstruction currently has no verified cross-JVM carry-over contract from service-registrar JVM (the JVM that registers the activatable descriptor) decisions. | Policy bypass if group JVM allowlist differs from caller allowlist. |
| 2. Phoenix persistent store integrity boundary | No documented descriptor-level integrity mechanism (HMAC/signature) for stored `ActivationDesc` state. | Descriptor tampering can inject altered activation payloads before restart/re-activation. |
| 3. Re-activation policy authority boundary | Reconstruction-time policy authority is implementation-defined for restart/replay flows and must be treated as requiring explicit operator verification. | Effective authority may drift to the weaker policy surface, reducing intended deserialization controls. |
| 4. AccessControlContext lifecycle boundary | Restart/replay flows do not define a guaranteed fresh `AccessControlContext` rebind contract unless bootstrap logic explicitly rebuilds context from current policy state. | Stale context reuse can preserve broader historical privilege after policy tightening. |
| 5. TLS-authenticated identity propagation boundary | TLS peer authentication is transport-level; authenticated peer identity requires explicit context propagation/binding to participate in service deserialization authority decisions. | Identity confusion: authenticated client identity may not participate in per-call deserialization decisions. |

#### Threat model and exploitation scenarios

| Gap | Threat actor capability | Representative scenario | Security impact |
|---|---|---|---|
| SerialObjectPermission reinforcement ambiguity | Can register or influence activatable descriptors | Admin-side checks are strict, but group JVM policy is more permissive; re-activation deserializes a class denied in the origin JVM | Cross-JVM deserialization policy bypass |
| ActivationDesc integrity gap | Can modify Phoenix persistence store (filesystem compromise or daemon compromise) | Stored descriptor/init data is altered, then loaded after crash/restart | Tampered descriptor injection during activation |
| Policy authority ambiguity | Can cause re-activation under different policy state | Service re-activates under policy scope that does not match operator expectation | Silent weakening of deserialization authority |
| ACC freshness gap | Can trigger restart after policy/state drift | Previously captured context survives restart semantics and is reused | Privilege persistence/escalation after policy change |
| TLS subject propagation gap | Has valid TLS credentials but should have constrained identity scope | Transport auth succeeds, but deserialization path lacks caller principal binding | Confused identity / coarse-grained authorization decisions |

#### Existing mitigations vs residual risk

| Area | Existing mitigation | Residual risk |
|---|---|---|
| Standard Java deserialization in DirtyChai | `SerialObjectPermission` guard at `ObjectInputStream.readOrdinaryObject()` in the active JVM | Cross-JVM activation path authority boundaries are not yet fully documented/enforced end-to-end |
| JGDMS transport | TLS socket factories and JERI constraints for channel auth/integrity/confidentiality | Transport identity is not equivalent to deserialization-authority identity inside re-activation context |
| Process isolation | Phoenix and each group JVM run in separate OS processes with separate policies | Isolation does not guarantee descriptor integrity or authority continuity across restart/replay |
| Policy controls | Per-process policy files and least-privilege guidance in this document | Re-activation-time policy precedence and ACC freshness semantics remain under-specified |

#### Hardening recommendations

**High priority**

1. Define and implement descriptor integrity protection for persisted activation state
   (signature or HMAC over `ActivationDesc` and security-relevant fields such as
   implementation class, codebase, policy path, restart flag, and init data).
2. Make group JVM deserialization authority explicit and enforceable: document and
   verify `SerialObjectPermission` reinforcement semantics during activation
   reconstruction.
3. Bind re-activation authority to fresh security context materialization at group JVM
   bootstrap (no stale context reuse across restart boundaries).

**Medium priority**

1. Specify policy precedence rules for activation replays/restarts (registrar policy vs
   group policy) and add operator-facing diagnostics when mismatches are detected.
2. Define principal propagation semantics for TLS-authenticated calls so service-side
   deserialization/authorization logic can consume authenticated identity explicitly.
3. Add activation-lifecycle audit events (descriptor write/read/verify/replay) for
   incident response and post-mortem authority tracing.

#### Investigation task backlog (for issue tracking)

- [ ] ACTIVATION-DESC-INTEGRITY (high): Prototype `ActivationDesc` integrity envelope (sign/verify) for Phoenix persistence.
- [ ] GROUP-DESERIALIZATION-AUTHORITY (high): Instrument group JVM reconstruction path to assert/document `SerialObjectPermission` authority source.
- [ ] ACC-RESTART-FRESHNESS (high): Define and test `AccessControlContext` refresh semantics on activation group restart.
- [ ] POLICY-PRECEDENCE-REACTIVATION (medium): Specify and validate policy-authority precedence for re-activation.
- [ ] TLS-SUBJECT-PROPAGATION (medium): Define TLS subject propagation contract into service deserialization context.

### What Activation Isolation Does and Does Not Provide

| Property | In-process (no Activation) | With JGDMS Activation |
|---|---|---|
| Separate heap | No | Yes — separate OS process |
| SecurityManager isolation | Yes — same SM, same policy | Yes — independent SM and policy per group |
| Crash isolation | No — one thread can crash the JVM | Yes — group crash does not affect Phoenix or other groups |
| Side-channel isolation | No — shared cache lines | Partial — OS process boundary reduces but does not eliminate timing side channels |
| Memory corruption isolation | No — shared heap | Yes — separate address spaces |
| Network isolation | Depends on policy | Depends on policy + OS firewall |

**What Activation does not solve:**

- A group JVM that holds a `SocketPermission "* connect"` grant can still make
  arbitrary outbound network connections unless the OS firewall also restricts the
  group's process.
- JVM-level side channels (Spectre, Meltdown) cross process boundaries on shared
  hardware without OS-level mitigations (KPTI, retpoline, etc.).
- A compromised Phoenix daemon can manipulate all group JVMs.  Phoenix itself must
  therefore run under a strict DirtyChai policy and be considered a high-value
  attack target.

### Recommended Configuration for Untrusted Code

1. **One activation group per untrusted service** — do not share a group between
   services of differing trust levels.
2. **Minimal policy per group** — use `SecurityPolicyWriter` to generate a
   least-privilege policy for each service and apply it to that group's JVM only.
3. **Phoenix under DirtyChai** — run the Phoenix daemon itself with the
   DirtyChai SecurityManager and a tightly scoped policy.
4. **OS-level containment** — run each group JVM under a separate OS user account or
   Linux namespace (cgroup + seccomp) to prevent cross-process resource access even
   if the SecurityManager is bypassed.
5. **Outbound firewall per group** — use per-user or per-cgroup firewall rules to
   restrict which remote hosts each group JVM may contact.

### Hardware-Level Isolation Against Spectre/Meltdown-Class Attacks

#### Why These Attacks Are Different

Spectre and Meltdown exploit **CPU microarchitectural behaviour** — speculative
execution, out-of-order execution, and shared cache structures — not software bugs.
They leak information through timing rather than direct memory reads.  This means:

- OS-level process isolation (separate address spaces, ASLR) **does not prevent
  them** on its own.
- The attack works across OS process boundaries as long as two processes share the
  same physical CPU core or sibling hyper-thread, because they share the L1 cache,
  branch predictor tables, and TLBs.

#### OS-Level Software Mitigations

The following mitigations are available today on Linux, Windows, and macOS and
are what the table in [What Activation Isolation Does and Does Not Provide](#what-activation-isolation-does-and-does-not-provide)
references:

| Mitigation | What it does | OS / hardware support |
|---|---|---|
| **KPTI** (Kernel Page-Table Isolation) | Separates kernel and user-space page tables so kernel memory is not mapped while user code runs. Defeats Meltdown (CVE-2017-5754). | Linux ≥ 4.15 (default on); Windows 10; macOS 10.13.2+ |
| **Retpoline** | Replaces indirect branches with a non-speculative trampoline; defeats most Spectre v2 (CVE-2017-5715) variants. | Linux (GCC/Clang, default); Windows (MSVC); requires recompiled kernel and JVM |
| **IBRS / IBPB / STIBP** | CPU microcode patches from Intel/AMD that flush branch-predictor state on context switches. | Requires microcode update + OS support (Linux, Windows) |
| **SSB Disable** (Spectre v4, CVE-2018-3639) | Disables speculative store bypass. Performance cost: 10–30 %. | Linux (`prctl(PR_SET_SPECULATION_CTRL, ...)`); Windows registry policy |
| **SMT / Hyper-Threading disabled** | Completely removes cross-thread cache sharing on the same physical core. Most effective physical isolation short of a separate machine. | Linux (`echo off > /sys/devices/system/cpu/smt/control`); BIOS setting; OpenBSD (default) |

**OpenBSD** is the most aggressive general-purpose OS in this space: it disables
hyper-threading by default across the entire system and has applied KPTI, retpoline,
and IBPB mitigations as kernel defaults since 2018.  For deployments where the
threat model includes Spectre-class cross-process leakage, OpenBSD provides the
strongest out-of-the-box posture among mainstream OSes.

#### Physical Core Separation

For a Phoenix host classified as a high-value target, software mitigations alone are
not sufficient: an adversary with kernel access on the same physical host can disable
or bypass them.  The definitive countermeasure is to remove the shared microarchitectural
resource entirely:

1. **Dedicated physical host for Phoenix** — bare metal or a dedicated-tenancy cloud
   instance.  If no other process runs on the same physical CPUs, cross-process
   speculative-execution leakage has no channel to exploit.

2. **Disable SMT (hyper-threading)** — two hyper-threads on the same physical core
   share the L1 cache and branch predictor.  Disabling SMT at the BIOS level (or via
   the kernel interface above) eliminates this sharing for all processes on the host.

3. **Hypervisor with strict CPU affinity** — when VMs are in use, pin Phoenix's VM
   to physical cores that are never shared with untrusted VMs.  Xen supports this
   via `cpupool`; VMware via vCPU affinity; KVM via `vcpupin` in the domain XML.
   AWS Nitro dedicated instances provide physical-core exclusivity as a product
   guarantee.

4. **Apply all microcode + OS mitigations on the untrusted-code host** — KPTI, IBPB,
   and retpoline on the host running group JVMs ensure that even if an untrusted
   process can speculate, the kernel's view of Phoenix memory is not in scope.

#### Platforms and Deployment Topologies

| Platform / topology | Spectre/Meltdown posture |
|---|---|
| OpenBSD (bare metal or VM) | HT off by default; KPTI + IBPB applied; strongest general-purpose OS default |
| Linux with `smt=off`, KPTI, IBPB, retpoline | Equivalent to OpenBSD when correctly configured; requires explicit setup |
| AWS Nitro dedicated instance + SMT disabled | Physical-core exclusivity guaranteed by hypervisor; no neighbour noise |
| seL4 microkernel | Formally verified isolation; minimal kernel attack surface; does not solve speculative execution but eliminates large classes of kernel-level attack that enable Meltdown exploitation |
| Genode (on seL4 or Fiasco.OC) | Capability-based compartmentalisation; inherits seL4 isolation properties |
| Shared multi-tenant cloud VM (default) | **Insufficient** — physical cores and cache shared with unknown neighbours; software mitigations only |

#### Practical Recommendation for Phoenix

For a Phoenix daemon considered a high-value target (see
[What Activation does not solve](#what-activation-does-not-solve)):

1. Run Phoenix on a **dedicated physical host** (bare metal, or dedicated-tenancy
   cloud instance with confirmed physical-core exclusivity).
2. **Disable SMT** at the BIOS or kernel level on the Phoenix host.
3. **Enable KPTI + IBPB + retpoline** on every host running group JVMs, so those
   processes cannot read the Phoenix host's kernel-level data even if a Meltdown
   variant is discovered.
4. Use **network-only communication** between Phoenix and group JVM hosts — no shared
   memory segments, no shared IPC namespaces, no shared filesystems.

With this topology, two processes running on the Phoenix host never share a physical
CPU core with untrusted processes, and microarchitectural side channels have no viable
path to leak Phoenix secrets.

---

## Investigation: DirtyChai + JGDMS for In-Process and Remote Network Isolation

> **JDK compatibility note:** JGDMS requires a SecurityManager-capable JDK.
> Standard OpenJDK removed `SecurityManager` in Java 24.  DirtyChai restores
> this infrastructure, making DirtyChai the required JDK for any deployment
> that combines JGDMS services with the in-process permission model described
> in this document.  Using JGDMS on standard OpenJDK 24+ without DirtyChai
> leaves the in-process permission layer absent.

### The Two Isolation Dimensions

A JGDMS service deployment has two distinct isolation boundaries:

| Dimension | Mechanism | Provided by |
|---|---|---|
| **In-process** | SecurityManager + policy enforcement | DirtyChai |
| **Remote network** | JERI transport + endpoint constraints | JGDMS |

These two dimensions are independent and complementary.  DirtyChai governs what code
running *inside* a JVM process may do.  JGDMS governs what objects are permitted to
*cross* the network boundary.  Neither is sufficient alone.

### In-Process Isolation Layer (DirtyChai)

When a DirtyChai SecurityManager is active in a service JVM, every permission-checked
operation passes through `CombinerSecurityManager.checkPermission()` and is evaluated
against the policy loaded by `ConcurrentPolicyFile`.

**What is isolated in-process:**

| Attack | DirtyChai Control |
|---|---|
| Deserialization gadget chain via `ObjectInputStream` | `SerialObjectPermission` — class must be whitelisted |
| Arbitrary native library loading | `NativeInvocationPermission` + `RuntimePermission("loadLibrary.*")` |
| Unauthorized class loader creation | `LoadClassPermission` |
| Thread bomb DoS | `createPlatformThread` / `createVirtualThread` (implemented) |
| `System.exit()` | `RuntimePermission("exitVM.*")` |
| Reflective access to internals | Module encapsulation + SecurityManager |
| DNS / LDAP lookups (Log4j-style) | `SocketPermission` must be granted |

**What in-process isolation cannot prevent:**

See "Why Process Isolation Remains Essential" earlier in this document
(shared memory, side-channel attacks, JVM internals, resource exhaustion,
class-loader confusion).  These residual gaps make OS process isolation
essential for truly untrusted code.

### Remote Network Isolation Layer (JGDMS JERI)

JERI (Jini Extensible Remote Invocation) is the transport layer used for all
JGDMS remote service communication.  It sits above the socket/SSL layer and below
the Java application code.

**JERI security features used for network isolation:**

| Feature | How it works |
|---|---|
| **Transport authentication** | Kerberos, TLS mutual authentication, or anonymous — negotiated per endpoint |
| **Message integrity** | `Integrity.YES` constraint ensures no MITM tampering with method arguments or return values |
| **Confidentiality** | `Confidentiality.YES` constraint enables TLS encryption for sensitive transports |
| **`AccessControlContext` propagation** | The caller's security context travels with the remote call; the server can inspect it |
| **`AtomicMarshalInputStream`** | All unmarshalled objects cross the `@AtomicSerial` constructor — gadget chains cannot fire |

**JERI constraint enforcement:**

Every JERI endpoint is configured with a set of `InvocationConstraints`.  When the
client proxy makes a call, the `BasicInvocationHandler` verifies that the negotiated
transport satisfies all required constraints before the call is dispatched.  If the
transport cannot satisfy a required constraint (e.g., the server does not support TLS),
the call is rejected before any data is sent.

```
Client proxy (BasicInvocationHandler)
        │
        │  Required: Integrity.YES, Confidentiality.YES, ServerAuthentication
        │
        ▼
JERI transport negotiation
        │
        ├── OK: transport satisfies all constraints → call dispatched
        └── FAIL: constraint unsatisfied → RemoteException, no data sent
```

This means a network attacker who strips TLS or replaces the server certificate cannot
cause the client to send sensitive method arguments — the client detects the constraint
failure and aborts before transmission.

### AccessControlContext Propagation Across the JERI Boundary

JGDMS JERI can propagate the caller's `AccessControlContext` with the remote call.
On the server side, the service implementation can call
`ServerContext.getServerContextElement(AccessControlContext.class)` to retrieve the
caller's context.  The server can then execute code under `doPrivileged(action, clientContext)`,
applying the client's restrictions rather than the server's full privileges.

**Threat model implication:**  Even if an attacker successfully authenticates to the
service (e.g., with a valid but low-privilege Kerberos ticket), the server can enforce
that the caller's operations are bounded by the caller's own `ProtectionDomain`
permissions.  The server does not grant its own elevated permissions to arbitrary callers.

### Combined Architecture for a JGDMS Service

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Client JVM                                                              │
│  JGDMS smart proxy (BasicInvocationHandler)                            │
│  Required constraints: Integrity.YES, TLS, ServerAuthentication        │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │  JERI over TLS
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│ OS network boundary (firewall / namespace)                             │
│  Allowed: specific port from specific source IP                        │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Service OS process (Phoenix activation group)                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ DirtyChai SecurityManager (CombinerSecurityManager)             │   │
│  │  ConcurrentPolicyFile — least-privilege policy for this group   │   │
│  ├─────────────────────────────────────────────────────────────────┤   │
│  │ JERI server endpoint                                            │   │
│  │  AtomicMarshalInputStream — @AtomicSerial deserialization       │   │
│  │  AccessControlContext propagation from client                   │   │
│  ├─────────────────────────────────────────────────────────────────┤   │
│  │ Service implementation                                          │   │
│  │  SerialObjectPermission guards any ObjectInputStream use        │   │
│  │  NativeInvocationPermission guards any native API use               │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘
```

### Network Isolation — What JGDMS Provides and What the OS Must Provide

JGDMS JERI provides **application-layer network isolation**: it controls what objects
and calls may cross a specific service endpoint.  It does not control which IP addresses
or ports the service JVM may contact at the OS level.

OS-level network isolation is required as a separate, independent layer:

| OS Control | Effect |
|---|---|
| Per-process firewall rules (nftables, iptables) | Restrict which remote hosts the service JVM may contact |
| Linux network namespaces | Give each service JVM its own loopback and a controlled external interface |
| Container network policy (Kubernetes `NetworkPolicy`) | Enforce which services may communicate |
| Egress-only firewall for sensitive services | Prevent a compromised service from becoming a pivot point |

**Without OS-level network controls**, a service JVM that holds a
`SocketPermission "* connect"` grant can contact any reachable host.  DirtyChai can
narrow this grant to specific hosts and ports in the policy file, but the OS firewall
provides a defence-in-depth layer that is not defeatable by a compromised SecurityManager.

### Summary: Layered Isolation Model

| Layer | Mechanism | Addresses |
|---|---|---|
| JVM in-process | DirtyChai SecurityManager + ConcurrentPolicyFile | Per-code-source permission enforcement |
| Deserialization | `SerialObjectPermission` + JGDMS `@AtomicSerial` | Gadget chains, class whitelisting |
| OS process | JGDMS Phoenix activation groups | Memory, crash, and class-loader isolation |
| Network application | JGDMS JERI constraints + `AtomicMarshalInputStream` | Tampered proxies, MITM, malformed RPC arguments |
| Network OS | Firewall, namespaces, container policy | Unrestricted outbound connections, pivot attacks |

No single layer is sufficient.  All five layers are required for a defence-in-depth
posture when handling untrusted remote input.

---

## Correction: How JGDMS Actually Handles Proxy Trust (No ProxyTrust)

> **Reference context:** This section documents JGDMS-specific proxy-trust
> mechanics for developers integrating DirtyChai-based services into a JGDMS
> deployment.  It corrects a common misreading of Jini/Apache River
> documentation.

### The Misconception

A common assumption when reading Jini or Apache River documentation is that **smart
proxy trust** is established through the `net.jini.security.proxytrust.ProxyTrust`
interface:

```java
// Classic Jini ProxyTrust pattern (NOT used in JGDMS)
public interface ProxyTrust {
    TrustVerifier getProxyVerifier() throws RemoteException;
}
```

In this pattern, a smart proxy implements `ProxyTrust`.  A client calls
`getProxyVerifier()` through a separate, already-trusted channel (the bootstrap stub),
obtains a `TrustVerifier`, and then calls `TrustVerifier.isTrustedObject(proxy, context)`.
If the verifier confirms the proxy, it is trusted.

**JGDMS does not use this pattern** for its primary trust mechanism.

### How JGDMS Actually Establishes Proxy Trust

JGDMS replaces the `ProxyTrust` callback model with a combination of three independent
mechanisms that together guarantee the same properties without requiring a
`getProxyVerifier()` round-trip.

#### Mechanism 1: Codebase Certificates (Static Trust)

When a JGDMS service registers with the Jini lookup service (Reggie or equivalent),
it annotates its proxy classes with a codebase URL.  The proxy JAR at that URL is
signed with the service provider's certificate.

When the client downloads the proxy:

1. The client's JGDMS dynamic policy first requires `DownloadPermission` to be
   granted to the lookup service's authenticated principal before it will fetch
   any proxy JAR.  This prevents an untrusted lookup service from injecting
   arbitrary proxy classes.
2. `RMIClassLoader` (or the JGDMS class loader) fetches the JAR from the codebase URL.
3. The JAR signature is verified against the certificate in the client's truststore.
4. The proxy class is loaded into a `ProtectionDomain` whose `CodeSource` records the
   verified certificate.
5. The client's policy grants permissions to `CodeSource` entries signed by trusted
   certificates — unsigned or mis-signed proxies receive no permissions and are
   immediately inert.

This is equivalent to the `ProxyTrust` pattern's outer layer (confirming that the proxy
*class* comes from a trusted source), but it is enforced by the JVM class loader and
the DirtyChai `ConcurrentPolicyFile` rather than by a `getProxyVerifier()` call.

#### JGDMS JERI ClassLoader Resolution in `AtomicILFactory` (and why it prevents ClassLoader confusion)

`AtomicILFactory` anchors unmarshalling to a deterministic loader rather than ambient
thread context:

1. `AtomicILFactory` is created with an explicit loader, or derives one from
   `proxyOrServiceImplClass.getClassLoader()`.
2. It passes that loader into `AtomicInvocationDispatcher`.
3. `AtomicInvocationDispatcher.createMarshalInputStream(...)` selects `streamLoader`
   and passes it as both `defaultLoader` and `verifierLoader` to
   `AtomicMarshalInputStream.create(...)`.
4. `AtomicMarshalInputStream` extends `MarshalInputStream`, and
   `MarshalInputStream.resolveClass/resolveProxyClass` call
   `ClassLoading.loadClass/loadProxyClass(..., defaultLoader, ...)`.

By default, `AtomicILFactory` does not use stream codebase annotations
(`useAnnotations = false`), so resolution occurs with a `null` codebase and the selected
default loader.  Annotation-enabled constructors are deprecated and explicitly described
as risky for class-loading safety.

This design reduces ClassLoader confusion by forcing remote argument and proxy-interface
resolution through the service/proxy loader chosen at export time, instead of whichever
thread context class loader happens to be active at invocation time.  The result is more
stable class identity, fewer cross-loader type mismatches, and policy decisions that
remain tied to the expected `CodeSource`/`ProtectionDomain`.

#### Mechanism 2: JERI Endpoint Integrity Constraints (Dynamic Trust)

Once the proxy class is loaded, all communication through the proxy passes through a
`BasicInvocationHandler` configured with required `InvocationConstraints`:

```
Required: { Integrity.YES }
```

`Integrity.YES` is a mandatory constraint.  If the transport cannot guarantee message
integrity (e.g., the connection is plain TCP with no HMAC), the `BasicInvocationHandler`
refuses to make the call.  This ensures that:

- Method arguments travelling from client to server are not tampered with in transit.
- Return values travelling from server to client are not tampered with in transit.
- A network attacker who intercepts the connection cannot substitute a different proxy
  or alter the objects the server returns.

This replaces the `ProxyTrust` pattern's inner layer (confirming that the proxy
*instance* has not been tampered with at runtime), without requiring a
`getProxyVerifier()` call through a separate trusted channel.

#### Mechanism 3: GrantPermission (Dynamic Policy Trust)

JGDMS uses `net.jini.security.GrantPermission` to allow authenticated services to
request specific permissions from the client's policy.  The proxy JAR bundles a
`PREFERRED/permissions.properties` or equivalent declaration of the permissions the
service requires.  An administrator grants `GrantPermission` scoped to those specific
permissions to authenticated service principals.

When the service authenticates successfully (Kerberos or TLS mutual auth), the client's
dynamic policy promotes the proxy's `ProtectionDomain` to include exactly the
advertised permissions — no more.  If the proxy requests permissions beyond what the
administrator has authorised, the `GrantPermission` grant does not cover them, and the
call fails.

This replaces the trust-grant step that `ProxyTrust.getProxyVerifier()` was sometimes
used for, with a declarative, administrator-controlled permission grant.

### Why ProxyTrust Is Not Needed

The `ProxyTrust` interface was designed to answer the question: *"How does a client
know that this smart proxy object it downloaded from the lookup service can be
trusted?"*

JGDMS answers that question through the three mechanisms above:

| Question | ProxyTrust answer | JGDMS answer |
|---|---|---|
| Is the proxy class from a trusted source? | `getProxyVerifier()` call through bootstrap stub | Signed JAR + ConcurrentPolicyFile CodeSource grant |
| Has the proxy instance been tampered with? | `TrustVerifier.isTrustedObject(proxy)` | JERI `Integrity.YES` constraint on all transport |
| What permissions may this proxy use? | Not addressed by ProxyTrust | `GrantPermission` scoped to authenticated service principal |

The `ProxyTrust` approach requires the client to have a pre-trusted bootstrap stub
(typically a plain JRMP or JERI stub without smart-proxy logic) through which it can
reach the server to call `getProxyVerifier()`.  This adds a round-trip and requires
the bootstrap stub to be separately managed.

The JGDMS approach eliminates the bootstrap stub requirement: the JAR signature alone
establishes class-level trust, and the JERI endpoint integrity constraint establishes
instance-level trust.  The only precondition is that the client's truststore contains
the service provider's certificate — the same precondition that the `ProxyTrust`
bootstrap stub approach requires for the bootstrap channel anyway.

### Implications for @AtomicSerial

Because all JGDMS proxies are reconstructed through `@AtomicSerial` constructors when
they cross a JERI boundary (via `AtomicMarshalInputStream`), there is an additional
implicit trust check: the proxy object's `@AtomicSerial` constructor validates all
fields at construction time.  A tampered proxy that has syntactically invalid fields
(e.g., a null endpoint reference, out-of-range constraint values) will throw
`InvalidObjectException` before the proxy is usable, regardless of whether the
transport integrity check passed.

This means the trust model has an additional in-constructor layer that the classic
`ProxyTrust` pattern does not provide.

### Summary

| Property | Classic Jini ProxyTrust | JGDMS |
|---|---|---|
| Mechanism | `getProxyVerifier()` round-trip through bootstrap stub | JAR certificate + JERI `Integrity.YES` + `GrantPermission` |
| Requires bootstrap stub | Yes | No |
| Class-level trust | Via `TrustVerifier.isTrustedObject()` | Via signed JAR CodeSource in policy |
| Instance-level trust | Via `TrustVerifier.isTrustedObject()` | Via JERI mandatory `Integrity.YES` constraint |
| Permission grant | Not addressed | `GrantPermission` scoped to authenticated principal |
| Tampered-object detection at construction | No | Yes — `@AtomicSerial` constructor validates all fields |
| Round-trips for trust establishment | 1 extra (`getProxyVerifier()`) | 0 extra (trust established by class loading + transport) |

---

## Analysis: Phoenix as a High-Value Attack Target — Security Hardening

### Why Phoenix Is the Crown Jewel of a JGDMS Deployment

The activation section above correctly identifies that "a compromised Phoenix daemon can
manipulate all group JVMs."  This section analyses *why* that is true, and derives the
minimum security hardening steps that must be applied to Phoenix itself.

Phoenix holds two powers that no other process in a JGDMS deployment shares:

1. **Fork authority** — Phoenix calls `Runtime.exec()` (or an equivalent OS API) to
   create each group JVM process.  The command line passed to `exec()` determines the
   SecurityManager class, policy file path, codebase, and every JVM argument for the
   group.  An attacker who can influence Phoenix's `exec()` call can install any
   SecurityManager, any policy, or any JVMTI agent in the spawned group.

2. **Registration authority** — Phoenix is the `ActivationSystem` implementation.  It
   decides which `ActivationGroupDesc` and `ActivationDesc` objects are valid.  An
   attacker who compromises Phoenix can register new services or modify existing
   registrations without any caller-side SecurityManager check catching the action.

The consequence is: **Phoenix is not just another service process; it is the trust anchor
for the entire activation topology.**  It must be treated with the same security posture
as the OS kernel of the host.

### Threat Model for Phoenix

| Threat | Attack Vector | Impact |
|--------|--------------|--------|
| T-P1: Policy injection | Attacker registers a malicious `ActivationGroupDesc` with a crafted policy path | All services in that group run under attacker-controlled policy |
| T-P2: SecurityManager injection | Malicious `ActivationGroupDesc` specifies `-Djava.security.manager=com.attacker.EvilSM` | DirtyChai SM replaced for that group |
| T-P3: JVMTI agent injection | Malicious JVM args include `-agentlib:evil` in `ActivationGroupDesc` | Native agent bypasses all Java-level security in that group |
| T-P4: ActivationDesc tampering | Attacker modifies Phoenix persistence store (log file) between restarts | Arbitrary service class loaded at activation time |
| T-P5: DoS via activation storm | Attacker causes continuous group crashes → continuous re-fork → CPU/memory exhaustion | Phoenix and all groups become unavailable |
| T-P6: Phoenix policy bypass | Phoenix itself is exploited (e.g., via a deserialisation bug in its internal RMI) | All groups can be controlled |

### Mitigations

#### M-P1 and M-P2: ActivationGroupDesc Validation

The primary guard is `java.rmi.activation.ActivationPermission "registerGroup"`.  Phoenix
only accepts a `registerGroup` call when the calling code's `ProtectionDomain` is granted
this permission.  With DirtyChai, the policy entry is:

```
// Phoenix policy — restrict who may register groups
grant CodeBase "file:/path/to/admin-tool/-"
      signedBy "admin-cert" {
    permission java.rmi.activation.ActivationPermission "registerGroup";
};
```

**No other codebase** should hold `registerGroup`.  This single grant is the entire
gate on T-P1, T-P2, and T-P3.

However, `ActivationPermission "registerGroup"` only controls *who* can call the API.
It does not validate the *content* of the `ActivationGroupDesc` after the call is
authorised.  A malicious but authorised admin tool could still pass a crafted descriptor.

The second layer of defence is therefore **OS-level path controls**:
- Phoenix should only accept policy file paths under a directory that the Phoenix OS
  user owns and that no other account can write to.
- The Phoenix startup wrapper script should validate that the `ActivationGroupDesc`'s
  policy path is an absolute path under a known-good prefix before forwarding it to
  `exec()`.

#### M-P3: JVMTI Agent Exclusion

Phoenix forks group JVMs using a command-line template.  The template should explicitly
reject any `ActivationGroupDesc` that attempts to include `-agentlib:`, `-agentpath:`,
`-javaagent:`, or `-Xrun` in its JVM arguments.

With DirtyChai, the recommended approach is to use a Phoenix startup wrapper that
filters the JVM argument list from `ActivationGroupDesc.getCommandEnvironment()` against
a whitelist of permitted flags before passing them to `exec()`.

#### M-P4: Persistence Store Integrity

Phoenix persists its activation state to a log directory.  If an attacker can write to
this directory between Phoenix restarts, they can inject arbitrary `ActivationDesc` or
`ActivationGroupDesc` objects that will be deserialised and acted upon at next startup.

Required OS controls:
- The log directory must be owned by the Phoenix OS user and mode `0700`.
- No other account (including the group JVM accounts) may write to it.
- A file-integrity monitor (e.g., `inotifywait`, AIDE, Tripwire) should alert on
  changes to the log directory between scheduled maintenance windows.

#### M-P5: Activation Storm Limiting

Phoenix does not natively limit how many re-activation attempts it makes for a crashing
group.  A service implementation that always crashes on startup will cause Phoenix to
fork indefinitely.  With DirtyChai, the recommended mitigation is to use a backoff
strategy:
- Phoenix (or the wrapper) tracks consecutive crash counts per group.
- After *N* consecutive crashes (suggested: 3), the group is marked `INACTIVE` and
  not re-activated until an administrator explicitly resets it.
- The JGDMS `ActivationPermission "system"` action allows management tools to reset
  group state.

#### M-P6: Phoenix's Own DirtyChai Policy

Phoenix must run under a DirtyChai `CombinerSecurityManager` with a minimal policy.
The policy should grant Phoenix only the permissions it needs:

```
// Minimum Phoenix policy — high-value-target hardening
grant CodeBase "file:/path/to/phoenix/-" {

    // Fork group JVMs
    permission java.lang.RuntimePermission "exec";

    // Read group policies (absolute paths under controlled directory)
    permission java.io.FilePermission "/etc/activation/groups/-", "read";

    // Read/write its own persistence store
    permission java.io.FilePermission "/var/lib/phoenix/-", "read,write,delete";

    // Listen for incoming activation requests (loopback, fixed port)
    permission java.net.SocketPermission "localhost:1098", "listen,accept";

    // Connect back to group JVMs on loopback (ephemeral ports)
    permission java.net.SocketPermission "localhost:1024-", "connect,resolve";

    // Deserialise ActivationDesc et al. from its persistence store
    permission au.zeus.jdk.authorization.guards.SerialObjectPermission
              "java.rmi.activation.ActivationDesc";
    permission au.zeus.jdk.authorization.guards.SerialObjectPermission
              "java.rmi.activation.ActivationGroupDesc";
    permission au.zeus.jdk.authorization.guards.SerialObjectPermission
              "java.rmi.activation.ActivationGroupDesc$CommandEnvironment";
    permission au.zeus.jdk.authorization.guards.SerialObjectPermission
              "java.rmi.activation.ActivationID";
    permission au.zeus.jdk.authorization.guards.SerialObjectPermission
              "java.rmi.activation.ActivationGroupID";
    permission au.zeus.jdk.authorization.guards.SerialObjectPermission
              "java.rmi.MarshalledObject";
    permission au.zeus.jdk.authorization.guards.SerialObjectPermission
              "java.util.Properties";

    // EXPLICITLY NOT GRANTED:
    //   NativeInvocationPermission — Phoenix has no native library needs
    //   SocketPermission "* connect" — Phoenix only talks to loopback
    //   ActivationPermission "registerGroup" — Phoenix is the registrar, not a caller
    //   AllPermission — Phoenix must not hold AllPermission
};
```

**Why Phoenix must not hold `AllPermission`:** A Phoenix process running with
`AllPermission` is equivalent to running as root from the security model's perspective.
If Phoenix is exploited, `AllPermission` means the attacker immediately gains all JVM
privileges.  A minimal policy limits the blast radius to exactly the permissions listed.

---

## Analysis: SerialObjectPermission Requirements for Phoenix and Group JVMs

### Background

DirtyChai's `SerialObjectPermission` is checked during `ObjectInputStream`
deserialisation.  The permission name is the fully-qualified class name of the
class being deserialised.

**Implemented scope (full coverage):** The check fires for every class resolved by
`ObjectInputStream`, not only those that have a custom `readObject` method.  Holding
`SerialObjectPermission` for a class is required before that class can be reconstructed
from any Java serialization stream, regardless of whether it uses default or custom
serialization.

The check is placed in `ObjectInputStream.readOrdinaryObject()`, immediately after the
class descriptor is resolved and before any object construction begins:

```java
// ObjectInputStream.java (DirtyChai modification — current)
private Object readOrdinaryObject(boolean unshared) throws IOException {
    ...
    new SerialObjectPermission(cl.getName()).checkGuard(null);
    //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    //  SerialObjectPermission(className).checkGuard(null)
    //  fires here, before any readObject or default deserialization
    ...
}
```

This covers all `Serializable` classes — those relying on default serialization and those
with a custom `readObject` — because the check runs before any deserialization path
diverges.

### Activation Classes That Require SerialObjectPermission

The following classes are part of the JGDMS activation serialisation path.
All of them have custom `readObject` implementations and therefore require
`SerialObjectPermission` under the current implementation:

| Class | Why it needs SerialObjectPermission |
|-------|-------------------------------------|
| `java.rmi.activation.ActivationDesc` | Custom `readObject` validates fields |
| `java.rmi.activation.ActivationGroupDesc` | Custom `readObject` validates policy/codebase |
| `java.rmi.activation.ActivationGroupDesc$CommandEnvironment` | Custom `readObject` validates JVM args list |
| `java.rmi.activation.ActivationID` | Custom `readObject` validates UID and activator ref |
| `java.rmi.activation.ActivationGroupID` | Custom `readObject` validates UID and system ref |
| `java.rmi.MarshalledObject` | Custom `readObject` reads serialised byte array |

With full-coverage enforcement now in place, all other `Serializable` classes that cross a
standard `ObjectInputStream` path also need explicit grants — including classes that
rely on default serialization.  Use
`SecurityPolicyWriter` to scan service JARs and generate the required grants.

### Where SerialObjectPermission Must Be Granted

#### Phoenix Daemon

Phoenix reads its persistence log at startup and when recovering from a crash.  The log
contains serialised `ActivationDesc` and `ActivationGroupDesc` objects.  Phoenix's
policy must grant `SerialObjectPermission` for all the classes in the table above.

Failure to grant these permissions causes Phoenix to throw a `SecurityException` during
log replay, which prevents all registered services from being re-activated after a
restart.

#### Group JVMs

Group JVMs do not typically read the Phoenix persistence log.  However, they do receive
`ActivationID` and `MarshalledObject` over the Phoenix↔group loopback RMI channel.
JERI's `AtomicMarshalInputStream` (when used) bypasses standard `ObjectInputStream`
entirely; but if a group JVM uses standard RMI unmarshalling for Phoenix communication,
it needs `SerialObjectPermission` for `ActivationID` and `MarshalledObject`.

The JGDMS recommendation is that group JVMs use `AtomicMarshalInputStream` exclusively.
If this is correctly configured, the group JVM policy does **not** need
`SerialObjectPermission` for Phoenix wire objects.

#### Service Implementations Inside Group JVMs

Service implementations may deserialise their own domain objects.  Each deserialised
class needs `SerialObjectPermission` granted to the service's codebase:

```
// Group JVM policy — service-specific SerialObjectPermission grants
grant CodeBase "file:/path/to/my-service.jar"
      signedBy "service-cert" {

    // Service's own serialisable domain objects
    permission au.zeus.jdk.authorization.guards.SerialObjectPermission
              "com.example.service.DomainObject";
    permission au.zeus.jdk.authorization.guards.SerialObjectPermission
              "com.example.service.RequestRecord";
    // Enumerate all Serializable classes in this service once full-coverage
    // fix lands; SecurityPolicyWriter can generate these grants automatically.
};
```

The `SecurityPolicyWriter` tool can generate these grants automatically by scanning
the service JAR for `Serializable` classes.

### SerialObjectPermission as a Defence Against Gadget Chains

A serialisation gadget chain requires that at least one class in the chain has a
custom `readObject` that triggers a dangerous side-effect (arbitrary code execution,
SSRF, file write, etc.).  By requiring an explicit `SerialObjectPermission` grant for
every class reaching the deserialisation path, DirtyChai ensures that:

1. A service policy that does not grant `SerialObjectPermission "com.sun.jndi.*"` will
   throw `SecurityException` before the JNDI gadget's `readObject` fires.
2. A dependency JAR that unexpectedly ships a gadget class cannot be weaponised unless
   the administrator explicitly grants `SerialObjectPermission` for that class.
3. Once the full-coverage fix lands, even gadget classes that use only default
   serialization (previously unguarded) will require an explicit grant.

This is a defence-in-depth supplement to the `ObjectInputFilter` (serial filter), not a
replacement.  Both should be configured: the serial filter enforces an allowlist of
deserialised class names; `SerialObjectPermission` enforces an allowlist of classes
that may be reconstructed from a stream.

---

## Analysis: LoadClassPermission and Codebase Loading During Activation

### How LoadClassPermission Is Enforced

DirtyChai modifies `SecureClassLoader.getProtectionDomain()` to check
`LoadClassPermission` before caching a new `ProtectionDomain`:

```java
// SecureClassLoader.java (DirtyChai modification)
SecurityManager sm = System.getSecurityManager();
if (sm != null) {
    sm.checkPermission(LOAD_CLASS_ALLOW,
            AccessControlContext.build(new ProtectionDomain[]{pd}));
    //                                 ^^
    //                                 AccessControlContext contains ONLY the
    //                                 new class's own ProtectionDomain
}
```

The critical detail is the `AccessControlContext` used for the check: it contains
**only the ProtectionDomain of the class being loaded**, not the calling stack.  This
means the policy must grant `LoadClassPermission` to the `CodeSource` of the JAR that
contains the class — not to the caller that triggered the class load.

**Consequence:** Every JAR codebase from which classes are loaded under a DirtyChai
SecurityManager must have an explicit `LoadClassPermission` grant in the active policy,
or class loading will fail with `AccessControlException`.

### LoadClassPermission in the Activation Context

When Phoenix forks a group JVM and the group JVM starts loading service classes from the
codebase URL, the loading path is:

```
Group JVM startup
    │
    ├─ Bootstrap classloader loads java.base (never goes through SecureClassLoader)
    │
    ├─ System classloader (AppClassLoader extends URLClassLoader extends SecureClassLoader)
    │       loads the JGDMS runtime JARs from the classpath
    │       → each JAR codebase needs LoadClassPermission in the group policy
    │
    └─ JGDMS codebase classloader (URLClassLoader extends SecureClassLoader)
            loads the service JAR from the ActivationGroupDesc codebase URL
            → service JAR codebase needs LoadClassPermission in the group policy
```

The group JVM policy must therefore grant `LoadClassPermission` to at minimum:

1. Every JAR on the group JVM's classpath that is not in `java.base` (i.e., everything
   loaded by `AppClassLoader`).
2. The service JAR loaded from the JGDMS codebase URL.
3. Any transitive dependency JARs loaded from codebase URLs.

A wildcard grant covering the JGDMS distribution directory is the minimal practical
configuration:

```
// Group JVM policy — LoadClassPermission for codebase loading
grant CodeBase "file:/opt/jgdms/-" {
    permission au.zeus.jdk.authorization.guards.LoadClassPermission;
};

grant CodeBase "file:/opt/services/my-service/-" {
    permission au.zeus.jdk.authorization.guards.LoadClassPermission;
};
```

**Do not use a universal `LoadClassPermission` grant** (i.e., do not grant it to all
codebases with `grant { ... }`).  The purpose of `LoadClassPermission` is to prevent
untrusted JARs from being loaded at all.  A universal grant defeats this purpose.

### The Relationship Between LoadClassPermission and the Codebase URL

The JGDMS codebase URL is specified in the `ActivationGroupDesc`.  If an attacker can
register a malicious `ActivationGroupDesc` with a codebase URL pointing to an attacker-
controlled JAR, that JAR would be loaded into the group JVM.  The two guards against
this are:

1. `ActivationPermission "registerGroup"` — prevents the attacker from registering the
   malicious descriptor in the first place (see Phoenix hardening section above).

2. `LoadClassPermission` — if the attacker somehow bypasses the registration guard, the
   attacker's JAR would still need `LoadClassPermission` in the group's policy.  Since
   the group's policy is controlled by the administrator, the attacker's codebase URL
   will not be in the policy and class loading will fail.

These two guards are complementary and both are necessary.

### Interaction with URI Validation in ConcurrentPolicyFile

DirtyChai's `ConcurrentPolicyFile` validates all `CodeSource` URLs through RFC 3986 URI
parsing (`Uri.java`).  This validation fires when the policy file is loaded and when a
`ProtectionDomain` is matched against grants.

If a malicious codebase URL contains path traversal sequences (e.g.,
`file:/opt/jgdms/../../../etc/evil.jar`), the URI validation will either:
- Normalise the path (removing `..` segments), resulting in a path that does not match
  the policy grant for `/opt/jgdms/-`, or
- Reject the URL entirely with a `URISyntaxException`, causing `getCodeSource()` to
  return `null` (fail-secure).

Either outcome means the class cannot gain permissions beyond the empty set, regardless
of what the policy file says.

---

## Analysis: ActivationGroupDesc JVM Argument Injection Attack Surface

### The Attack

An `ActivationGroupDesc` carries three JVM-argument mechanisms:

| Mechanism | API | Example Dangerous Value |
|-----------|-----|------------------------|
| Java property overrides | `CommandEnvironment.getCommandOptions()` | `-Djava.security.manager=com.attacker.EvilSM` |
| JVM flags | Same `getCommandOptions()` list | `-agentlib:evil` |
| Environment variables | `ActivationGroupDesc.getPropertyOverrides()` (as `Properties`) | `JAVA_TOOL_OPTIONS=-Djava.security.manager=...` |

If a caller who holds `ActivationPermission "registerGroup"` submits a crafted
`ActivationGroupDesc`, Phoenix will pass the contents directly to `Runtime.exec()` when
forking the group JVM.

### Analysis of the Guard

`ActivationPermission "registerGroup"` is the only guard provided by the activation
framework.  It controls *who* can call `ActivationSystem.registerGroup()`, but it does
not validate the *contents* of the `ActivationGroupDesc` after the call is authorised.

This means that **the `registerGroup` grant is transitive**: any tool or service that
holds `ActivationPermission "registerGroup"` and accepts externally-supplied group
descriptors inherits the ability to inject arbitrary JVM arguments.  A vulnerable admin
tool that passes user input to `registerGroup` is itself an injection vector.

### Mitigations

#### Layer 1: Minimal Grant of ActivationPermission "registerGroup"

Grant `ActivationPermission "registerGroup"` to as few codebases as possible.  Ideally,
only a dedicated administrative command-line tool (signed JAR, trusted certificate) holds
this permission.  No service implementation, no library, and no Phoenix plugin should
hold it.

#### Layer 2: Phoenix-Side Content Validation

Phoenix should validate the `CommandEnvironment.getCommandOptions()` list against a
whitelist of permitted JVM flags before constructing the `exec()` call.  The validation
rules are:

| Flag Pattern | Decision |
|---|---|
| `-Djava.security.manager=au.zeus.jdk.authorization.sm.*` | Allow (DirtyChai SM only) |
| `-Djava.security.policy=/etc/activation/groups/*.policy` | Allow (controlled directory only) |
| `-Xmx[0-9]+[kmgKMG]` | Allow (heap sizing only) |
| `-agentlib:*` | **Reject unconditionally** |
| `-agentpath:*` | **Reject unconditionally** |
| `-javaagent:*` | **Reject unconditionally** |
| `-Djava.security.manager=*` where `*` is not a DirtyChai SM | **Reject** |
| `-Djava.security.policy=*` where `*` is not under the controlled directory | **Reject** |
| Any other flag not in the whitelist | **Reject** |

This validation happens inside Phoenix, which runs under a minimal DirtyChai policy.
Because Phoenix does not hold `ActivationPermission "registerGroup"` itself, it cannot
register new groups; it can only validate and fork the groups already registered.

#### Layer 3: OS-Level Argument Sanitisation

The Phoenix startup wrapper (shell script or equivalent) can log the exact `exec()` call
before it is made, providing an audit trail.  A syslog or centralized logging system
receiving this audit trail gives an operator visibility into every group fork.

#### Layer 4: Policy File Path Restriction

The policy path in a `ActivationGroupDesc` should be validated against an allowed prefix
before being passed to `exec()`.  Phoenix running under a DirtyChai policy that only
grants `java.io.FilePermission "/etc/activation/groups/-" "read"` can only read policy
files from that directory.  If the attacker supplies a path outside that directory,
Phoenix's own SecurityManager will prevent the group JVM from reading the attacker's
policy even if the path validation is bypassed.

This is a defence-in-depth layer: Phoenix's `FilePermission` grant limits the effect of
a path-traversal attack on the policy argument.

---

## Recommended DirtyChai + JGDMS Activation Policy Configuration

This section provides a concrete, worked policy configuration for a minimal Phoenix
deployment.  All paths, class names, and certificate aliases must be adapted to the
specific deployment.

### Overview of Policy Files

| Process | Policy file | SecurityManager |
|---------|-------------|-----------------|
| Phoenix daemon | `/etc/activation/phoenix.policy` | `CombinerSecurityManager` |
| Group JVM A (service-a) | `/etc/activation/groups/service-a.policy` | `CombinerSecurityManager` |
| Admin tool | Inherits JVM policy | `CombinerSecurityManager` |

### Phoenix Daemon Policy (`/etc/activation/phoenix.policy`)

```
// DirtyChai policy for the Phoenix activation daemon.
// Phoenix is a high-value target: policy is deliberately minimal.

// Java SE permissions that Phoenix needs from the platform
grant CodeBase "jrt:/java.rmi/*" {
    permission java.net.SocketPermission "localhost:*", "listen,accept,connect,resolve";
};

// Phoenix implementation code
grant CodeBase "file:/opt/jgdms/jgdms-phoenix.jar"
      signedBy "jgdms-cert" {

    // Load JGDMS classes from the distribution directory
    permission au.zeus.jdk.authorization.guards.LoadClassPermission;

    // Fork group JVMs
    permission java.lang.RuntimePermission "exec";

    // Policy files for group JVMs (read-only access to controlled directory)
    permission java.io.FilePermission "/etc/activation/groups/-", "read";

    // Phoenix persistence log
    permission java.io.FilePermission "/var/lib/phoenix/-", "read,write,delete";

    // Listen for activation requests on fixed loopback port
    permission java.net.SocketPermission "localhost:1098", "listen,accept";

    // Communicate with group JVMs on loopback (ephemeral ports)
    permission java.net.SocketPermission "localhost:1024-65535", "connect,resolve";

    // Deserialise activation state from persistence log
    permission au.zeus.jdk.authorization.guards.SerialObjectPermission
              "java.rmi.activation.ActivationDesc";
    permission au.zeus.jdk.authorization.guards.SerialObjectPermission
              "java.rmi.activation.ActivationGroupDesc";
    permission au.zeus.jdk.authorization.guards.SerialObjectPermission
              "java.rmi.activation.ActivationGroupDesc$CommandEnvironment";
    permission au.zeus.jdk.authorization.guards.SerialObjectPermission
              "java.rmi.activation.ActivationID";
    permission au.zeus.jdk.authorization.guards.SerialObjectPermission
              "java.rmi.activation.ActivationGroupID";
    permission au.zeus.jdk.authorization.guards.SerialObjectPermission
              "java.rmi.MarshalledObject";

    // Logging
    permission java.util.logging.LoggingPermission "control";
    permission java.io.FilePermission "/var/log/phoenix.log", "write";
};

// NOT GRANTED to Phoenix: NativeInvocationPermission, AllPermission,
// SocketPermission "* connect" (only loopback), ActivationPermission "registerGroup"
```

### Group JVM Policy (`/etc/activation/groups/service-a.policy`)

```
// DirtyChai policy for activation group JVM running service-a.
// One policy file per group; each group is a separate OS process.

// JGDMS runtime JARs loaded from application classpath
grant CodeBase "file:/opt/jgdms/-"
      signedBy "jgdms-cert" {
    permission au.zeus.jdk.authorization.guards.LoadClassPermission;
    // JGDMS runtime only needs network access for its own JERI transport
    permission java.net.SocketPermission "localhost:*", "listen,accept,connect,resolve";
};

// Service implementation JAR loaded from codebase URL
grant CodeBase "file:/opt/services/service-a.jar"
      signedBy "service-a-cert" {

    permission au.zeus.jdk.authorization.guards.LoadClassPermission;

    // Service-specific network access (adjust to actual service needs)
    permission java.net.SocketPermission "db.internal:5432", "connect,resolve";

    // Service-specific file access
    permission java.io.FilePermission "/var/data/service-a/-", "read,write";

    // Deserialise only known-good service domain classes
    permission au.zeus.jdk.authorization.guards.SerialObjectPermission
              "com.example.service.DomainObject";
    permission au.zeus.jdk.authorization.guards.SerialObjectPermission
              "com.example.service.RequestRecord";
    // Add one entry per class with a custom readObject in service-a.jar

    // Communicate with Phoenix (activation registration / heartbeat)
    permission java.rmi.activation.ActivationPermission "system";
};

// NOT GRANTED to group JVM:
//   ActivationPermission "registerGroup" — groups do not register new groups
//   NativeInvocationPermission — service has no native library needs
//   AllPermission — never grant this
//   SerialObjectPermission for gadget classes (e.g., com.sun.jndi.*)
```

### Admin Tool Policy

The admin tool that calls `ActivationSystem.registerGroup()` requires only:

```
grant CodeBase "file:/opt/tools/activation-admin.jar"
      signedBy "admin-cert" {

    permission au.zeus.jdk.authorization.guards.LoadClassPermission;

    // The only privileged activation action this tool needs
    permission java.rmi.activation.ActivationPermission "registerGroup";
    permission java.rmi.activation.ActivationPermission "registerObject";

    // Connect to Phoenix
    permission java.net.SocketPermission "activation-host:1098", "connect,resolve";
};
```

Granting `ActivationPermission "registerGroup"` to this tool means that if the admin
tool is compromised, an attacker could register malicious groups.  This is why the
admin tool must itself be tightly scoped, signed, and not accessible from the network.

### DirtyChai SecurityManager Startup for Each Process

Every process in the activation topology must start the DirtyChai SecurityManager via
the JVM property:

```
-Djava.security.manager=au.zeus.jdk.authorization.sm.CombinerSecurityManager
-Djava.security.policy=/path/to/process-specific.policy
--illegal-native-access=deny
```

`CombinerSecurityManager` is on the DirtyChai trusted whitelist (it is in the
`trustedSMClass()` method), so no stack inspection is performed when it is installed —
startup overhead is negligible.

The `--illegal-native-access=deny` flag adds a module-system layer that independently
blocks native access even if the SecurityManager is bypassed (defence-in-depth).

### Security Properties of the Complete Configuration

| Property | Achieved By |
|---|---|
| Phoenix cannot be influenced by group JVMs | Phoenix does not grant any group access to its persistence store or port 1098 |
| A compromised group JVM cannot register new groups | `ActivationPermission "registerGroup"` not granted to group JVMs |
| An attacker who reads a service's serialised data cannot inject gadget classes | `SerialObjectPermission` allowlist is per-service, enumerated, non-wildcard |
| An attacker who controls a codebase URL cannot load classes without policy approval | `LoadClassPermission` must be explicitly granted per-codebase |
| Native library loading is blocked in all group JVMs | `NativeInvocationPermission` not granted; `--illegal-native-access=deny` in effect |
| Phoenix crash does not affect the other groups | OS process isolation; each group is an independent process |
| A policy-file tampering attack is limited to the process whose file was changed | One policy file per process; file owned by that process's OS user |

---

## Analysis: `Runtime::exec` vs `ProcessBuilder` — Secure Process Management for Phoenix

### The Problem with `Runtime.exec()`

Phoenix currently uses `Runtime.exec()` (or an equivalent OS API) to fork group JVMs.
There are two overload families:

| Overload | Argument Parsing | Environment | Working Directory |
|----------|-----------------|-------------|-------------------|
| `Runtime.exec(String cmd)` | Tokenises at whitespace; platform-dependent on some JVMs | Inherits parent | Inherits parent |
| `Runtime.exec(String[] cmdarray)` | Treats each element as a distinct argument token | Inherits parent | Inherits parent |
| `Runtime.exec(String[], String[] envp, File dir)` | Distinct tokens | Caller-supplied array | Caller-supplied |

**Why the single-String overload is dangerous:**  The `Runtime.exec(String)` overload
tokenises its argument at whitespace boundaries.  This is subtly different from shell
tokenisation (no glob expansion, no quote handling), but it remains ambiguous: any
whitespace in a path or argument — for example a policy file path containing a space —
silently produces extra tokens, changing the meaning of the command.  Developers who
write `Runtime.exec(buildCommandString(...))` with user-influenced input routinely
produce argument-injection bugs even without a shell being involved.

**Why all `Runtime.exec()` overloads share the same critical weakness:**  Every
`Runtime.exec()` overload that does not accept an explicit `envp` array **inherits the
parent process's environment**.  This exposes a class of injection attack that is
entirely separate from argument injection and that the existing `ActivationGroupDesc`
content-validation layers do not address.

### The Environment Variable Injection Vector

The JVM honours several environment variables that it reads at startup to modify its
own argument list.  An attacker who can set these variables in the process environment
that Phoenix inherits — or in the group JVM's inherited environment — can inject
arbitrary JVM arguments without touching `ActivationGroupDesc` at all:

| Variable | Effect | Scope |
|----------|--------|-------|
| `JAVA_TOOL_OPTIONS` | JVM argument list prepended at startup | All JDK implementations |
| `_JAVA_OPTIONS` | JVM argument list prepended/appended (HotSpot extension) | HotSpot only |
| `JDK_JAVA_OPTIONS` | JVM argument list prepended (Java 9+, replaces `_JAVA_OPTIONS`) | OpenJDK / DirtyChai |
| `CLASSPATH` | Modifies the application classpath | All JDK implementations |
| `JAVA_HOME` | Redirects to a different JVM binary | Launcher scripts |

**Attack scenario — same-user compromise:**

If any process running as the same OS user as Phoenix is compromised, that process can
set `JAVA_TOOL_OPTIONS=-javaagent:/tmp/evil.jar` in the shared environment (via
`/proc/self/environ` tricks on Linux, or `putenv()` in a JNI agent).  When Phoenix
subsequently calls `Runtime.exec()` with an inherited environment, the group JVM
starts with the attacker's agent injected — bypassing all `ActivationGroupDesc`
whitelist validation.

**Why this is not covered by the existing mitigation layers:**

The "Layer 2: Phoenix-Side Content Validation" section describes filtering the
`CommandEnvironment.getCommandOptions()` list from the `ActivationGroupDesc`.  That
filtering acts on the **command-line arguments** that Phoenix explicitly builds.  It
has no visibility into the **inherited environment variables** that the JVM launcher
reads independently of the command line.

### `ProcessBuilder` — The Direct Replacement

`ProcessBuilder` (introduced in Java 5) provides all of the safety properties that
`Runtime.exec()` lacks:

| Property | `Runtime.exec(String)` | `Runtime.exec(String[])` | `ProcessBuilder(List<String>)` |
|----------|------------------------|--------------------------|-------------------------------|
| Argument tokenisation ambiguity | Yes — whitespace split | No | No — each List element is one token |
| Explicit environment control | No | Partial (`envp` array) | Yes — mutable `Map<String,String>` |
| Ability to clear inherited environment | No | No (empty `envp` means inherit) | Yes — `environment().clear()` |
| I/O stream control | Limited | Limited | Full — `redirectInput/Output/Error()` |
| Working directory control | No | Yes (3-arg overload) | Yes — `directory()` |
| Cross-platform consistency | Varies by OS | Better | Best |
| Readable, auditable code | Low | Medium | High |

### ProcessBuilder Security Hardening Pattern for Phoenix

The following describes the security properties a human implementer should achieve
when replacing `Runtime.exec()` with `ProcessBuilder` in Phoenix.  All code below
is illustrative of the required design; the actual implementation must be
human-written per the OpenJDK Interim Policy on Generative AI.

**Step 1 — Build the command from a validated List, not a String:**

Rather than concatenating a command string, build the argument list as a
`List<String>` where each element is a distinct, validated token.  This eliminates
whitespace tokenisation ambiguity entirely.

The whitelist validation from the "ActivationGroupDesc JVM Argument Injection"
section should be applied to each element of the list **before** it is passed to
`ProcessBuilder`, so that the validated list is the only input to the builder.

**Step 2 — Clear the environment, then add back only what is required:**

```
ProcessBuilder pb = new ProcessBuilder(validatedCommandList);

// Start with an empty environment.
pb.environment().clear();

// Add only the variables the group JVM needs.
pb.environment().put("PATH", "/usr/lib/jvm/dirtychai-24/bin:/usr/bin:/bin");
pb.environment().put("LANG", "en_US.UTF-8");
pb.environment().put("HOME", groupWorkDir.getAbsolutePath());

// Defensively remove injection vectors even after clear(),
// in case clear() is skipped in a future maintenance change.
pb.environment().remove("JAVA_TOOL_OPTIONS");
pb.environment().remove("_JAVA_OPTIONS");
pb.environment().remove("JDK_JAVA_OPTIONS");
pb.environment().remove("CLASSPATH");
pb.environment().remove("JAVA_HOME");
```

`clear()` is the primary defence.  The explicit `remove()` calls are a second line
of defence against accidental reintroduction of these variables during maintenance.

**Step 3 — Redirect I/O to prevent file descriptor leakage:**

Phoenix's own stdin, stdout, and stderr file descriptors should not be inherited by
group JVMs.  A group JVM that inherits Phoenix's stdin can block waiting for input
that Phoenix never provides; a group JVM that inherits Phoenix's stdout can pollute
Phoenix's log stream.

```
pb.redirectInput(ProcessBuilder.Redirect.from(new File("/dev/null")));
pb.redirectOutput(groupLogFile);
pb.redirectErrorStream(true);  // merge stderr into stdout for unified logging
```

**Step 4 — Set an explicit working directory:**

```
pb.directory(groupWorkDirectory);
```

This ensures that relative paths in the group JVM's code resolve predictably and
cannot traverse into directories that the group JVM's OS user does not own.

### Java 9+ `ProcessHandle` for Lifecycle Management

`Runtime.exec()` returns a `Process` object with limited lifecycle visibility:
polling `process.isAlive()` is the only way to detect termination.  In contrast,
`ProcessBuilder.start()` also returns a `Process`, and Java 9 extended `Process`
with `toHandle()` which provides the richer `ProcessHandle` API:

| `ProcessHandle` Feature | Phoenix Benefit |
|------------------------|-----------------|
| `handle.onExit()` — `CompletableFuture<ProcessHandle>` | Asynchronous crash detection without polling; enables the activation-storm backoff described in M-P5 |
| `handle.info().startInstant()` | Audit log timestamp for group JVM starts |
| `handle.info().totalCpuDuration()` | CPU-time monitoring; detect runaway group JVMs |
| `handle.descendants()` | Enumerate child processes spawned by the group JVM (e.g., if the service itself calls `exec()`) |
| `handle.destroy()` / `handle.destroyForcibly()` | Graceful SIGTERM then SIGKILL for group shutdown; replaces `process.destroy()` with explicit escalation |
| `handle.pid()` | PID for OS-level audit log correlation |

The `onExit()` callback directly enables the activation-storm limiting strategy
(M-P5 above): Phoenix increments a per-group crash counter in the callback and
marks the group `INACTIVE` after *N* consecutive crashes, without requiring a
background polling thread.

### OS-Level Resource Controls for Group JVMs

`ProcessBuilder` controls *what process is launched* and *what it inherits*; it
does not control *how many resources* that process may consume.  OS-level controls
are the correct tool for resource limits:

#### Linux cgroups v2

cgroups v2 allows Phoenix (or a privileged wrapper) to assign each group JVM to a
dedicated cgroup with explicit resource limits before the JVM starts.  The
recommended approach is to use `systemd-run` as the launcher, which applies a
transient systemd unit with cgroup accounting:

```
systemd-run --scope \
    --property=MemoryMax=512M \
    --property=CPUQuota=50% \
    --property=TasksMax=64 \
    -- java -Djava.security.manager=... -jar service-a.jar
```

When Phoenix launches the group JVM, it calls `systemd-run` (via `ProcessBuilder`)
as a thin wrapper around the actual `java` binary.  The cgroup created by systemd
automatically limits the group JVM and all processes it forks to the declared
resource envelope.

**Effect:** A `createVirtualThread` permission bypass or a thread-bomb attack inside
the group JVM is bounded by the cgroup `TasksMax` and `CPUQuota` limits.  The
attacker cannot exhaust the host OS thread table or saturate all CPU cores.

#### seccomp-BPF Syscall Filtering

A seccomp profile applied to the group JVM's process restricts which Linux system
calls the JVM may make.  A group JVM running a network service does not need
`fork(2)`, `execve(2)`, `ptrace(2)`, or `mount(2)`.  Denying these at the OS level
provides a backstop that survives a complete JVM security model bypass:

| Denied Syscall | Attack It Prevents |
|----------------|-------------------|
| `execve` | Group JVM cannot spawn new processes (complements `RuntimePermission("exec")` denial) |
| `fork` / `vfork` | Group JVM cannot create child processes |
| `ptrace` | Group JVM cannot attach a debugger to other processes |
| `mount` | Group JVM cannot remount the filesystem |
| `setuid` / `setgid` | Group JVM cannot change its OS identity |
| `socket` with `AF_NETLINK` | Group JVM cannot manipulate network interfaces |

Docker and Podman apply a default seccomp profile that already denies many of these
calls.  For a non-container deployment, `libseccomp` or a systemd `SystemCallFilter`
directive can apply the same restrictions.

#### Linux Network Namespaces

Each group JVM can be placed in its own network namespace, giving it a private
loopback interface and a single controlled external interface.  Traffic rules on that
interface are enforced by the OS kernel, not by the JVM SecurityManager.  A
compromised SecurityManager cannot bypass a kernel netfilter rule.

The deployment model is:

```
Host network namespace
│
├─ Phoenix daemon (loopback + one NIC shared with group JVMs via veth pairs)
│
└─ Group JVM A network namespace
       ├─ lo (loopback, for intra-JVM connections)
       └─ veth0 ↔ veth1 (virtual Ethernet pair to host bridge)
              Egress iptables: only allow dport 5432 (database)
```

This means the group JVM can only reach its declared upstream services, regardless
of what `SocketPermission` its DirtyChai policy happens to grant.

### Architectural Alternatives to `Runtime.exec()` for Process Management

The Phoenix activation model is one specific solution to the process isolation
problem.  Depending on the operational environment, alternative architectures may be
more suitable:

#### Container-Per-Service (Docker / Podman)

Each service runs in its own container, with the container runtime (Docker daemon,
`podman`, `containerd`) acting as the "activation manager" instead of Phoenix.

| Property | JGDMS Phoenix | Container-Per-Service |
|----------|--------------|----------------------|
| Process isolation | Yes — separate OS process | Yes — separate OS process + namespace + cgroup |
| SecurityManager control | Yes — DirtyChai per group | Yes — DirtyChai in container JVM |
| Crash recovery | Phoenix re-activates on client call | Container restart policy (e.g., `--restart=on-failure:3`) |
| Process launch API | `Runtime.exec()` / `ProcessBuilder` | Container runtime API / OCI |
| JVM argument injection surface | `ActivationGroupDesc` command options | Container image entrypoint + env vars |
| Resource limits | OS-level (manual cgroup setup) | Built-in per container (cgroup delegation) |
| Network isolation | Manual (namespaces) | Built-in (bridge network per compose service) |
| Audit | Custom Phoenix log | Container runtime event log (`docker events`) |

The trade-off is operational complexity: containers require a runtime daemon
(Docker/Podman) but provide richer resource management, image signing, and network
isolation out of the box.  JGDMS Phoenix provides richer Java-level lifecycle
management (activation on demand, `ActivationID`-based recovery) without requiring a
container daemon.

**Combining both:** JGDMS Phoenix can run *inside* a container alongside its group
JVMs, gaining the container's cgroup/namespace isolation while retaining Phoenix's
activation-on-demand semantics.

#### systemd Socket Activation

systemd supports *socket activation*: the OS holds the listening socket and starts
the service process only when an incoming connection arrives.  This is directly
analogous to the Java Activation Framework's on-demand instantiation model, but
implemented at the OS level.

For a JGDMS service, this means:

1. A systemd socket unit holds the JERI transport port.
2. On the first incoming connection, systemd starts the group JVM service unit.
3. The group JVM receives the pre-bound socket via file descriptor passing
   (`SD_LISTEN_FDS`).
4. If the group JVM crashes, systemd restarts it on the next connection (subject to
   restart rate limits).

This eliminates the Phoenix daemon as a single point of failure: the OS init system
manages process lifecycle.  The trade-off is the loss of Phoenix's
`ActivationGroupDesc`-based configuration model and its cross-host failover
capability.

#### GraalVM Isolates (In-Process, Separate Heap)

GraalVM Isolates allow multiple isolated heap regions within a single OS process.
Each isolate has its own garbage collector and cannot directly share object
references with other isolates.  Data crossing an isolate boundary must be
explicitly marshalled (similar to FFM memory segments).

| Property | JGDMS Activation (OS process) | GraalVM Isolates (in-process) |
|----------|------------------------------|-------------------------------|
| Memory isolation | Full — separate address space | Partial — separate heap, shared native memory |
| Crash isolation | Full — JVM crash terminates only that process | Partial — isolate crash may destabilise host JVM |
| SecurityManager | Independent per process | Shared JVM SecurityManager (not per-isolate) |
| Start-up latency | High — JVM startup | Low — isolate creation |
| Resource limits | OS cgroups | JVM-level; no per-isolate cgroup |
| Compatibility | Full JVM compatibility | Requires GraalVM; limited dynamic class loading |
| `Runtime.exec()` equivalent | Required | Not needed |

GraalVM Isolates are a better fit for *same-trust-level* parallelism (e.g., running
multiple requests in parallel with heap isolation) than for *different-trust-level*
service isolation (e.g., an untrusted service that might crash or exhaust resources).
The lack of per-isolate SecurityManager means DirtyChai cannot enforce separate
least-privilege policies across isolates.

For JGDMS use cases involving different-trust-level services, OS process isolation
(via Phoenix or containers) remains the correct architecture.

### Recommendation Summary

The following changes are recommended to make Phoenix's process management more
secure.  All code changes are human implementation tasks.

| Task | Priority | Addresses |
|------|----------|-----------|
| Replace `Runtime.exec()` with `ProcessBuilder(List<String>)` | **High** | Argument tokenisation ambiguity |
| Clear inherited environment and remove injection variables (`JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`, `CLASSPATH`) | **Critical** | Environment variable injection vector |
| Redirect group JVM stdin to `/dev/null`, stdout/stderr to log file | **High** | File descriptor leakage |
| Set explicit working directory | **Medium** | Relative path ambiguity |
| Use `ProcessHandle.onExit()` for crash detection | **High** | Activation-storm backoff (M-P5) |
| Apply systemd `MemoryMax`, `CPUQuota`, `TasksMax` per group JVM | **High** | Resource exhaustion |
| Apply seccomp profile denying `execve`, `fork`, `ptrace` to group JVMs | **Medium** | Syscall-level escape prevention |
| Place each group JVM in its own network namespace | **Medium** | Unrestricted outbound connections |

The environment-variable injection fix (`environment().clear()` + targeted `remove()`
calls) is the highest-priority item because it is the only attack vector that
bypasses all of the existing `ActivationGroupDesc` whitelist validation layers
described earlier in this document.

---

## Analysis: JGDMS TlsRMIServerSocketFactory vs DirtyChai SslRMIServerSocketFactory

### Summary of Comparison

Two `RMIServerSocketFactory` implementations are relevant to DirtyChai + JGDMS deployments:

| Property | DirtyChai `SslRMIServerSocketFactory` (`javax.rmi.ssl`) | JGDMS `TlsRMIServerSocketFactory` (`au.net.zeus.rmi.tls`) |
|---|---|---|
| Origin | JDK standard class (Oracle, Java 1.5) | JGDMS custom class (Apache 2.0) |
| JAAS `Subject` integration | None | Full: credentials sourced from `Subject` via `Subject.getSubject(AccessController.getContext())` |
| `AuthenticationPermission` enforcement | None | Yes, via `ServerSubjectKeyManager.getPrivateCredential()` checked against the calling `Subject` |
| Mutual TLS enforcement | Optional (`needClientAuth` parameter) | Always on (hardcoded `needClientAuth=true`) |
| TLS credential rotation | Static singleton `SSLSocketFactory`; no session invalidation | Per-`Subject` `SSLContext` cached in a weak/soft map; sessions invalidated when credentials are removed or expire |
| TLS version | Configurable at construction time | `TLSv1.3` by default (system-property override) |
| `equals()` / `hashCode()` | Implemented correctly (required by RMI spec for stub comparison) | **Missing** — correctness gap |
| `Serializable` | Implicitly yes | **Missing** — correctness gap |

**Architectural verdict:** For DirtyChai + JGDMS deployments, the JGDMS
`TlsRMIServerSocketFactory` is the architecturally superior choice because it
is the only factory that connects TLS identity to a JAAS `Subject` and, through
that Subject, to principal-keyed policy grants enforced by the DirtyChai
`ConcurrentPolicyFile`.  The DirtyChai in-tree `SslRMIServerSocketFactory` has
no awareness of principals and produces no identity context that policy can
reason about.

The JGDMS factory has two correctness gaps that must be remedied by a human
implementor before it can be used reliably in production:

1. **Missing `equals()` / `hashCode()`** — Per the RMI specification, socket
   factories embedded in `RemoteRef` objects are compared by value during stub
   lookup and transport sharing.  Without these methods, two
   `TlsRMIServerSocketFactory` references that represent the same logical factory
   will not compare as equal, causing unnecessary transport channel multiplication
   or `SecurityException` during stub validation.
2. **Missing `Serializable`** — `RMIServerSocketFactory` instances are distributed
   to clients as part of the stub's `RemoteRef`.  A non-serializable factory
   prevents correct stub distribution and deserialization on the client side.

These gaps must be addressed before a production deployment.

### DirtyChai API Status: `Subject.getSubject` and `AccessController.getContext`

In standard OpenJDK 17+, both `Subject.getSubject(AccessControlContext)` and
`AccessController.getContext()` are marked deprecated-for-removal because their
semantics depend on the `SecurityManager` infrastructure that OpenJDK is
removing.

**In DirtyChai these methods are fully supported and are the preferred API.**
DirtyChai preserves and maintains the `SecurityManager`, `AccessController`, and
`Subject` infrastructure.  The `@SuppressWarnings("removal")` annotations
present in DirtyChai source files indicate intentional preservation, not
deprecated usage.

The DirtyChai `Subject.current()` method is implemented as:

```java
public static Subject current() {
    if (!SharedSecrets.getJavaLangAccess().allowSecurityManager()) {
        return SCOPED_SUBJECT.isBound() ? SCOPED_SUBJECT.get() : null;
    } else {
        return getSubject(AccessController.getContext());  // preferred path in DirtyChai
    }
}
```

When a `SecurityManager` is active (the DirtyChai deployment model),
`Subject.current()` is exactly equivalent to
`Subject.getSubject(AccessController.getContext())`.  Both idioms are correct
and supported.  JGDMS uses `Subject.getSubject(acc)` with an explicitly captured
`AccessControlContext`; this is the correct pattern when the context must be
captured at one point in time and consulted at another (e.g., capturing the
context at socket-creation time to identify which server Subject owns the socket).

### How DirtyChai Can Support Subject Propagation from JGDMS TlsRMIServerSocketFactory

#### The Propagation Problem

The JGDMS `TlsRMIServerSocketFactory` uses the server's `Subject` (captured at
`createServerSocket()` time) to select the private key used during the TLS
handshake.  After the handshake completes, the accepted `SSLSocket` has an
established `SSLSession` that holds the **peer's** (client's) authenticated
X.509 certificate chain.

Standard RMI's `TCPTransport.ConnectionHandler.run()` dispatches each incoming
connection with:

```java
AccessController.doPrivileged((PrivilegedAction<Void>)() -> {
    run0();
    return null;
}, NOPERMS_ACC);
```

`NOPERMS_ACC` is a no-permissions `AccessControlContext`.  This means the
connection handler thread — and therefore the service method invocation thread —
starts with an empty context that contains **no `Subject`** and **no
`SubjectDomainCombiner`**.  Consequently:

- `Subject.getSubject(AccessController.getContext())` returns `null` inside the
  service method.
- Policy grants keyed on `Principal "X500Principal CN=..."` never fire, even
  though the TLS handshake has already authenticated the client.

This is the "TLS subject propagation gap" identified as boundary 5 in the N-13
trust-boundary analysis earlier in this document.

#### The Propagation Mechanism

DirtyChai can close this gap by having `TCPTransport.ConnectionHandler` extract
the authenticated peer identity from the `SSLSession` and wrap the service
dispatch inside `Subject.doAsPrivileged`.  The required steps are:

**Step 1 — Extract the peer `Subject` after `accept()`.**

When `TlsRMIServerSocketFactory` is in use, `serverSocket.accept()` returns an
`SSLSocket` (the factory's `createServerSocket()` returns an `SSLServerSocket`
that wraps accepted sockets via `SSLSocketFactory.createSocket(..., autoClose=true)`
or directly returns `SSLServerSocket` sockets).  After `accept()` completes and
the TLS handshake has been performed, the peer's certificate chain is available:

```java
// Inside AcceptLoop.executeAcceptLoop() after socket = serverSocket.accept()
if (socket instanceof SSLSocket) {
    SSLSocket sslSocket = (SSLSocket) socket;
    SSLSession session = sslSocket.getSession();
    java.security.cert.Certificate[] peerCerts = session.getPeerCertificates();
    // peerCerts[0] is the peer's end-entity certificate
    // Build a read-only Subject containing the peer's X500Principal
    // and public credential CertPath for policy grant matching
}
```

The accepted socket can be tested with `instanceof SSLSocket` to detect
TLS-authenticated connections without any coupling to a specific factory
implementation.

**Step 2 — Construct a read-only `Subject` for the peer.**

A minimal peer `Subject` for policy-grant matching contains:

- The peer's `X500Principal` (from `peerCerts[0].getSubjectX500Principal()`),
  placed in the `Subject`'s principal set.
- Optionally the full `CertPath` as a public credential, matching the contract
  expected by JGDMS `FilterX509TrustManager` and JERI authentication logic.

The `Subject` must be made read-only before passing to `doAs`/`doAsPrivileged`
so that downstream code cannot extend it with additional principals.

**Step 3 — Dispatch the connection handler under the peer Subject.**

Replace the existing `NOPERMS_ACC` dispatch in `ConnectionHandler.run()` with a
`Subject.doAsPrivileged` call that installs a `SubjectDomainCombiner`:

```java
// Conceptual pattern — human implementation required
Subject peerSubject = extractPeerSubject(socket);
if (peerSubject != null) {
    Subject.doAsPrivileged(peerSubject,
        (PrivilegedAction<Void>) () -> { run0(); return null; },
        NOPERMS_ACC);
} else {
    // Non-TLS or anonymous connection — use existing path
    AccessController.doPrivileged(
        (PrivilegedAction<Void>) () -> { run0(); return null; },
        NOPERMS_ACC);
}
```

`Subject.doAsPrivileged` creates a new `AccessControlContext` that wraps
`NOPERMS_ACC` with a `SubjectDomainCombiner(peerSubject)`.  Throughout the
execution of `run0()` (and therefore throughout every `UnicastServerRef.dispatch()`
invocation on that connection), the peer Subject is retrievable via:

```java
Subject caller = Subject.getSubject(AccessController.getContext());
// caller.getPrincipals() contains the peer's X500Principal
```

And any policy grant of the form:

```
grant Principal javax.security.auth.x500.X500Principal "CN=MyClient, O=Example" {
    permission java.io.FilePermission "/data/myservice/-" "read";
};
```

will correctly apply to the service method invocation because the
`SubjectDomainCombiner` injects the principal into the `AccessControlContext`
intersection that `CombinerSecurityManager.checkPermission()` evaluates.

#### Integration with `CombinerSecurityManager`

`CombinerSecurityManager` intersects the `ProtectionDomain` permissions from
every frame on the call stack.  When the `SubjectDomainCombiner` is active, it
augments the `ProtectionDomain` array with domains seeded from the Subject's
principal set.  The combiner is applied by `AccessControlContext.optimize()` at
each `checkPermission()` call, so the security manager sees the full principal
context without any change to its own implementation.

No modification to `CombinerSecurityManager` is required.  The entire
propagation is accomplished by the `SubjectDomainCombiner` installed by
`Subject.doAsPrivileged` in the transport layer.

#### Integration with JGDMS `TlsRMIServerSocketFactory.createServerSocket()`

The JGDMS factory's `createServerSocket()` already calls:

```java
AccessControlContext acc = AccessController.getContext();
Subject subject = AccessController.doPrivileged(
    new PrivilegedAction<Subject>() {
        public Subject run() { return Subject.getSubject(acc); }
    }
);
SSLContext sslContext = Utilities.getServerSSLContextInfo(subject);
```

This pattern captures the **server's** Subject (the identity of the code that
called `exportObject`) and uses it for key selection during the TLS handshake.
The DirtyChai extension described above complements this by extracting the
**client's** Subject from the completed handshake result and binding it to the
dispatch thread.

The two subjects serve different roles:

| Subject | Source | Role |
|---|---|---|
| Server Subject | `Subject.getSubject(acc)` at `createServerSocket()` | Selects the server's private key for the TLS handshake |
| Peer (client) Subject | `SSLSession.getPeerCertificates()` after `accept()` | Bound to the dispatch thread via `SubjectDomainCombiner`; governs policy grants for the service method call |

#### Files Requiring Human Implementation

| File | Change |
|---|---|
| `src/java.rmi/share/classes/sun/rmi/transport/tcp/TCPTransport.java` | `ConnectionHandler.run()` — detect `SSLSocket`, extract peer certs, call `Subject.doAsPrivileged` |
| `src/java.rmi/share/classes/sun/rmi/transport/tcp/TCPTransport.java` | New private helper `extractPeerSubject(Socket)` — null-safe, returns null for non-TLS sockets |
| JGDMS `TlsRMIServerSocketFactory` | Add `equals()`, `hashCode()`, and `Serializable` to satisfy the `RMIServerSocketFactory` contract (see gaps above) |

#### Investigation Task Backlog

- [x] **TLS-SUBJECT-PROPAGATION (complete):** Implemented in `TCPTransport.ConnectionHandler` (commit `5e5682a8dbb1d3aa0a0838893646e43bfd150dc6`):
  - Extracts peer X.509 certificates from `SSLSession` after `accept()`
  - Constructs immutable read-only `Subject` with peer `X500Principal` (`new Subject(true, ...)`)
  - Handles `SSLPeerUnverifiedException` with graceful fallback to unauthenticated dispatch
  - Dispatches under `Subject.doAsPrivileged(..., null)` to enable principal-keyed policy grants
  - Verified behavior target: `Subject.getSubject(AccessController.getContext())` inside service methods returns the authenticated peer `Subject`
- [ ] **TLS-FACTORY-RMI-CONTRACT (high):** Add `equals()`, `hashCode()`, and `implements Serializable` to JGDMS `TlsRMIServerSocketFactory` to satisfy RMI stub-comparison and stub-distribution requirements.
- [ ] **TLS-FACTORY-TEST (medium):** Add a test that exports a remote object with `TlsRMIServerSocketFactory`, connects with `TlsRMIClientSocketFactory`, and asserts that the service method's calling `Subject` matches the client's X.509 certificate principal.

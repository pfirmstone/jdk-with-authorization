# Process Isolation in DirtyChai and JGDMS

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

---

## DirtyChai: SerialObjectPermission as the JDK-level Backstop for JGDMS Atomic Serialization — and Why Process Isolation Remains Essential

### SerialObjectPermission as Backstop

`au.zeus.jdk.authorization.guards.SerialObjectPermission` is a
`BasicPermission` whose name is the canonical class name of a serializable type.
It is checked at the entry to standard Java serialization and deserialization.

**What it does:**

- Forces policy authors to explicitly whitelist every class that may be
  serialized or deserialized via `ObjectInputStream` / `ObjectOutputStream`.
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
- It does not prevent a permitted class from executing malicious logic in its
  `readResolve()` or `readObject()` method.  For classes that implement these
  callbacks the behaviour of those callbacks is still the responsibility of the
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

#### 2. Side-channel attacks

Timing attacks, cache-flush attacks, and speculative-execution side channels
(Spectre, Meltdown class) operate below the Java security model.  A hostile
thread running in the same process can leak secrets from other threads via these
channels regardless of permission grants.

#### 3. JVM internals access

Despite module encapsulation and permission checks, the JVM exposes internal
state (e.g., via `sun.misc.Unsafe`, JNI, or JVMTI) that can be exploited by
native code or compromised JVM extensions to escape the security model entirely.

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
| Thread creation control | `createPlatformThread` / `createVirtualThread` | DirtyChai (proposed) |
| Permission enforcement | `SecurityManager` + `ConcurrentPolicyFile` | DirtyChai |
| Blast-radius containment | Isolated `ForkJoinPool` + deadline | JGDMS service layer |
| Memory isolation | Separate OS process | OS / GraalVM Espresso / container |
| Network isolation | Firewall / namespace | OS / container runtime |

> **Non-goal of DirtyChai**: Sandboxing untrusted code.  DirtyChai focuses on
> user *authorisation* — ensuring users have access only when using approved,
> policy-controlled code — and provides tooling to audit and limit the
> privileges requested by third-party code prior to deployment.  Developers
> needing untrusted-code sandboxing should consider GraalVM Espresso or Graal
> process isolation.

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

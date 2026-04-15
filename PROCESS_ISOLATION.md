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

#### Gate 1 — `NativeAccessPermission` via `Module.ensureNativeAccess()`

`Module.java` has been modified to call `NativeAccessPermission.checkGuard(null)`
at the top of `ensureNativeAccess()`, which is invoked by
`Reflection.ensureNativeAccess()` before every `@Restricted` method call.

```java
// Module.java — ensureNativeAccess() (DirtyChai modification)
void ensureNativeAccess(Class<?> owner, String methodName,
                        Class<?> currentClass, boolean jni) {
    new NativeAccessPermission(
            currentClass != null ? currentClass.getName() : "code",
            methodName).checkGuard(null);      // ← SM policy check fires here
    // ... module-flag check follows
}
```

`Permission.checkGuard(null)` calls `SecurityManager.checkPermission(this)` when
a SecurityManager is active.  The calling code's `ProtectionDomain` must have
`NativeAccessPermission` granted in the policy file, or a `SecurityException` is
thrown before any native call proceeds.

The `@Restricted` / FFM entry points that all flow through this gate include:

| API | Restricted Method |
|-----|-------------------|
| `System.load(String)` | `System::load` |
| `System.loadLibrary(String)` | `System::loadLibrary` |
| `Runtime.load(String)` | `Runtime::load` |
| `Runtime.loadLibrary(String)` | `Runtime::loadLibrary` |
| `Linker.downcallHandle(...)` | `Linker::downcallHandle` |
| `Linker.upcallStub(...)` | `Linker::upcallStub` |
| `SymbolLookup.libraryLookup(...)` | `SymbolLookup::libraryLookup` |
| `MemorySegment.reinterpret(...)` | `MemorySegment::reinterpret` |
| `AddressLayout.withTargetLayout(...)` | `AddressLayout::withTargetLayout` |

Every one of these is blocked for untrusted code unless the policy explicitly
grants `NativeAccessPermission` to that code's `ProtectionDomain`.

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

For `System.loadLibrary("foo")`:

```
System.loadLibrary("foo")
    │
    ├─1─ Reflection.ensureNativeAccess(caller, System.class, "loadLibrary", false)
    │        └─ Module.ensureNativeAccess(...)
    │               └─ NativeAccessPermission("callerClass","loadLibrary").checkGuard(null)
    │                       └─ SecurityManager.checkPermission(NativeAccessPermission)
    │                               ← GATE 1: SM policy check
    │
    └─2─ Runtime.loadLibrary0(fromClass, libname)
             └─ security.checkLink("foo")
                     └─ checkPermission(RuntimePermission("loadLibrary.foo"))
                             ← GATE 2: SM policy check
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

### The Residual Gap — Already-Loaded Native Code

The two loading gates fully protect against untrusted jars *loading new* native
libraries.  They do not protect against the following scenarios:

#### 1. Native code loaded before untrusted code runs

If a trusted class loaded `mylib.so` via `System.loadLibrary("mylib")` earlier
in the JVM session, that library is permanently registered in the class loader's
`NativeLibraries` instance.  Unloading a native library is not supported by
the JVM.  The library's native functions remain callable via JNI or FFM for
the rest of the JVM's lifetime.

**Implication:** Untrusted code that can persuade a trusted class to call a
native method on its behalf — a confused-deputy attack — can indirectly invoke
native functionality without itself holding `NativeAccessPermission`.

**Mitigation:** Use `AccessController.doPrivileged` with a restricted context
when trusted classes call native methods on behalf of caller-supplied inputs.
This is a design obligation for trusted library code, not something DirtyChai
can enforce automatically.

#### 2. JNI callbacks from within native code

Native code that has already been loaded by a trusted class can call back into
the JVM via the JNI `CallXxxMethod` family without any Java-side permission
check.  The JVM executes those calls in whatever thread is current, which may
not have the restricted `AccessControlContext` the Java caller intended.

**Mitigation:** `doPrivileged` with a limited context in the Java wrapper method,
combined with explicit input validation before any JNI call.  DirtyChai's
`SerialObjectPermission` guards the deserialization path; native method wrappers
must apply analogous input validation.

#### 3. JVMTI and JVM agents

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
| Untrusted jar calls `System.loadLibrary()` | `NativeAccessPermission` + `RuntimePermission("loadLibrary.*")` | **Blocked by DirtyChai** |
| Untrusted jar uses FFM `Linker.downcallHandle()` | `NativeAccessPermission("callerClass","downcallHandle")` | **Blocked by DirtyChai** |
| Untrusted jar uses `MemorySegment.reinterpret()` | `NativeAccessPermission("callerClass","reinterpret")` | **Blocked by DirtyChai** |
| Untrusted jar calls `SymbolLookup.libraryLookup()` | `NativeAccessPermission("callerClass","libraryLookup")` | **Blocked by DirtyChai** |
| Confused-deputy: trusted class calls native on behalf of untrusted caller | `doPrivileged` with restricted context (design requirement on trusted code) | **Not automated — requires design discipline** |
| Native code already loaded by trusted class | No Java-side gate (native code is already at OS level) | **Residual gap — use process isolation** |
| JVMTI / `-agentlib:` attached at startup | OS / JVM launch controls | **Out of scope for DirtyChai** |

---

## Implementation Plan: Native Code Isolation in DirtyChai

The `NativeAccessPermission` class and its integration into `Module.ensureNativeAccess()`
are already implemented.  The following tasks remain for a complete, policy-auditable
native isolation story.

### Task N-1 — Add `NativeAccessPermission` to the Default Deny Policy

**Priority:** High  
**Files:** `src/java.base/share/classes/au/zeus/jdk/authorization/policy/`
(default policy template) and any example policy files in the repository.

**Description:**  
The default policy should grant `NativeAccessPermission` only to named trusted
modules (e.g., `jrt:/java.base/*`, `jrt:/java.desktop/*`) and explicitly
withhold it from the unnamed module and from application classpath code.

**Policy pattern (human to implement):**

```
// Deny by default; grant only to bootstrap classes
grant codeBase "jrt:/java.base/*" {
    permission au.zeus.jdk.authorization.guards.NativeAccessPermission
        "*", "*";
};

grant codeBase "jrt:/java.desktop/*" {
    permission au.zeus.jdk.authorization.guards.NativeAccessPermission
        "*", "*";
};

// Do NOT grant NativeAccessPermission to application classpath or untrusted jars
```

---

### Task N-2 — Add `RuntimePermission("loadLibrary.*")` to the Default Deny Policy

**Priority:** High  
**Files:** Same as N-1.

**Description:**  
Pair the `NativeAccessPermission` deny with an explicit deny of
`RuntimePermission("loadLibrary.*")` for untrusted code.  Because
`SecurityManager.checkLink()` fires independently of `NativeAccessPermission`,
both must be denied to close the loading gate.

**Policy pattern (human to implement):**

```
// Deny loadLibrary to untrusted classpath code by omission
// (no RuntimePermission "loadLibrary.*" grant in untrusted code's grant block)

// Grant specific libraries to specific trusted code:
grant codeBase "file:/opt/myapp/lib/trusted.jar" {
    permission java.lang.RuntimePermission "loadLibrary.myspecificlib";
};
```

---

### Task N-3 — Extend `SecurityPolicyWriter` to Report `NativeAccessPermission` Grants

**Priority:** Medium  
**Files:** `src/java.base/share/classes/au/zeus/jdk/authorization/tool/SecurityPolicyWriter.java`

**Description:**  
`SecurityPolicyWriter` already enumerates `LoadClassPermission` and
`SerialObjectPermission` grants, making the serialization and class-loading
surfaces auditable.  The same tool should be extended to enumerate all
`NativeAccessPermission` grants observed during a test run, so that policy
authors can audit exactly which code attempted to use native or restricted APIs.

This is a human implementation task because it involves modifying `SecurityPolicyWriter.java`,
a production Java source file subject to the OpenJDK Interim Policy on
Generative AI.

---

### Task N-4 — Document `NativeAccessPermission` in `RuntimePermission.java`'s Permission Table

**Priority:** Medium  
**Files:** `src/java.base/share/classes/java/lang/RuntimePermission.java`

**Description:**  
Add a row to the JavaDoc permission table in `RuntimePermission.java` that
cross-references `NativeAccessPermission` so that users who look up
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
Document the pattern that trusted library code must follow when it calls native
methods on behalf of caller-supplied inputs:

```java
// Pattern: restrict the AccessControlContext before calling native code
// that uses caller-controlled inputs
AccessController.doPrivileged(
    () -> { nativeMethod(callerSuppliedInput); },
    restrictedContext   // built from the caller's context, not the trusted class's
);
```

Failing to do this creates a confused-deputy vulnerability where untrusted code
can exploit the trusted class's `NativeAccessPermission` to indirectly invoke
native functionality it could not invoke directly.

This guidance is for documentation files only and is therefore within scope for
this session.

### Task N-7 — Add `NativeAccessPermission` Grant to `CombinerSecurityManager` Policy

**Priority:** High  
**Files:** Policy files used by `CombinerSecurityManager` tests and the
`SecurityPolicyWriter` default output.

**Description:**  
`CombinerSecurityManager` intersects permission sets.  If neither the caller's
policy nor the `CombinerSecurityManager`'s own policy grants
`NativeAccessPermission`, a `checkPermission` call for that permission will
correctly fail.  Confirm that the test policy files explicitly enumerate which
trusted modules receive `NativeAccessPermission` so that the intersection logic
is exercised in tests.

This is a human implementation task (policy file changes and test additions).

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
- `NativeAccessPermission` blocks unauthorized native library loading.
- `LoadClassPermission` gates class loader creation.
- `ConcurrentPolicyFile` evaluates grants without DNS lookups.
- `createVirtualThread` / `createPlatformThread` (proposed) limit thread creation.

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

---

## Investigation: DirtyChai + JGDMS for In-Process and Remote Network Isolation

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
| Arbitrary native library loading | `NativeAccessPermission` + `RuntimePermission("loadLibrary.*")` |
| Unauthorized class loader creation | `LoadClassPermission` |
| Thread bomb DoS | `createPlatformThread` / `createVirtualThread` (proposed) |
| `System.exit()` | `RuntimePermission("exitVM.*")` |
| Reflective access to internals | Module encapsulation + SecurityManager |
| DNS / LDAP lookups (Log4j-style) | `SocketPermission` must be granted |

**What in-process isolation cannot prevent:**

- A thread that is already running can exhaust the CPU or heap without any
  permission check.
- Memory corruption through a JNI/JVMTI agent bypasses all Java-level checks.
- An attacker who has already escalated to a fully-trusted context (e.g., through
  the WhiteBox or Unsafe APIs) can read or corrupt any JVM state.

These residual gaps make process isolation (Section above) essential for truly
untrusted code.

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
│  │  NativeAccessPermission guards any native API use               │   │
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

1. `RMIClassLoader` (or the JGDMS class loader) fetches the JAR from the codebase URL.
2. The JAR signature is verified against the certificate in the client's truststore.
3. The proxy class is loaded into a `ProtectionDomain` whose `CodeSource` records the
   verified certificate.
4. The client's policy grants permissions to `CodeSource` entries signed by trusted
   certificates — unsigned or mis-signed proxies receive no permissions and are
   immediately inert.

This is equivalent to the `ProxyTrust` pattern's outer layer (confirming that the proxy
*class* comes from a trusted source), but it is enforced by the JVM class loader and
the DirtyChai `ConcurrentPolicyFile` rather than by a `getProxyVerifier()` call.

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
    //   NativeAccessPermission — Phoenix has no native library needs
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

DirtyChai's `SerialObjectPermission` is checked in `SerialCallbackContext` immediately
before a class's custom `readObject`/`readFields` method is invoked during
`ObjectInputStream` deserialisation.  The permission name is the fully-qualified class
name of the class being deserialised.

```java
// SerialCallbackContext.java (DirtyChai modification)
SerialCallbackContext(Object obj, ObjectStreamClass desc) {
    this(obj, desc, check(getGuard(desc.getName())), Thread.currentThread());
    //                    ^^^^^^^^^^^^^^^^^^^^^^^^^^
    //                    SerialObjectPermission(className).checkGuard(null)
    //                    fires here, before readObject is called
}
```

The effect is that **every class that implements `Serializable` and has a custom
`readObject` method** requires a `SerialObjectPermission` grant in the deserialising
thread's `AccessControlContext` stack.  Classes that rely purely on default serialisation
(no `readObject`) do not trigger this check — only those with custom `readObject`
implementations do.

### Activation Classes That Require SerialObjectPermission

The following classes are part of the JGDMS activation serialisation path and have
custom `readObject` implementations:

| Class | Why it needs SerialObjectPermission |
|-------|-------------------------------------|
| `java.rmi.activation.ActivationDesc` | Custom `readObject` validates fields |
| `java.rmi.activation.ActivationGroupDesc` | Custom `readObject` validates policy/codebase |
| `java.rmi.activation.ActivationGroupDesc$CommandEnvironment` | Custom `readObject` validates JVM args list |
| `java.rmi.activation.ActivationID` | Custom `readObject` validates UID and activator ref |
| `java.rmi.activation.ActivationGroupID` | Custom `readObject` validates UID and system ref |
| `java.rmi.MarshalledObject` | Custom `readObject` reads serialised byte array |

Classes that use default serialisation only (e.g., `java.util.Properties`,
`java.lang.String`, primitive wrappers) do not require `SerialObjectPermission` and may
be freely deserialised as long as the `ObjectInputFilter` does not reject them.

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
class that has a custom `readObject` method needs `SerialObjectPermission` granted to
the service's codebase:

```
// Group JVM policy — service-specific SerialObjectPermission grants
grant CodeBase "file:/path/to/my-service.jar"
      signedBy "service-cert" {

    // Service's own serialisable domain objects
    permission au.zeus.jdk.authorization.guards.SerialObjectPermission
              "com.example.service.DomainObject";
    permission au.zeus.jdk.authorization.guards.SerialObjectPermission
              "com.example.service.RequestRecord";
    // ... enumerate all classes with custom readObject in this service
};
```

The `SecurityPolicyWriter` tool can generate these grants automatically by scanning
the service JAR for classes that implement `readObject`.

### SerialObjectPermission as a Defence Against Gadget Chains

A serialisation gadget chain requires that at least one class in the chain has a
custom `readObject` that triggers a dangerous side-effect (arbitrary code execution,
SSRF, file write, etc.).  By requiring an explicit `SerialObjectPermission` grant for
every such class, DirtyChai ensures that:

1. A service policy that does not grant `SerialObjectPermission "com.sun.jndi.*"` will
   throw `SecurityException` before the JNDI gadget's `readObject` fires.
2. A dependency JAR that unexpectedly ships a gadget class cannot be weaponised unless
   the administrator explicitly grants `SerialObjectPermission` for that class.

This is a defence-in-depth supplement to the `ObjectInputFilter` (serial filter), not a
replacement.  Both should be configured: the serial filter enforces an allowlist of
deserialised class names; `SerialObjectPermission` enforces an allowlist of classes
whose custom `readObject` logic may execute.

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

// NOT GRANTED to Phoenix: NativeAccessPermission, AllPermission,
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
//   NativeAccessPermission — service has no native library needs
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
| Native library loading is blocked in all group JVMs | `NativeAccessPermission` not granted; `--illegal-native-access=deny` in effect |
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

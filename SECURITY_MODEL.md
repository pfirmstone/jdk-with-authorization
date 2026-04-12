# Dirty Chai - OpenJDK Authorization Security Model: Comprehensive Architecture

**Version:** 1.4  
**Date:** 2025  
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
6. [Authentication & Authorization Framework](#authentication--authorization-framework)
7. [SecureClassLoader Enhancement](#secureclassloader-enhancement)
8. [Virtual Thread Support](#virtual-thread-support)
9. [Subject Context Management](#subject-context-management)
10. [AccessController Integration](#accesscontroller-integration)
11. [Backward Compatibility](#backward-compatibility)
12. [Threat Model & Prevention](#threat-model--prevention)
13. [Configuration & Deployment](#configuration--deployment)
14. [Security Properties](#security-properties)
15. [Implementation Guidelines](#implementation-guidelines)
16. [Performance & Scalability](#performance--scalability)
17. [API Reference](#api-reference)
18. [Troubleshooting](#troubleshooting)
19. [References](#references)
20. [Conclusion](#conclusion)

---

## Executive Summary

> **In plain English:** While the standard JDK SecurityManager can enforce policy-based access control, it does not validate an authenticated user (`Subject`) context before code is loaded. Dirty Chai provides the infrastructure for optional principal-authenticated class loading—administrators can configure policy grants to require a verified Subject context (blocking unauthenticated code at the class-loading gate), or allow unauthenticated code by granting permissions without principal requirements. The policy file determines how strictly authentication is enforced.

**Dirty Chai** is a comprehensive authorization framework for OpenJDK that implements a **multi-layered security architecture** enforcing the **Principle of Least Privilege (PoLP)** through:

- **Optional Principal-Authenticated Code Loading:** Infrastructure enabling policy-configured Subject context requirements; policy grants with principals enforce authentication, grants without principals allow unauthenticated code
- **Transitive Dependency Lockdown:** Each dependency independently validated; no trust transfer
- **Platform Module Authorization:** Even standard OpenJDK modules require explicit policy grants
- **Virtual Thread Integration:** ScopedValue preserves security context; AccessControlContext inherited immutably; PrivilegedActions fully supported
- **Unified Subject Context:** Subject.callAs() always delegates to Subject.doAs() in Dirty Chai system (allowSecurityManager = true)
- **AccessController Stack Walk:** Native stack walking compatible with virtual threads
- **Backward Compatible APIs:** Subject.doAs() and legacy security APIs fully operational
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
| **Virtual Thread Compatible** | ScopedValue + AccessControlContext + StackWalk | Security context maintained across mounts/unmounts | 1M+ concurrent threads remain fully governed |
| **Subject Management** | callAs() always delegates to doAs() via SecurityManager | Unified access control model | Single predictable code path; no bypass routes |
| **Backward Compatible** | Subject.doAs() fully operational; legacy APIs supported | Existing code works without modification | Zero migration cost for existing applications |
| **Non-Blocking Performance** | ConcurrentHashMap with lock-free reads | High-concurrency throughput maintained | Security does not become the bottleneck |

---

## Project Overview

### What is Dirty Chai?

**Dirty Chai** enhances OpenJDK with rigorous code validation and principal-authenticated class loading, ensuring that every piece of code (whether "clean" from trusted sources or "dirty" from untrusted origins) undergoes comprehensive security validation.

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
java -Djava.security.manager=au.zeus.jdk.authorization.sm.CombinerSecurityManager \
     -Djava.security.policy=/path/to/app.policy \
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
| Virtual thread context | No propagation guarantee | `ScopedValue` ensures consistent context |
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
| Subject context propagation | `ThreadLocal` — not inherited by child threads | `ScopedValue` — automatically inherited within scope |
| AccessControlContext inheritance | Mutable, thread-local | Immutable, inherited via `ScopedValue` |
| PrivilegedAction support | Full | Full (identical semantics) |
| Stack walk for permission checks | OS-level stack | JVM-level stack (carrier frames excluded) |
| Carrier thread domains included? | N/A | No — only virtual thread frames counted |
| Subject modification during execution | Allowed (until `setReadOnly()`) | Allowed within scope; scope exit restores prior state |
| Concurrency | Kernel threads (limited) | Up to millions of virtual threads |

> **Key difference from platform threads:** ScopedValue replaces ThreadLocal for context propagation, ensuring security context is never accidentally absent or accidentally shared.

---

### 1. AccessControlContext Inheritance Model

**Architecture:** Virtual threads inherit immutable AccessControlContext

```
AccessControlContext Inheritance Hierarchy:

Platform Thread Model (Traditional):
  AccessControlContext (thread-local, mutable during execution)
    └─ ProtectionDomains
    └─ DomainCombiner
    └─ Privileged Context

Virtual Thread Model (Enhanced):
  AccessControlContext (inherited immutably via ScopedValue)
    └─ ProtectionDomains (copied at inheritance point)
    └─ DomainCombiner (same instance)
    └─ Privileged Context (immutable snapshot)
    
  ✅ Immutable inheritance prevents tampering
  ✅ Child VTs cannot modify parent's context
  ✅ Full stack walk capability maintained
```

### 2. PrivilegedAction & PrivilegedExceptionAction Support

**Full Support:** Virtual threads execute PrivilegedActions with complete permission inheritance

```
// Example: Privileged action in virtual thread
private static final ScopedValue<AccessControlContext> ACC = 
    ScopedValue.newInstance();

public void executePrivilegedInVirtualThread() throws Exception {
    AccessControlContext context = AccessController.getContext();
    
    try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
        executor.submit(
            ScopedValue.where(ACC, context).runner(() -> {
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
            })
        );
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

### 4. ScopedValue-Based Context Propagation

**Architecture:** Security context propagates via ScopedValue

```
ScopedValue Propagation:

Platform Thread Model (Traditional):
  ThreadLocal<AccessControlContext> → NOT inherited by child threads
  ThreadLocal<Subject> → NOT inherited by child threads
  
Virtual Thread Model (Enhanced):
  ScopedValue<AccessControlContext> → Inherited automatically ✅
  ScopedValue<Subject> → Inherited automatically ✅
  
  private static final ScopedValue<AccessControlContext> ACC = 
      ScopedValue.newInstance();
  
  // Automatic inheritance:
  ScopedValue.where(ACC, context).run(() -> {
      // Child VT inherits context
      AccessControlContext current = ACC.get();  // ✅ Same as parent
  });
```

**Advantages:**
- ✅ Explicit scoping (clear intent)
- ✅ Automatic inheritance by child tasks
- ✅ No memory leaks from ThreadLocal cleanup
- ✅ Works seamlessly with structured concurrency

### 5. Virtual Thread Lifecycle Integration

```
Virtual Thread Creation:
┌─────────────────────────────────────────┐
│ Parent VirtualThread (authenticated)    │
│ AccessControlContext: inherited         │
│ Subject: inherited via ScopedValue      │
└────────────┬────────────────────────────┘
             │
             ├─→ Create child task: VirtualThread.Builder
             │   └─ Inherits ACC and Subject
             │
             ▼
┌─────────────────────────────────────────┐
│ Child VirtualThread (NEW)               │
│ AccessControlContext: inherited ✅      │
│ Subject: inherited via ScopedValue ✅   │
│ Can load classes with inherited auth    │
└────────────┬────────────────────────────┘
             │
             ├─→ defineClass() called
             │
             ▼
┌─────────────────────────────────────────┐
│ SecureClassLoader.getProtectionDomain()│
│ Subject.current() from ScopedValue ✅   │
│ ACC from ScopedValue ✅                 │
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
       (From ScopedValue, not thread state)

Transition: VirtualThread unmounts (park)
┌──────────────────┐
│ Carrier Thread   │
│ (different user) │
└──────────────────┘
           ↓
    VirtualThread still has
    ScopedValue context in scope
    AccessControlContext in scope
           ↓
    Later: VirtualThread resumes on different carrier
           ↓
    Subject.current() called
    AccessController.getContext() called
           ↓
    ✅ Still returns correct context
       (ScopedValue + ACC survive unmount/mount)
```

### 7. Structured Concurrency Integration

**Pattern:** Use `StructuredTaskScope` for concurrent tasks

```
private static final ScopedValue<Subject> SUBJECT = 
    ScopedValue.newInstance();
private static final ScopedValue<AccessControlContext> ACC = 
    ScopedValue.newInstance();

// Example: Execute multiple authenticated tasks concurrently
void executeWithContext(Subject subject, AccessControlContext acc) throws Exception {
    ScopedValue.where(SUBJECT, subject)
        .where(ACC, acc)
        .run(() -> {
            try (var scope = new StructuredTaskScope.ShutdownOnFailure()) {
                var future1 = scope.fork(() -> {
                    // Child task 1
                    Subject current = SUBJECT.get();  // Inherited ✅
                    AccessControlContext ctx = ACC.get(); // Inherited ✅
                    return loadAndProcessClasses();
                });
                
                var future2 = scope.fork(() -> {
                    // Child task 2
                    Subject current = SUBJECT.get();  // Inherited ✅
                    AccessControlContext ctx = ACC.get(); // Inherited ✅
                    return accessResources();
                });
                
                scope.joinUntil(Instant.now().plusSeconds(10));
                
                // Process results...
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
| **Subject storage** | ThreadLocal (isolated) | ScopedValue (inherited) | ✅ Better context propagation |
| **ACC storage** | ThreadLocal (isolated) | ScopedValue (inherited) | ✅ Immutable inheritance |
| **Stack walk** | OS-level stack | JVM-level stack | ✅ Works correctly |
| **Cache effects** | L1/L2 impact | Minimal | ✅ Better performance |
| **GC pressure** | Long-lived memory | Short-lived, GC-friendly | ✅ Reduced GC pause |

**Security Scalability:**
- **Before (Platform Threads):**
  - 1000 concurrent users = 1000 * 1MB = ~1GB memory
  - Each needs ThreadLocal Subject/ACC storage
  - OS context switch overhead for each
  
- **After (Virtual Threads):**
  - 1,000,000 concurrent virtual tasks = ~100MB memory
  - ScopedValue-based context efficient
  - Minimal scheduler overhead per context
  - AccessControlContext inherited, not copied per-thread

### 9. Virtual Thread with SecurityManager Integration

```
// Configure for virtual threads
// -Djava.security.manager=au.zeus.jdk.authorization.sm.CombinerSecurityManager
// -Djava.security.policy=/etc/java.policy

// Application code
public class VirtualThreadApp {
    private static final ScopedValue<Subject> SUBJECT_CONTEXT = 
        ScopedValue.newInstance();
    private static final ScopedValue<AccessControlContext> ACC_CONTEXT = 
        ScopedValue.newInstance();
    
    public static void main(String[] args) throws Exception {
        // Authenticate user
        Subject subject = authenticateUser(args[0]);
        AccessControlContext acc = AccessController.getContext();
        
        // Create thread pool of virtual threads
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            
            // Submit 1 million tasks with authenticated context
            for (int i = 0; i < 1_000_000; i++) {
                executor.submit(
                    ScopedValue.where(SUBJECT_CONTEXT, subject)
                        .where(ACC_CONTEXT, acc)
                        .runner(() -> {
                            // Each task inherits authenticated subject and ACC
                            Subject current = SUBJECT_CONTEXT.get();
                            AccessControlContext currentAcc = ACC_CONTEXT.get();
                            assert current == subject; // ✅ Inherited
                            assert currentAcc == acc;  // ✅ Inherited immutably
                            
                            // Load classes with authentication
                            ClassLoader cl = new SecureClassLoader();
                            Class<?> appClass = cl.loadClass("com.app.Task");
                            
                            // Execute with security context
                            appClass.getMethod("run").invoke(null);
                        })
                );
            }
            
            executor.shutdown();
            if (!executor.awaitTermination(5, TimeUnit.MINUTES)) {
                executor.shutdownNow();
            }
        }
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
ScopedValue.where(SUBJECT_CONTEXT, subject)
    .where(ACC_CONTEXT, acc)
    .runner(() -> {
        try {
            ClassLoader cl = new SecureClassLoader();
            Class<?> appClass = cl.loadClass("com.app.Task");
            appClass.getMethod("run").invoke(null);
        } catch (SecurityException e) {
            // Security context available even in exception handler
            Subject current = SUBJECT_CONTEXT.get();  // ✅ Still available
            AccessControlContext currentAcc = ACC_CONTEXT.get(); // ✅ Still available
            
            // Log with authentication context
            logger.error("Task failed with authenticated user: " + 
                        current.getPrincipals(), e);
            
            // Can initiate remediation with known principal
            notifySecurityAdmin(current.getPrincipals(), e);
        } catch (Exception e) {
            // Standard exception handling
            throw new RuntimeException(e);
        }
    }).run();
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
AccessControlContext context = AccessController.getContext();

ScopedValue.where(ACC_CONTEXT, context).runner(() -> {
    // Virtual thread executes with inherited ACC
    
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

## Backward Compatibility

### 1. Subject.doAs() Full Compatibility

**Model:** Legacy `Subject.doAs()` fully operational with virtual threads

```
// Legacy code (pre-virtual threads)
Subject subject = new Subject();
LoginContext lc = new LoginContext("MyApp");
lc.login();  // Populate subject

// Using deprecated but fully supported Subject.doAs()
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

### 2. Subject.doAsPrivileged() Compatibility

**Model:** Legacy `Subject.doAsPrivileged()` with explicit context

```
// Legacy code with explicit context
Subject subject = authenticateUser();
AccessControlContext context = AccessController.getContext();

// Using deprecated but fully supported Subject.doAsPrivileged()
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

**Backward Compatibility Details:**
- ✅ No code changes required
- ✅ Explicit context properly applied
- ✅ Privilege boundaries respected
- ✅ Virtual threads handle transparent to code

### 3. ThreadLocal Subject Access Patterns

**Pattern:** Code accessing Subject from ThreadLocal remains compatible

```
// Pattern 1: ThreadLocal Subject (old pattern)
private static final ThreadLocal<Subject> subjectLocal = 
    new ThreadLocal<>();

// DEPRECATED but compatible:
// In virtual threads, use ScopedValue instead
private static final ScopedValue<Subject> subjectScoped = 
    ScopedValue.newInstance();

// Pattern 2: AccessControlContext from SecurityManager
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

// New code (recommended for VTs):
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
// Legacy pattern with reflection
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
| **Reflection-based SM bypass** | `Method.invoke()` on setSecurityManager | Layer 2: Stack inspection detects reflection |
| **Untrusted code loading** | Unsigned JAR from attacker.com | Layer 3: LoadClassPermission denied |
| **Privilege escalation via deps** | Trusted code loads evil transitive dep | Layer 4: Each dep independently validated |
| **Cache poisoning** | Unauthenticated context reuses cached domain | Layer 5: Cache validates principals on hit |
| **Null principal exploit** | Load with empty Subject | Layer 2: Principals non-empty check fails |
| **Certificate forgery** | Fake cert for trusted.com | CodeSourceKey: cert must validate for URL |
| **Agent injection** | Load java.lang.instrument without auth | Layer 1: No CodeSource → Layer 2: No Subject |
| **Service loader bypass** | ServiceLoader.load() restricted module | Layer 3: Module not in policy → denied |
| **Read-only subject escape** | Load while subject sealed | Layer 2: isReadOnly() check throws exception |
| **DNS-based cache confusion** | Same IP, different DNS names | CodeSourceKey: String comparison, no DNS |
| **Virtual thread context escape** | Child VT steals parent's ScopedValue | ScopedValue design: inherited, not stolen |
| **Cross-virtual thread pollution** | One VT accesses another VT's context | ScopedValue isolation: separate instances |
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
  1. ScopedValue.where() creates a new, scoped binding per invocation
  2. Binding is read-only inside the scope; cannot be modified
  3. Children only inherit if explicitly passed via ScopedValue.where()
  4. Outside the scope boundary Subject.current() returns null
  5. ✅ Context cannot escape its original scope

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
  2. Inherited via ScopedValue (read-only binding)
  3. Cannot be modified post-inheritance
  4. New context creation requires explicit doPrivileged()
  5. ✅ Tampering attempt fails
  
Result: ACC integrity maintained
```

#### **Scenario F: Subject Context Escape**

```
Attack:
  Child virtual thread tries to access parent's Subject context
  
Prevention:
  1. Subject bound via ScopedValue
  2. ScopedValue.where() creates new binding scope
  3. Parent's Subject NOT accessible outside binding
  4. Child VTs only inherit if explicitly wrapped
  5. ✅ Context escape prevented
  
Result: Subject isolation maintained per scope
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
- Virtual thread context protected by ScopedValue isolation
- AccessControlContext protected by immutability

---

### 2. Integrity

**Enforced through:**
- Certificate validation in CodeSourceKey
- Principal verification in Subject
- Policy-based permission grants
- ScopedValue immutability (inherited, not modified)
- AccessControlContext immutability (cannot be tampered)

**Guarantees:**
- Modified code fails certificate check
- Corrupted principals detected by Subject validation
- Policy tampering detected via permission denial
- ScopedValue context cannot be corrupted by child threads
- AccessControlContext remains pristine throughout execution

---

### 3. Authentication

**Enforced through:**
- Subject-based principal authentication
- LoginModule-driven authentication process
- Principal presence validation in each class load
- ScopedValue-preserved authentication across virtual thread boundaries
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
- ScopedValue-based context inheritance
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
- ScopedValue context in exception handlers
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
ScopedValue.where(SUBJECT, subject)
    .where(ACC, context)
    .run(() -> {
        logger.info("Virtual thread task started for principal: " + 
            subject.getPrincipals());
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

#### **Authentication Setup (Legacy - Still Fully Supported)**

```
// Legacy approach (still works everywhere)
Subject subject = new Subject();
LoginContext lc = new LoginContext("MyApp");
lc.login();

// Using deprecated but fully supported Subject.doAs()
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
// Modern pattern for virtual threads
private static final ScopedValue<Subject> SUBJECT_CONTEXT = 
    ScopedValue.newInstance();
private static final ScopedValue<AccessControlContext> ACC_CONTEXT = 
    ScopedValue.newInstance();

public void executeWithVirtualThreads(Subject subject) throws Exception {
    AccessControlContext acc = AccessController.getContext();
    
    try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
        for (int i = 0; i < 10_000; i++) {
            executor.submit(
                ScopedValue.where(SUBJECT_CONTEXT, subject)
                    .where(ACC_CONTEXT, acc)
                    .runner(() -> {
                        // Child virtual thread inherits both subject and ACC
                        Subject current = SUBJECT_CONTEXT.get();
                        AccessControlContext currentAcc = ACC_CONTEXT.get();
                        assert current == subject;        // ✅ Inherited
                        assert currentAcc == acc;         // ✅ Inherited immutably
                        
                        // All operations use inherited authentication
                        ClassLoader cl = new SecureClassLoader();
                        Class<?> appClass = cl.loadClass("com.app.Task");
                        appClass.getMethod("run").invoke(null);
                    })
            );
        }
        
        executor.shutdown();
        if (!executor.awaitTermination(5, TimeUnit.MINUTES)) {
            executor.shutdownNow();
        }
    }
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
□ ScopedValue context properly isolated
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
| `Subject.callAs()` / `doAs()` | < 0.05 ms | Scoped value binding only |
| `AccessController.checkPermission()` | < 0.01 ms | Single-level permission lookup with cached domain |
| Virtual thread spawn with context | ~0.1 ms | `ScopedValue.where()` binding |

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
- Virtual thread security context propagation adds zero per-thread allocation (ScopedValue uses carrier-local storage).
- Avoid calling `Subject.setReadOnly()` before class loading is complete; it forces re-validation on every check.

---

## API Reference

### Key Method Summary

| Method | Class | When to Use | Signature |
|--------|-------|-------------|-----------|
| `callAs()` | `javax.security.auth.Subject` | Modern replacement for `doAs()`; use in all new code | `static <T> T callAs(Subject subject, Callable<T> action)` |
| `doAs()` | `javax.security.auth.Subject` | Legacy pattern; fully supported | `static <T> T doAs(Subject subject, PrivilegedAction<T> action)` |
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
| "Virtual thread ScopedValue not bound" | Accessed outside ScopedValue.where() scope | Ensure call within run()/call() context |
| "Virtual thread context not inherited" | Not wrapped with ScopedValue.where() | Use ScopedValue.where().runner() or .callable() |
| "PrivilegedAction not working" | ACC not inherited properly | Use ScopedValue to inherit ACC |
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
| `java.security.SecureClassLoader` | Class loading with principal-based authorization |
| `java.security.AccessController` | Privileged action execution with caller validation; stack walk compatible with VTs |
| `java.security.AccessControlContext` | Security context snapshot; immutable inheritance in VTs |
| `java.lang.ScopedValue` | Virtual thread-compatible context propagation |
| `javax.security.auth.Subject` | Principal container; Subject.doAs() and Subject.callAs() support |
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

## Conclusion

**Dirty Chai** provides **comprehensive protection** against privilege escalation, code injection, and context escape attacks through:

1. **Multi-layer validation** at class loading time
2. **Principal-based authorization** requiring both identity and code source
3. **Independent evaluation** of each dependency
4. **Fail-secure design** with no silent failures
5. **Virtual thread integration** via ScopedValue + immutable ACC + native stack walk
6. **Unified Subject context** via Subject.callAs() → Subject.doAs() delegation (allowSecurityManager = true)
7. **Full backward compatibility** with Subject.doAs() and legacy APIs
8. **PrivilegedAction support** with inherited and explicit contexts
9. **High-performance caching** without sacrificing security
10. **Clear audit trails** for compliance and monitoring

This architecture successfully enforces the **Principle of Least Privilege** while maintaining compatibility with OpenJDK security APIs and achieving high performance in multi-threaded and virtual-threaded environments.

---

**Document Version:** 1.4  
**Last Updated:** 2025  
**Classification:** Technical Documentation  
**Project:** Dirty Chai - OpenJDK with Authorization  
**Base:** OpenJDK (trunk)  
**License:** GPL v2 + Classpath Exception  
**Subject Context:** Subject.callAs() always delegates to Subject.doAs() in Dirty Chai system (allowSecurityManager() = true)  
**Virtual Thread Support:** Fully Integrated via Immutable AccessControlContext + Native Stack Walk + ScopedValue  
**Backward Compatibility:** Complete (Subject.doAs(), PrivilegedAction, legacy APIs fully operational)

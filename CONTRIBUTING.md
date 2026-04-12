# Contributing to Dirty Chai

Please see the [OpenJDK Developers' Guide](https://openjdk.org/guide/).

There may be legal ramifications of using AI Generated code and generated documents, at this time, we're trialling using AI to generate markdown text documents in the root directory to help describe changes.  You can use AI agents to assist in understanding how the JVM works, assistance identifying bugs and adding markdown text documents that aren't part of the final product, and are either stored in the root of the project or a directory named AI.

https://openjdk.org/legal/ai

This is the description of what the code block changes:
Apply project preference: Adding comprehensive documentation about the conditional validation strategy for SecurityManager installation, including rationale, implementation details, and developer guidance for working with trusted vs. custom SecurityManager implementations.

This is the code block that represents the suggested code change:

# Claude Development Guide

## Overview

This document provides guidance for AI assistants (Claude) working on the JDK with Authorization project. It documents the project structure, security model, coding standards, and best practices.

**Project:** JDK with Authorization  
**Repository:** https://github.com/pfirmstone/jdk-with-authorization  
**Upstream:** https://github.com/openjdk/jdk  
**Branch:** trunk

---

## Quick Reference

### Key Files & Their Purpose

| File | Purpose | Security Level |
|------|---------|-----------------|
| `System.java` | SecurityManager installation with conditional validation | CRITICAL |
| `AccessController.java` | Privileged action execution with caller validation | CRITICAL |
| `ConcurrentPolicyFile.java` | Policy-based permission enforcement | HIGH |
| `Uri.java` | RFC 3986 URI validation | HIGH |
| `CombinerSecurityManager.java` | Permission intersection enforcement | HIGH |
| `LoadClassPermission.java` | Class loading authorization | HIGH |
| `NativeAccessPermission.java` | Native code access control | HIGH |
| `SerialObjectPermission.java` | Object serialization authorization | MEDIUM |

### Critical Security Constraints

**MUST FOLLOW:**
1. ✅ All code follows `.editorconfig` formatting rules (2-space indent for hotspot)
2. ✅ Security validation occurs at ALL entry points
3. ✅ Fail-secure design (defaults to deny on validation failure)
4. ✅ No exception swallowing without explicit security justification
5. ✅ @CallerSensitive on all privileged APIs
6. ✅ StackWalker for synthetic code detection (custom SM only)
7. ✅ RFC 3986 URI validation for all CodeSource URLs
8. ✅ Conditional validation strategy for SecurityManager implementations

---

## Project Structure

### Module Organization


src/
├── java.base/
│   ├── share/classes/
│   │   ├── java/lang/
│   │   │   ├── System.java              # SecurityManager installation (conditional)
│   │   │   └── SecurityManager.java     # Permission checks
│   │   ├── java/security/
│   │   │   ├── AccessController.java    # Privilege execution
│   │   │   └── AccessControlContext.java # Context management
│   │   ├── javax/security/auth/
│   │   │   └── Subject.java            # Principal management
│   │   └── au/zeus/jdk/
│   │       ├── authorization/
│   │       │   ├── sm/
│   │       │   │   └── CombinerSecurityManager.java
│   │       │   ├── policy/
│   │       │   │   └── ConcurrentPolicyFile.java
│   │       │   ├── guards/
│   │       │   │   ├── LoadClassPermission.java
│   │       │   │   ├── NativeAccessPermission.java
│   │       │   │   └── SerialObjectPermission.java
│   │       │   └── tool/
│   │       │       └── SecurityPolicyWriter.java
│   │       └── net/
│   │           └── Uri.java             # RFC 3986 validation
│   └── share/native/
│       └── java/lang/
│           └── System.c                 # Native security checks
└── hotspot/
    └── share/runtime/
        └── java.cpp                     # VM-level security integration


### Authorization Framework Architecture


┌─────────────────────────────────────────────┐
│ Application Code                            │
└─────────────────┬───────────────────────────┘
                  │
        ┌─────────▼──────────┐
        │ SecurityManager    │
        │ (CombinerSM or     │
        │  Custom)           │
        └─────────┬──────────┘
                  │
        ┌─────────▼──────────────────────┐
        │ AccessController               │
        │ ├─ setSecurityManager()        │
        │ ├─ doPrivileged()              │
        │ └─ checkPermission()           │
        └─────────┬──────────────────────┘
                  │
        ┌─────────▼──────────────────────┐
        │ ConcurrentPolicyFile           │
        │ ├─ Grant Matching              │
        │ ├─ Permission Intersection     │
        │ └─ Policy Evaluation           │
        └─────────┬──────────────────────┘
                  │
        ┌─────────▼──────────────────────┐
        │ Permission Classes             │
        │ ├─ LoadClassPermission         │
        │ ├─ NativeAccessPermission      │
        │ ├─ SerialObjectPermission      │
        │ └─ Standard Permissions        │
        └────────────────────────────────┘


---

## Security Model

### Conditional Validation Strategy

The system implements **conditional validation** for SecurityManager installation, balancing security and usability:

#### For Trusted SecurityManager Classes

**Classes:** `SecurityManager`, `CombinerSecurityManager`

**Rationale:**
- Loaded from bootstrap classloader (java.base module)
- Part of trusted codebase (not user-provided)
- Permissions controlled via policy file
- Policy enforcement provides equivalent protection to stack inspection

**Validation Performed:**
- ✅ Null parameter check only
- ✅ Policy-based permission enforcement

**Effect:**
- No stack inspection overhead
- Full compatibility with test frameworks
- Modern frameworks with bytecode generation work seamlessly

#### For Custom SecurityManager Implementations

**Classes:** Any class extending `SecurityManager` from application classpath

**Rationale:**
- May originate from untrusted source
- Could be malicious or buggy
- Attack vector: Generated code injection

**Validation Performed:**
- ✅ Layer 1: Direct caller check (@CallerSensitive)
- ✅ Layer 2: Stack inspection (StackWalker)
- ✅ Layer 3: ProtectionDomain validation
- ✅ Layer 4: Generated code detection

**Effect:**
- Strict defense-in-depth protection
- Reflection-based attacks blocked
- Generated code bypass prevented
- Synthetic domain creation blocked

### Implementation Details

java
private static boolean trustedSMClass(SecurityManager sm){
    // Exact class matching (prevents subclass bypass)
    if (SecurityManager.class.equals(sm.getClass())) return true;
    if (CombinerSecurityManager.class.equals(sm.getClass())) return true;
    return false;
}


**Key Security Properties:**
- Uses `equals()` not `instanceof` (prevents subclass bypass)
- Explicit whitelist (default-deny approach)
- Simple, auditable logic

### Defense-in-Depth Layers (Custom SM Only)

**Layer 1: Caller Validation**
- All privileged APIs use `@CallerSensitive`
- Direct caller identity verified via `Reflection.getCallerClass()`
- Null caller results in immediate `SecurityException`

**Layer 2: Stack Inspection**
- `StackWalker` inspects call chain (limit: 10 frames)
- Detects reflection API usage
- Blocks generated code (Lambda, Proxy, accessors)
- Fails immediately on suspicious frames

**Layer 3: CodeSource Validation**
- Verifies `ProtectionDomain` has valid code source
- Null CodeSource → guaranteed unprivileged
- RFC 3986 URI validation prevents path traversal

**Layer 4: Policy Enforcement**
- `ConcurrentPolicyFile` matches grants to domains
- Permission intersection computed
- `DomainCombiner` validation before execution

**Layer 5: Permission-Based Access Control**
- Custom permission classes (`LoadClassPermission`, etc.)
- Permission contract prevents spoofing
- Fail-secure defaults on validation failure

### Critical Security Properties

**Invariant 1: No Privilege Without Valid CodeSource**

If ProtectionDomain.getCodeSource() == null:
  Then domain CANNOT match any policy grants
  And domain is GUARANTEED unprivileged


**Invariant 2: Fail-Secure on Validation Failure**

If URI validation throws exception:
  Then return null CodeSource
  Then domain is unprivileged


**Invariant 3: Synthetic Code Detection**

If reflection/generated code detected in stack:
  Then throw SecurityException immediately
  Then operation BLOCKED


**Invariant 4: Permission Contract Enforcement**

Permission A.implies(Permission B):
  Returns true IFF A grants B
  Attacker cannot make TrojanPermission.implies(FilePermission) return true


---

## Coding Standards

### Format & Style

**Follow `.editorconfig` Requirements:**
- Character set: UTF-8
- Line endings: Unix (LF)
- Indentation: 2 spaces (hotspot code)
- Trailing whitespace: Trimmed
- Newline at EOF: Required

### Security Requirements

**Every Security-Critical Method:**
1. Must have `@CallerSensitive` annotation
2. Must verify caller via `Reflection.getCallerClass()` or native check
3. For custom SecurityManager validation: Must use StackWalker
4. Must have comprehensive JavaDoc explaining security model
5. Must throw `SecurityException` on violation (NOT `IllegalArgumentException`)

**Example (Conditional Strategy):**

java
/**
 * Sets the system-wide security manager.
 *
 * <p><b>Validation Strategy (Conditional):</b>
 * For trusted implementations (SecurityManager, CombinerSecurityManager):
 * Only null parameter validation is performed.
 * 
 * For custom implementations: Full defense-in-depth validation:
 * <ol>
 *   <li>Direct Caller Check (@CallerSensitive)</li>
 *   <li>Stack Inspection (StackWalker)</li>
 *   <li>ProtectionDomain Validation</li>
 *   <li>Generated Code Detection</li>
 * </ol>
 */
@CallerSensitive
public static void setSecurityManager(SecurityManager sm) {
    if (sm == null) throw new IllegalArgumentException("sm cannot be null");
    
    if (!trustedSMClass(sm)) {
        // Full validation for custom implementations
        Class<?> caller = Reflection.getCallerClass();
        if (caller == null) {
            throw new SecurityException("No direct caller");
        }
        validateCallerStackWithStackWalker();
        // ... rest of validation
    }
    
    // Proceed with setup
}


### Exception Handling

**DO:**
- ✅ Throw `SecurityException` for security violations
- ✅ Return `null` on validation failure (fail-secure)
- ✅ Log security events (without exposing sensitive info)
- ✅ Document why exceptions are caught

**DON'T:**
- ❌ Silently swallow security-relevant exceptions
- ❌ Fall back to unpredictable behavior
- ❌ Continue execution after validation failure
- ❌ Use generic `Exception` handling for security checks

**Exception Pattern (RFC 3986 URI Validation):**

java
try {
    URL url = new URI(sb.toString()).toURL();
    return new CodeSource(url, certificates);
} catch (MalformedURLException | URISyntaxException e) {
    // SECURITY: Return null CodeSource on exception.
    // Null CodeSource cannot match any policy grants,
    // preventing privilege escalation if URI validation fails.
    return null;
}


### JavaDoc Requirements

**Security-Critical Methods Need:**
1. `@CallerSensitive` annotation (if applicable)
2. Description of security requirements
3. List of security checks performed
4. Explanation of conditional strategy (if applicable)
5. Attack vectors prevented
6. Exception conditions documented

**Example (Conditional Strategy Documentation):**

java
/**
 * Sets the system-wide security manager.
 *
 * <p><b>Validation Strategy (Conditional):</b>
 * This method implements a conditional validation strategy that balances 
 * security with usability:
 * 
 * <h3>For Trusted SecurityManager Classes (SecurityManager, CombinerSecurityManager):</h3>
 * <ul>
 *   <li><b>Rationale:</b> These classes are part of the trusted codebase 
 *     (java.base module). Their permissions are controlled through the policy file, 
 *     which provides equivalent protection to stack inspection.</li>
 *   <li><b>Validation:</b> Only null parameter validation is performed.</li>
 * </ul>
 * 
 * <h3>For Custom SecurityManager Implementations:</h3>
 * <ul>
 *   <li><b>Rationale:</b> Custom implementations may originate from the application 
 *     classpath and could be malicious. Strict validation is required.</li>
 *   <li><b>Validation:</b> Full defense-in-depth validation is performed:
 *     <ol>
 *       <li>Direct Caller Check (@CallerSensitive)</li>
 *       <li>Stack Inspection (StackWalker)</li>
 *       <li>ProtectionDomain Validation</li>
 *       <li>Generated Code Detection</li>
 *     </ol>
 *   </li>
 * </ul>
 * 
 * @param sm the security manager to install (must not be null)
 * @throws IllegalArgumentException if sm is null
 * @throws SecurityException if caller is untrusted (custom SM only)
 */


---

## Common Tasks

### Working with the Conditional Strategy

#### When to Apply Strict Validation

**Situation:** You're adding a new security-critical method

**Decision Tree:**

Is this method for installing SecurityManager?
├─ YES: Use conditional validation
│       ├─ Check class type: trustedSMClass()
│       ├─ For trusted: minimal validation
│       └─ For custom: full defense-in-depth
│
└─ NO: Is it for privileged operations?
       ├─ YES: Use StackWalker always
       └─ NO: Use standard permission checks


#### When to Add a Trusted Class

**Guidelines:**
1. Class must be from java.base module only
2. Class must be loaded by bootstrap classloader
3. Class must be security-critical
4. Must document in comments why it's trusted

**Example Addition:**
java
private static boolean trustedSMClass(SecurityManager sm){
    if (SecurityManager.class.equals(sm.getClass())) return true;
    if (CombinerSecurityManager.class.equals(sm.getClass())) return true;
    // NEW: Only add after thorough security review!
    // if (NewTrustedSM.class.equals(sm.getClass())) return true;
    return false;
}


### Adding a New Permission Class

**Template:**

java
package au.zeus.jdk.authorization.guards;

import java.security.Permission;

/**
 * Permission for [CAPABILITY].
 * 
 * <p><b>Security Impact:</b>
 * Allows code to [DESCRIBE IMPACT]
 */
public class YourPermission extends Permission {
    
    private static final long serialVersionUID = 1L;
    
    /**
     * Creates permission with target name and actions.
     * 
     * @param name target name (e.g., "[RESOURCE]")
     * @param actions permitted actions (e.g., "read,write")
     */
    public YourPermission(String name, String actions) {
        super(name);
        // Validate and store actions
    }
    
    /**
     * Checks if this permission implies another.
     * 
     * <p>Permission A implies B if A grants at least the
     * permissions that B requires.
     * 
     * @param p permission to check
     * @return true if this implies p
     */
    @Override
    public boolean implies(Permission p) {
        if (!(p instanceof YourPermission)) {
            return false;
        }
        // Implement implication logic
        return checkImplies((YourPermission) p);
    }
    
    /**
     * Returns string representation for policy files.
     * 
     * Format: permission au.zeus.jdk.authorization.guards.YourPermission "name" "actions";
     */
    @Override
    public String toString() {
        return String.format("YourPermission(\"%s\",\"%s\")", 
            getName(), getActions());
    }
    
    // ... other required methods
}


### Modifying Security-Critical Code

**Before:**
1. Review `SECURITY_ANALYSIS.md` - understand current threat model
2. Review conditional validation strategy if modifying setSecurityManager
3. Identify all affected layers (Caller, Stack, CodeSource, Policy)
4. Review existing defenses

**During:**
1. Add security comments explaining WHY (not just WHAT)
2. Document conditional logic if applicable
3. Include threat model in commit message
4. Add comprehensive tests
5. Update JavaDoc with security requirements

**After:**
1. Run full test suite (including JUnit with CombinerSecurityManager)
2. Update `SECURITY_ANALYSIS.md` if invariants change
3. Document any new restrictions or trusted classes

### Adding Tests

**Security Test Pattern (Conditional Check):**

java
@Test
public void testSetSecurityManagerAcceptsTrustedClasses() {
    // Trusted implementations should work without restriction
    assertDoesNotThrow(() -> {
        System.setSecurityManager(new CombinerSecurityManager());
    });
}

@Test
public void testSetSecurityManagerRejectsReflectionCustom() {
    // Custom SM via reflection should be blocked
    Method m = System.class.getMethod("setSecurityManager", SecurityManager.class);
    
    assertThrows(SecurityException.class, () -> {
        m.invoke(null, new CustomSecurityManager());
    });
}

@Test
public void testSetSecurityManagerRejectsGeneratedCodeCustom() {
    // Custom SM via Lambda should be blocked
    PrivilegedAction<?> malicious = () -> {
        System.setSecurityManager(new CustomSecurityManager());
        return null;
    };
    
    assertThrows(SecurityException.class, () -> {
        AccessController.doPrivileged(malicious);
    });
}

@Test
public void testNullCodeSourceUnprivileged() {
    // Verify null CodeSource prevents privilege grants
    ProtectionDomain nullPD = new ProtectionDomain(
        null,  // null CodeSource
        new Permissions(),
        null,
        null
    );
    
    PermissionCollection perms = policy.getPermissions(nullPD);
    assertFalse(perms.implies(new AllPermission()));
}


---

## Common Patterns & Idioms

### Conditional Validation Pattern

java
private static boolean trustedSMClass(SecurityManager sm) {
    // Use exact class matching (prevents subclass bypass)
    if (SecurityManager.class.equals(sm.getClass())) return true;
    if (CombinerSecurityManager.class.equals(sm.getClass())) return true;
    return false;
}

if (!trustedSMClass(sm)) {
    // Strict validation for custom implementations
    validateCallerStackWithStackWalker();
    // ... other checks
}


### Caller Sensitive Method Pattern

java
@CallerSensitive
public static <T> T secureOperation(T param) {
    // Step 1: Get direct caller
    Class<?> caller = Reflection.getCallerClass();
    if (caller == null) {
        throw new SecurityException("No direct caller");
    }
    
    // Step 2: For custom implementations, inspect call stack
    if (!trustedClass(caller)) {
        validateCallerStackWithStackWalker();
    }
    
    // Step 3: Validate CodeSource
    ProtectionDomain pd = caller.getProtectionDomain();
    if (pd != null && pd.getCodeSource() == null) {
        throw new SecurityException("Invalid code source");
    }
    
    // Step 4: Perform operation
    return executeSecurely(caller, param);
}


### Fail-Secure Resource Pattern

java
private static Resource getResource(Class<?> clazz) {
    try {
        // Attempt to validate and construct resource
        return constructValidatedResource(clazz);
    } catch (ValidationException e) {
        // SECURITY: Return null/empty resource on failure
        // This guarantees unprivileged state
        return null;
    }
}


### Permission Checking Pattern

java
@Override
public boolean implies(Permission p) {
    if (!(p instanceof ThisPermission)) {
        return false;  // Cannot imply different type
    }
    
    ThisPermission other = (ThisPermission) p;
    
    // Permission A implies B if A's scope includes B's scope
    return this.isMoreGeneralThan(other);
}


---

## Debugging & Troubleshooting

### Enable Security Debugging


# Run with security debugging enabled
java -Djava.security.debug=access,domain,provider -jar app.jar


### Common Security Errors

**`SecurityException: Reflection detected` (Custom SM)**
- Cause: Method called via reflection
- Fix: Call directly from application code
- Verification: Stack trace should show direct method call

**`SecurityException: Generated code detected` (Custom SM)**
- Cause: Call from Lambda, Proxy, or generated accessor
- Fix: Use standard methods, not generated wrappers
- Verification: Stack trace shows `$$Lambda$` or `$Proxy`

**`SecurityException: Invalid code source`**
- Cause: ProtectionDomain has null CodeSource
- Fix: Ensure classes loaded from valid source
- Verification: Check class loader and module name

**`AccessControlException: Access denied`**
- Cause: Policy doesn't grant required permission
- Fix: Update policy file with required permission
- Verification: Review `java.security.debug=access` output

### Conditional Check Decision

**When debugging setSecurityManager validation:**

1. **Check trusted class first:**
   java
   if (trustedSMClass(sm)) {
       // Only null parameter check performed
       // If error, it's not from stack inspection
   }
   

2. **Identify error type:**
   - Direct error: "Direct caller cannot be null"
   - Stack error: "Reflection detected" or "Generated code detected"
   - Domain error: "Null ProtectionDomain"

3. **Correlate with error message** to identify which layer failed

---

## Performance Considerations

### StackWalker Overhead

- Inspects up to 10 frames (not entire stack)
- Used only for custom SecurityManager implementations
- Trusted implementations skip entirely
- Negligible impact on runtime performance

### RFC 3986 URI Validation

- Performed during doPrivileged() with restricted permissions
- Validates URI character set strictly
- Caches validation results in CodeSource
- Minimal impact due to fail-fast design

### Policy Matching

- `ConcurrentPolicyFile` designed for concurrent access
- No caching of permission decisions (scales better)
- Permission intersection computed on-demand
- Optimized for high-throughput scenarios

### Conditional Check Impact

- `trustedSMClass()` is O(1) operation (simple equals checks)
- Trusted implementations: Only null check (minimal overhead)
- Custom implementations: Full validation (acceptable at startup)
- Negligible overall impact due to single installation per JVM

---

## References & Resources

### Project Documentation
- [SECURITY_ANALYSIS.md](./SECURITY_ANALYSIS.md) - Comprehensive security analysis
- [VULNERABILITIES_ADDRESSED.md](./VULNERABILITIES_ADDRESSED.md) - Vulnerability catalog
- [.editorconfig](./.editorconfig) - Code formatting standards
- [CONTRIBUTING.md](./CONTRIBUTING.md) - Contribution guidelines

### External Standards
- [RFC 3986 - URI Generic Syntax](https://tools.ietf.org/html/rfc3986)
- [OpenJDK Security Architecture](https://openjdk.org/guide/)
- [Java Security Tutorial](https://docs.oracle.com/javase/tutorial/security/)

### Related Projects
- [OpenJDK JDK](https://github.com/openjdk/jdk) - Upstream repository
- [River Project](https://river.apache.org/) - Authorization framework basis

---

## Getting Help

### For AI Assistants Working on This Project

1. **Conditional Strategy Questions?** → Review this section first
2. **Security Questions?** → Check `SECURITY_ANALYSIS.md`
3. **Code Format?** → Check `.editorconfig` requirements
4. **API Design?** → Look at existing `*Permission` classes
5. **Stack Inspection?** → See `System.setSecurityManager()` implementation
6. **Policy Matching?** → Study `ConcurrentPolicyFile.implies()`

### Decision Tree for SecurityManager Changes


Modifying setSecurityManager()?
├─ YES: Consider conditional validation
│       ├─ Trusted class? Skip some checks
│       └─ Custom class? Full defense-in-depth
│
├─ Adding new trusted class?
│       └─ Update trustedSMClass() + document why
│
└─ Adding validation layer?
        └─ Document in JavaDoc + SECURITY_ANALYSIS.md


---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.1 | 2026-04-09 | Added conditional validation strategy documentation |
| 1.0 | 2026-04-09 | Initial Claude development guide |

---

**Last Updated:** April 9, 2026  
**Maintained By:** Project Security Team  
**Status:** Active

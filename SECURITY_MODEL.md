# Dirty Chai Security Model

**Version:** 2.0  
**Date:** 2026-04-16  
**Project:** Dirty Chai  
**Repository:** https://github.com/pfirmstone/DirtyChai

---

## 1) Purpose and Scope

Dirty Chai extends OpenJDK authorization behavior to enforce policy-based least privilege with stronger controls around class loading, caller validation, and privilege boundaries.

This document covers the active model implemented in:

- `java.lang.System`
- `java.security.AccessController`
- `au.zeus.jdk.authorization.policy.ConcurrentPolicyFile`
- `au.zeus.jdk.authorization.sm.CombinerSecurityManager`
- `au.zeus.jdk.authorization.guards.*`

---

## 2) Core Security Guarantees

1. **Fail-secure defaults**: validation failures deny access (exception or unprivileged state).
2. **Least privilege**: permissions must be explicitly granted by policy.
3. **No trust transfer**: dependencies are evaluated independently.
4. **Policy-driven principal enforcement**: principal checks apply when grants include `principal` clauses.
5. **Caller-sensitive privilege boundaries**: privileged APIs retain caller-sensitive behavior.
6. **URI-validated code source matching**: policy matching relies on RFC 3986 URI handling.

---

## 3) High-Level Architecture

1. Application invokes security-sensitive operation.
2. `SecurityManager.checkPermission(...)` delegates to policy evaluation.
3. `AccessController` computes effective context (stack + inherited + explicit context).
4. `ConcurrentPolicyFile` resolves grants by code source, signer, principal, and permission implication.
5. Permission decision is enforced (allow/deny).

---

## 4) SecurityManager Installation Model (`System.setSecurityManager`)

Dirty Chai uses **conditional validation** when installing a SecurityManager.

### Trusted implementations (exact class match)

`trustedSMClass(sm)` trusts only:

- `java.lang.SecurityManager`
- `au.zeus.jdk.authorization.sm.CombinerSecurityManager`
- `au.zeus.jdk.authorization.sm.PolicyOnlySecurityManager`

For these classes, Dirty Chai applies the trusted path and avoids full custom-stack hardening.

### Custom implementations (all other classes)

For non-trusted classes, Dirty Chai applies layered checks before installation:

1. Direct caller check (`@CallerSensitive` + caller lookup)
2. Stack inspection via `StackWalker` (reflection/method-handle/generated-frame detection)
3. Caller `ProtectionDomain` validation
4. Generated/synthetic caller rejection

If any layer fails, installation is blocked with `SecurityException`.

### Important operational note

`SecurityPolicyWriter` is intentionally **not** in the trusted whitelist and is for audit/staging workflows, not production enforcement.

---

## 5) AccessController and Privilege Boundaries

Dirty Chai keeps `AccessController` and `doPrivileged` semantics active for authorization use.

- `doPrivileged(...)` establishes bounded privilege elevation.
- `doPrivilegedWithCombiner(...)` preserves combiner/domain behavior.
- Effective permissions are constrained by the active `AccessControlContext` and policy grants.

Security depends on minimizing privileged blocks and scoping them to the smallest operation necessary.

---

## 6) Policy Model (`ConcurrentPolicyFile`)

Policy decisions are computed from:

- **CodeSource** (location/signer)
- **Principals** (when grant clauses require them)
- **Permission implication rules**

### Default posture

- No matching grant => denied.
- Invalid or unmatched inputs do not gain privileges.

### Principal semantics

- Grants **without** principal clauses can apply without authenticated Subject identity.
- Grants **with** principal clauses require matching Subject principals.

This makes principal enforcement configurable by policy rather than globally forced.

---

## 7) Class Loading and Authorization

Dirty Chai introduces authorization-aware class loading controls (including `LoadClassPermission`) to reduce unauthorized code execution risk.

Security posture assumes:

- class loading is policy-controlled,
- code source and signer identity can be policy-constrained,
- ungranted code paths fail closed.

---

## 8) Virtual Threads and Subject Context

Dirty Chai preserves authorization behavior with virtual threads by carrying effective context through standard Java security context mechanisms.

`Subject.callAs(...)` and `Subject.doAs(...)` remain available and participate in principal-aware authorization flows where policy requires principals.

---

## 9) Threats Addressed

- Reflection/proxy/generated-code attempts to bypass SecurityManager installation controls
- Privilege escalation via overly broad or inherited permission assumptions
- Policy bypass through malformed/ambiguous code source handling
- Unauthorized execution through missing grant constraints

---

## 10) Non-Goals / Limitations

- Dirty Chai is an authorization and policy-enforcement model, not a complete malware sandbox by itself.
- Misconfigured policy can still over-grant privileges.
- Operational security still requires key management, signer governance, secure build pipelines, and review discipline.

---

## 11) Recommended Deployment Pattern

1. **Stage/Audit** with `polpAudit` (`SecurityPolicyWriter`) to discover required permissions.
2. Review and narrow grants (remove over-broad file/socket/all-permission entries).
3. **Production** with strict policy and SecurityManager enabled.
4. Keep policy and signer trust material under change control and audit.

---

## 12) Security Invariants (Must Hold)

1. Trusted SecurityManager checks use exact class identity, not subclass trust.
2. Custom SecurityManager installation requires all validation layers.
3. Privileged execution must remain caller-sensitive and context-bounded.
4. Policy evaluation must remain deny-by-default.
5. Validation failures must remain fail-secure.

---

## 13) Related Documents

- `SECURITY_ANALYSIS.md` (detailed findings and historical fixes)
- `STACK_VALIDATION_ANALYSIS.md` (stack-validation trade-offs)
- `VULNERABILITIES_ADDRESSED.md` (resolved issues)
- `SECURITY.md` (security policy and reporting)


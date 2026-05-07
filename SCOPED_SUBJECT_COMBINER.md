# SCOPED_SUBJECT Capture in SubjectDomainCombiner

## Overview

Java provides two independent mechanisms for propagating a `Subject` (identity) into code
that runs on a thread:

| Mechanism | API | Storage | Affects policy grants? |
|-----------|-----|---------|------------------------|
| ACC path | `Subject.doAs()` / `Subject.doAsPrivileged()` | `AccessControlContext` + `SubjectDomainCombiner` | **Yes** — principals are injected into `ProtectionDomain` instances during policy evaluation |
| ScopedValue path | `Subject.callAs()` | `SCOPED_SUBJECT` (`ScopedValue<Subject>`) | **No** — accessible only via `Subject.current()`; not visible to policy evaluation |

When used independently these mechanisms are well-defined. The problem arises when they
are **nested together**.

---

## The Dual-Identity Gap

### Scenario

A common real-world pattern in a multi-tenant service is:

```
Subject.callAs(humanUser, () -> {
    // humanUser is now the "current" subject — visible to Subject.current()

    Subject.doAsPrivileged(workloadIdentity, sensitiveAction, null);
    // sensitiveAction runs with an ACC containing SubjectDomainCombiner(workloadIdentity)
});
```

During `sensitiveAction`:

- The `AccessControlContext` carries a `SubjectDomainCombiner` constructed with `workloadIdentity`.
- `SCOPED_SUBJECT` is bound to `humanUser` (installed by `callAs()`).
- When the `SecurityManager` evaluates a permission check, it calls
  `SubjectDomainCombiner.combine()`, which injects principals into each
  `ProtectionDomain` being evaluated.

### The Missing Merge

`SubjectDomainCombiner.combine()` only sees the `Subject` it was **constructed** with
(`workloadIdentity`). It has no mechanism to read `SCOPED_SUBJECT` and therefore
**never injects `humanUser` principals into the ProtectionDomains**.

Consequence: any policy grant conditioned on a `humanUser` principal is silently not
applied, even though the code is logically executing on behalf of that user.

---

## Why `Subject.current()` Cannot Be Called from `combine()`

The obvious fix — calling `Subject.current()` inside `combine()` to read
`SCOPED_SUBJECT` — is not safe when a `SecurityManager` is installed.

`Subject.current()` contains:

```java
java.lang.SecurityManager sm = System.getSecurityManager();
if (sm != null) {
    sm.checkPermission(AuthPermissionHolder.GET_SUBJECT_PERMISSION);
}
return SCOPED_SUBJECT.isBound() ? SCOPED_SUBJECT.get() : null;
```

`SecurityManager.checkPermission()` triggers policy evaluation. Policy evaluation calls
`SubjectDomainCombiner.combine()`. Calling `Subject.current()` from inside `combine()`
therefore causes **infinite mutual recursion**, terminating with a `StackOverflowError`.

---

## Why `SCOPED_SUBJECT` Was `private`

In OpenJDK, `Subject.SCOPED_SUBJECT` is declared `private static final`. This ensures
that the `ScopedValue` binding (the "current user" for the thread) can only be read
through the guarded public API `Subject.current()`, which enforces the
`AuthPermission("getSubject")` check. Keeping it private prevents external code from
observing scope state without the required permission.

---

## The Fix

### Change 1 — `Subject.java`: relax visibility to package-private

```java
// Before (OpenJDK upstream)
private static final ScopedValue<Subject> SCOPED_SUBJECT = ScopedValue.newInstance();

// After (DirtyChai)
static final ScopedValue<Subject> SCOPED_SUBJECT = ScopedValue.newInstance();
```

Both `Subject` and `SubjectDomainCombiner` are in the `javax.security.auth` package
inside the `java.base` module. The module is sealed; no external code can reside in
this package. Making `SCOPED_SUBJECT` package-private therefore exposes it only to
`SubjectDomainCombiner` — trusted `java.base` infrastructure — and does not widen
access beyond the module boundary.

### Change 2 — `SubjectDomainCombiner.java`: read and merge in `getMergedPrincipals()`

```java
import static javax.security.auth.Subject.SCOPED_SUBJECT;

private Principal[] getMergedPrincipals() {
    Set<Principal> merged = new HashSet<>();

    // 1. ACC Subject principals (e.g., SPIFFE workload identity)
    if (subject.isReadOnly()) {
        for (Principal p : principals) merged.add(p);
    } else {
        merged.addAll(subject.getPrincipals());
    }

    // 2. SCOPED_SUBJECT principals (e.g., human user from callAs())
    //    Direct access — no AuthPermission check — this is trusted java.base code.
    //    Subject.current() cannot be used here because it calls checkPermission(),
    //    which would re-enter combine() and cause a StackOverflowError.
    Subject scopedSubject = SCOPED_SUBJECT.isBound() ? SCOPED_SUBJECT.get() : null;
    if (scopedSubject != null) {
        merged.addAll(scopedSubject.getPrincipals());
    }

    return merged.toArray(new Principal[0]);
}
```

The `AuthPermission("getSubject")` guard in `Subject.current()` protects **external**
callers. Inside `java.base` infrastructure the permission check is neither required nor
safe; the direct read of the `ScopedValue` is the correct approach.

---

## Security Properties of the Fix

### What is preserved

- **External access is unchanged.** `SCOPED_SUBJECT` remains inaccessible outside the
  `java.base` module. External code must still go through `Subject.current()` and its
  permission check.
- **Fail-secure when `SCOPED_SUBJECT` is unbound.** `ScopedValue.isBound()` returns
  `false` when no `callAs()` scope is active; `getMergedPrincipals()` falls through
  with only the ACC Subject's principals — identical to the previous behaviour.
- **No recursive permission evaluation.** The `SCOPED_SUBJECT` read is a direct
  `ScopedValue` get; it does not invoke the `SecurityManager`.

### What is gained

- **Principal completeness.** When `callAs()` and `doAs()`/`doAsPrivileged()` are
  nested, `combine()` now injects principals from **both** the workload identity and
  the human-user identity into each `ProtectionDomain`.
- **Policy correctness.** Grants conditioned on human-user principals (e.g., a role
  principal from a `LoginContext`) are evaluated and applied when elevated privileges
  are also in effect.

---

## Caching Constraint

The constructor caches ACC Subject principals for read-only `Subject` instances:

```java
// Cache ACC Subject principals only (not SCOPED_SUBJECT —
// that changes per request and must be read in combine())
if (subject.isReadOnly()) {
    principals = subject.getPrincipals().toArray(new Principal[0]);
}
```

`SCOPED_SUBJECT` must **never** be cached in the constructor because:

1. The `SubjectDomainCombiner` instance is created once per `doAs()` call and may
   outlive the `callAs()` scope that installed `SCOPED_SUBJECT`.
2. Different `callAs()` scopes may run with the same `SubjectDomainCombiner` instance
   (e.g., if the ACC is reused across requests).
3. Capturing `SCOPED_SUBJECT` at construction time would bind the wrong user to
   subsequent requests — a principal-leakage security defect.

Reading `SCOPED_SUBJECT` on every `combine()` invocation (hot path) is correct and
necessary.

---

## Summary Table

| Aspect | Before fix | After fix |
|--------|-----------|-----------|
| `SCOPED_SUBJECT` visibility | `private` (inaccessible outside `Subject`) | `package-private` (accessible within `javax.security.auth`) |
| `getMergedPrincipals()` reads SCOPED_SUBJECT | No | Yes — direct `ScopedValue` read |
| `callAs()` + `doAs()` nesting: user principals in ProtectionDomains | Missing | Present |
| Recursive `checkPermission()` risk | N/A | Avoided — no SM call in `getMergedPrincipals()` |
| External API behaviour | Unchanged | Unchanged |

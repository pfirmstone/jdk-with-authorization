# Implementation Plan: `DigestCodeSource` and `DigestGrant`

## Goal

Enable JGDMS JERI to transmit an `AccessControlContext` (ACC) through remote
endpoints in a way that correctly identifies code by content-hash, not just by
URL.  Every `ProtectionDomain` on the stack must carry a `DigestCodeSource` so
the remote receiver can reconstruct an equivalent ACC.

Use `SecureClassLoader` as the integration point (not the `ProtectionDomain`
constructors directly) so that `LoadClassPermission` is checked before a domain
is created, preserving the existing security gate.

---

## 1 – `java.security.DigestCodeSource`

**File:** `src/java.base/share/classes/java/security/DigestCodeSource.java`

A new public final class in the `java.security` package that extends
`CodeSource`.

### Fields

| Field | Type | Purpose |
|---|---|---|
| `digestAlgorithm` | `String` (e.g. `"SHA-256"`) | Which hash algorithm produced the value |
| `digest` | `byte[]` (defensive copy) | Content hash of the code artifact |
| `uri` | `Uri` (transient) | RFC 3986 normalised form of the URL for DNS-free equality |
| `hashCode` | `int` (cached) | Stable hash across all fields |

### Constructors

```
DigestCodeSource(URL url, Certificate[] certs,
                 String digestAlgorithm, byte[] digest)

DigestCodeSource(URL url, CodeSigner[] signers,
                 String digestAlgorithm, byte[] digest)

// Convenience: promote a plain CodeSource, computing no digest.
DigestCodeSource(CodeSource cs, String digestAlgorithm, byte[] digest)
```

### Key behaviour

* `hashCode()` – hashes `Uri` (not URL, to avoid DNS), certificates, algorithm
  name, and digest bytes.
* `equals(Object)` – compares `Uri`, certificates, algorithm, and digest with
  `Arrays.equals`.  Uses `Uri.urlToUri(url)` in the same way that
  `DomainIdentity.UriCodeSource` does, falling back to `super.equals()` if URI
  conversion throws.
* `getDigestAlgorithm()` / `getDigest()` – public accessors; `getDigest()`
  returns a defensive copy.
* **Serialization** – implements Externalizable, providing custom read/write
  methods for the digest fields, including those of CodeSource.
  The digest fields are appended to the stream after the CodeSource fields.
  Fields must be written out as byte arrays (not hex strings) to avoid unnecessary encoding overhead.
  Fields may be null, a suitable header must be written to the stream to indicate presence/absence of fields,
  including those in CodeSource.
  JGDMS JERI must be able to reconstruct a `DigestCodeSource` from the stream, so the format must be stable across versions.
  Standard Java Serialization (i.e. `Serializable`) is not supported, @AtomicSerial does support Externalizable classes, that do not
  that only send primitive data, String's or byte arrays.  Serializable objects are not supported by @AtomicSerial.
* `implies(CodeSource)` – if the argument is also a `DigestCodeSource` with the
  same algorithm, equality of digest is required in addition to the normal
  location/cert checks; otherwise delegates to `super.implies()`.

### Why `java.security`

`DigestCodeSource` is set into `ProtectionDomain` and must be visible across
all modules.  Placing it in `java.security` follows the same rationale as
`CodeSource`, `ProtectionDomain`, and `DomainIdentity`.

---

## 2 – `SecureClassLoader` changes

**File:** `src/java.base/share/classes/java/security/SecureClassLoader.java`

`SecureClassLoader.getProtectionDomain(CodeSource cs)` is the single place
where `ProtectionDomain` objects are created for loaded classes and where
`LoadClassPermission` is already checked.

### Change: honour `DigestCodeSource` directly

When the incoming `cs` is already a `DigestCodeSource`, use it as-is as the
key and as the domain's code-source:

```
CodeSourceKey key = new CodeSourceKey(cs);
// existing cache lookup …
ProtectionDomain pd = new ProtectionDomain(
        cs,           // ← DigestCodeSource flows through unchanged
        perms, SecureClassLoader.this, pals);
```

The `CodeSourceKey` record already delegates comparison to
`CodeSource.matchCerts` and `getLocationNoFragString()`, which are overridden
in `DigestCodeSource`, so caching remains correct.

### Change: `CodeSourceKey` equality for `DigestCodeSource`

Override `CodeSourceKey.equals` to additionally compare `digestAlgorithm` and
`digest` when both keys wrap a `DigestCodeSource`, so two class loads from
different artifact versions at the same URL produce distinct domains.

---

## 3 – `DigestGrant` in `org.apache.river.api.security`

**File:** `src/java.base/share/classes/org/apache/river/api/security/DigestGrant.java`

A new package-private class extending `CertificateGrant`.

### Implication semantics

```
DigestGrant.implies(ProtectionDomain pd)
  1. If pd == null → false
  2. Run super.implies(pd) (CertificateGrant: principal + cert checks)
  3. Extract pd.getCodeSource()
     a. If not a DigestCodeSource → false
        (the grant is digest-specific; plain CodeSource is not implied)
     b. If algorithm names differ → false
     c. If !Arrays.equals(this.digest, dcs.getDigest()) → false
  4. Return true
```

`implies(CodeSource, Principal[])` follows the same pattern.

`implies(ClassLoader, Principal[])` – returns `false` (indeterminate, same
as `CertificateGrant`).

### Constructor

```
DigestGrant(String digestAlgorithm, byte[] digest,
            Certificate[] certs, String[] aliases,
            Principal[] pals, Permission[] perms)
```

### Serialization

Uses the same serialization-proxy pattern as all other `PermissionGrant`
implementations: `writeReplace()` delegates to `getBuilderTemplate()` which
returns a `PermissionGrantBuilderImp`; `readObject()` throws
`InvalidObjectException`.

---

## 4 – `PermissionGrantBuilder` / `PermissionGrantBuilderImp`

**Files:**
* `src/java.base/share/classes/org/apache/river/api/security/PermissionGrantBuilder.java`
* `src/java.base/share/classes/org/apache/river/api/security/PermissionGrantBuilderImp.java`

### New constant

```java
/** Grant applies to DigestCodeSource with matching algorithm + digest. */
public static final int DIGEST = 6;
```

Update `PermissionGrantBuilderImp.context(int)` range check to accept `<= 6`.

### New state fields (in `PermissionGrantBuilderImp`)

```java
/*@serial */ private String digestAlgorithm;
/*@serial */ private byte[] digest;
```

### New builder methods (in `PermissionGrantBuilder`)

```java
public abstract PermissionGrantBuilder digest(String algorithm, byte[] digestValue);
```

Implemented in `PermissionGrantBuilderImp`:

```java
public PermissionGrantBuilder digest(String algorithm, byte[] value) {
    this.digestAlgorithm = algorithm;
    this.digest = value != null ? value.clone() : null;
    return this;
}
```

### `build()` switch case

```java
case DIGEST:
    return new DigestGrant(digestAlgorithm, digest,
                           certs, aliases, principals, permissions);
```

### `reset()`

Add `digestAlgorithm = null; digest = null;` to the existing reset body.

---

## 5 – Policy scanner/parser changes (optional, phase 2)

The initial implementation does not require policy-file syntax for
`DigestGrant`.  Grants are created programmatically by JGDMS JERI when
reconstructing an ACC at the remote endpoint.

If policy-file support is desired in a later phase, the following is the
recommended approach.

### Scanner token (`DefaultPolicyScanner.GrantEntry`)

Add an optional `digest` field:

```
grant codebase "http://example.com/foo.jar",
      digest "SHA-256:a1b2c3…" { … };
```

`GrantEntry` gains `private final String digest;` (a colon-separated
`algorithm:hexEncodedValue` string, or `null`).

### Parser (`DefaultPolicyParser.resolveGrant`)

When `ge.getDigest()` is non-null, parse the colon-separated pair, hex-decode
the value, call `.digest(algorithm, bytes)` on the builder, and set context to
`PermissionGrantBuilder.DIGEST`.

---

## 6 – `DigestGrant.getBuilderTemplate()`

```java
@Override
public PermissionGrantBuilder getBuilderTemplate() {
    PermissionGrantBuilder pgb = super.getBuilderTemplate();   // cert + principals + perms
    pgb.digest(digestAlgorithm, digest)
       .context(PermissionGrantBuilder.DIGEST);
    return pgb;
}
```

---

## 7 – JGDMS JERI integration notes

These notes are for the JGDMS implementor; no DirtyChai source changes are
required here.

When JERI serialises an ACC for remote transmission it must:

1. Iterate the **complete** `ProtectionDomain[]` obtained via
   `JavaSecurityAccess.getProtectDomains(acc)`.  Transmit *every* domain, not
   only the `DigestCodeSource` ones.  Codebase domains are subtractive in the
   AND-across-domains check, so omitting one drops a constraint and *elevates*
   privilege (fail-open).  Send the full reducing set; never prune it.
2. For each domain serialise the codebase URL and certificates.  Capture the
   content digest from **either** source:
   - a `DigestCodeSource` (its `digestAlgorithm` + `digest` fields), or
   - an `httpmd:` URL parameter (`…;sha-256=…`) on an ordinary `CodeSource`.
   A domain with neither is still serialised — it crosses as a reducer with no
   verified code identity (treated worst-case on receipt, never dropped).
   Principals are carried too, but the receiver honours only those the
   connection authenticated (see step 4).
3. On the remote side, reconstruct each domain.  For a digest-bearing domain
   reconstruct a `DigestCodeSource` (or look one up from a local cache keyed on
   the digest) so the reconstructed ACC preserves code identity; for a
   digest-less domain reconstruct an ordinary `CodeSource` — still included, as
   a reducer.
4. Score the reconstructed domains against the receiver's **static** policy —
   they reduce *within* that ceiling and are **not** a source of dynamic grants.
   Inbound call authorization makes no dynamic grants.  A `DigestGrant` in the
   static policy may match a digest-bearing domain to give it the authority the
   policy assigns that digest; a digest-less domain receives only the URL-scoped
   operational permissions static policy already allows for its URL.  A claimed
   digest that does **not** verify is an attack signal — reject the call, do not
   strip-and-proceed.  A known-vulnerable digest may be blocklisted outright.
   Principals contribute to grant matching only when the connection
   authenticated them; an unauthenticated baked-in principal keeps its (reducing)
   codebase but adds no principal.

`DigestGrant` created via `PermissionGrantBuilder` remains the mechanism for the
separate **proxy-loading** path (dynamic `Security.grant` at proxy preparation,
client or server), which is distinct from the inbound-authorization path above.
See `JGDMS-STD-003` §10.4–§10.5 and
`JGDMS/docs/DESIGN-spiffe-authorization-acc-transmission-2026-06-27.md` §3 for
the full receiving-side model.

---

## 8 – Invariants and security properties

| Property | How it is maintained |
|---|---|
| Fail-secure on digest mismatch | `DigestGrant.implies` returns `false`; no privileges are granted |
| No DNS in equality | `DigestCodeSource.equals` uses `Uri`, not `URL.equals` |
| Digest is immutable | `getDigest()` returns a defensive copy; field is `private final` |
| `LoadClassPermission` always checked | `DigestCodeSource` enters via `SecureClassLoader.getProtectionDomain`, which already calls `sm.checkPermission(LOAD_CLASS_ALLOW, …)` |
| Serialization safety | `DigestCodeSource` follows `CodeSource` serialization protocol; extra fields appended, never prepended |
| No subclass bypass | `DigestGrant.implies(CodeSource)` checks `instanceof DigestCodeSource`; a plain `CodeSource` subclass cannot satisfy a digest grant |

---

## 9 – Files to create / modify

| Action | File |
|---|---|
| **Create** | `src/java.base/share/classes/java/security/DigestCodeSource.java` |
| **Create** | `src/java.base/share/classes/org/apache/river/api/security/DigestGrant.java` |
| **Modify** | `src/java.base/share/classes/java/security/SecureClassLoader.java` |
| **Modify** | `src/java.base/share/classes/org/apache/river/api/security/PermissionGrantBuilder.java` |
| **Modify** | `src/java.base/share/classes/org/apache/river/api/security/PermissionGrantBuilderImp.java` |
| **Modify (phase 2)** | `src/java.base/share/classes/au/zeus/jdk/authorization/policy/DefaultPolicyScanner.java` |
| **Modify (phase 2)** | `src/java.base/share/classes/au/zeus/jdk/authorization/policy/DefaultPolicyParser.java` |

---

**Policy Compliance:** All contributions in this PR are human-written and comply
with the [OpenJDK Interim Policy on Generative AI](openjdk_ai_policy.md)
adopted by DirtyChai.

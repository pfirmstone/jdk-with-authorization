# Problems Solved by JGDMS and DirtyChai

**Last Reviewed:** 2026-07-01

This document catalogues the engineering problems that the **JGDMS** distributed-services
framework and the **DirtyChai** OpenJDK fork solve, organised by problem area
(deserialization, serialization, class resolution, versioning, security, and so on). For each
area it shows what the problem is, how each project addresses it, and where the relevant code
lives.

---

## How the Two Projects Fit Together

The two projects are different layers of the same stack:

| Layer | Project | Role |
|-------|---------|------|
| **Distributed framework** | [JGDMS](https://github.com/pfirmstone/JGDMS) | Secure, dynamically discoverable micro-services over IPv6: serialization, remote invocation, discovery, activation, proxy trust. |
| **Platform (JVM)** | [DirtyChai](https://github.com/pfirmstone/DirtyChai) | OpenJDK fork that retains and hardens Java's Authorization infrastructure (SecurityManager / AccessController / Policy) and the enforcement *guards* that JGDMS depends on. |

```
          ┌─────────────────────────────────────────────┐
          │ Application services (Reggie, Outrigger, …)  │
          ├─────────────────────────────────────────────┤
          │ JGDMS framework                              │
          │  • @AtomicSerial + DER serialization        │
          │  • JERI remote invocation + constraints     │
          │  • Discovery (multicast/unicast, IPv6)      │
          │  • Phoenix activation / process isolation   │
          │  • Proxy trust, bootstrap proxies, httpmd   │
          ├─────────────────────────────────────────────┤
          │ DirtyChai platform (java.base)              │
          │  • SecurityManager / AccessController kept   │
          │  • ConcurrentPolicyFile (from JGDMS)         │
          │  • LoadClass / SerialObject / Native perms  │
          │  • RFC 3986 Uri, fail-secure CodeSource     │
          │  • PolicyWriter audit tool (from JGDMS)      │
          └─────────────────────────────────────────────┘
```

Two facts drive the relationship:

1. **JGDMS cannot run on stock modern Java.** Upstream OpenJDK removed the `SecurityManager`
   API in Java 24, and authorization is *foundational* to JGDMS — it is how independent but
   cooperating parties limit each other's privileges. JGDMS therefore supports only Java ≤ 23
   on stock JVMs; DirtyChai removes that ceiling by keeping (and improving) the authorization
   layer.
2. **DirtyChai's authorization tooling came from JGDMS.** `ConcurrentPolicyFile`, the
   `SecurityPolicyWriter` (`polpAudit`) least-privilege tool, and the `PermissionGrant` /
   `ScalableNestedPolicy` API surface were developed in JGDMS (originally Apache River) and
   have been pushed down into `java.base`. DirtyChai is, in part, JGDMS's authorization layer
   relocated into the platform — plus new platform-only guards.

**A shared non-goal:** neither project tries to *sandbox untrusted code*. The aim is to
ensure that users exercise only the code you intended, with the least privilege required, and
to break attack chains — not to safely execute hostile bytecode. (For untrusted-code
sandboxing, both projects point developers to GraalVM/Espresso process isolation instead.)

---

## Problem Index

| # | Problem area | JGDMS contribution | DirtyChai contribution |
|---|--------------|--------------------|------------------------|
| 1 | Unsafe deserialization | `@AtomicSerial` pre-construction validation | `SerialObjectPermission` class allowlist |
| 2 | Cross-platform serialization | Deterministic, polyglot DER codec | — |
| 3 | Class resolution / loading | Per-endpoint ClassLoader resolution, separate proxy streams | `LoadClassPermission`, split-package compat |
| 4 | Codebase integrity & versioning | `httpmd` URLs, bootstrap + smart proxies | `DigestCodeSource` content stamping, `DigestGrant`, RFC 3986 `Uri` |
| 5 | Remote method invocation | JERI pluggable transport/invocation | (platform RMI/serialization guards) |
| 6 | Per-method security constraints | `InvocationConstraints`, constrainable proxies | (authorization mechanism beneath them) |
| 7 | Service discovery | Authenticated IPv6 multicast/unicast | RFC 3986 URIs, no DNS in policy path |
| 8 | Authorization & policy | Remote/revocable policy, Subject-per-scope (`ScopedValue`) | Retained + hardened `Policy`/`AccessController` |
| 9 | Process & proxy isolation | Phoenix activation groups, BAE/VerdictRegistry | Per-service policy enforcement |
| 10 | Transport security | TLSv1.3 endpoints, method constraints | (TLS stack remains platform-provided) |
| 11 | Native code (JNI/FFM) boundary | — | `NativeInvocationPermission`, `NativeMemoryPermission` |
| 12 | URI handling / DNS removal | RFC3986 `Uri`, no DNS calls | RFC 3986/5952/6874 `Uri`, no DNS in `CodeSource` |
| 13 | Performance & scalability | Lock-free collections, fast classloader | <1% authorization overhead, no DNS, no perm cache |
| 14 | Platform survival | — | Keeps SecurityManager alive past Java 24 |

---

## 1. Unsafe Deserialization

**The problem.** Java's built-in serialization runs attacker-influenced logic *during*
object reconstruction: it can instantiate arbitrary classes, drive "gadget chains" to remote
code execution (Log4Shell, ysoserial), exhaust memory through circular references, and leak a
reference to a partially-constructed object before its invariants have been checked.

**JGDMS — validate before you construct.** The `@AtomicSerial` framework inverts the model:
every annotated class provides a public `(GetArg)` constructor that calls a static
`check(GetArg)` *before any field is assigned*. If invariants cannot be satisfied, no instance
is created and therefore no reference can be stolen ("atomic" = atomic failure). The
`GetArg` accessor memoises reads so a hostile subclass cannot return different values on the
second look. At the wire level, `AtomicMarshalInputStream`/`AtomicMarshalOutputStream` enforce
these rules, and the `Valid` helper class provides defensive copying and null/element checks.

> *"Atomic stands for atomic failure, if invariants cannot be satisfied an instance cannot be
> created and hence a reference cannot be stolen."* — `AtomicSerial.java`

**DirtyChai — control which classes may deserialize at all.** `SerialObjectPermission`
implements a deserialization *allowlist*. The check runs in
`ObjectInputStream.readOrdinaryObject()` *before* object instantiation (Issue #85), so even
ordinary default-`Serializable` gadget paths are covered. Combined with `PolicyWriter`, which
records every class actually deserialized during a staging run, an administrator can deny all
classes by default and permit only the observed set.

The two layers are complementary: DirtyChai decides *whether a class may be deserialized*;
JGDMS guarantees that *if it is, its invariants hold before any reference escapes*.

| | JGDMS | DirtyChai |
|---|---|---|
| Mechanism | `@AtomicSerial`, `(GetArg)` constructor, `AtomicMarshalInputStream`, `Valid` | `SerialObjectPermission` allowlist in `readOrdinaryObject()` |
| Location | `jgdms-platform/.../org/apache/river/api/io/AtomicSerial.java`, `Valid.java`; `jgdms-jeri/.../io/AtomicMarshalInputStream.java` | `au/zeus/jdk/authorization/guards/SerialObjectPermission.java` |

---

## 2. Deterministic, Cross-Platform Serialization (DER)

**The problem.** Java's native serialization is JVM-only and non-deterministic: the same object
graph can encode to different byte sequences (handle/back-reference ordering, platform-specific
details), so encodings are neither reproducible nor directly comparable, and no non-Java peer
can read them. That blocks polyglot interoperability, content-hashing of serialized state, and
tamper-evident wire formats.

**JGDMS — a language-neutral, canonical, atomic codec.** The `jgdms-der` module (per the
internal JGDMS-STD-006 standard) provides a DER (X.690) wire-format codec for `@AtomicSerial`
objects, with three properties:

- **Language-neutral / polyglot** — the package is a *"Language-neutral DER (X.690) wire-format
  codec"*. DER/X.690 is a widely-implemented ASN.1 encoding, so the same objects can be encoded
  and decoded by non-Java peers, not only JVM-to-JVM.
- **Deterministic / canonical** — DER admits exactly one valid encoding per value: no handle
  table (a pure value-tree, encoded by value), canonical IEEE-754 (normalised NaN and `-0.0`),
  and minimal TLV lengths. The same state therefore always yields the same bytes, so encodings
  are reproducible and directly hashable.
- **Atomic** — decoding flows through a `GetArg` field store (`DerGetArg` / `DerFieldStore`), so
  invariants are validated *before* construction, exactly as on the `@AtomicSerial` stream path
  (§1). A malformed or non-canonical encoding is rejected (`DerException`) rather than partially
  materialised.

Each type also carries an `AtomicSerialSchemaRecord` with a SHA-256 Merkle-chain schema digest,
and a `DerMarshalledInstance` embeds its authoritative schema — giving versioned,
integrity-checked wire types. Because the encoding is canonical, those schema and content
digests are stable, which dovetails with the codebase digest/reproducibility work in §4.

| | JGDMS |
|---|---|
| Mechanism | DER (X.690) TLV codec (`DerReader`/`DerWriter`), `DerGetArg`/`DerFieldStore`, `AtomicSerialSchemaRecord` (Merkle-chain digest), `DerMarshalledInstance` |
| Location | `jgdms-der/.../au/net/zeus/jgdms/der/` (per JGDMS-STD-006) |

---

## 3. Class Resolution and Class Loading

**The problem.** Java RMI's global `RMIClassLoader` does not isolate downloaded classes by
codebase, endpoint, or security context, so proxies from different sources can collide and
untrusted code can be forced into a trusted loader. Separately, historic JDK `ClassLoader`s
assigned permissions to the code they loaded — trusting the developer to vet URLs — which is
exactly the assumption JNDI/Log4Shell violated.

**JGDMS — make the ClassLoader responsible for resolution, one per endpoint.** The fix is
architectural. JERI does *not* try to reconstruct class visibility from codebase annotations
carried in-band in the marshalling stream (the RMI/JRMP model). Instead, **a ClassLoader is
assigned at each endpoint and is solely responsible for class resolution there** — it alone
determines which classes are visible. (As the JGDMS README puts it, JERI "doesn't attempt to
duplicate the role of ClassLoaders; instead ClassLoaders are assigned at endpoints and these
are used to determine class visibility.") `ProxyCodebaseSpi.resolve()` selects or creates that
loader at the endpoint (with a short-TTL cache), verifying codebase integrity before creating a
new one.

Equally important, **a proxy's serialized form is kept separate from the stream it travels
over.** A smart proxy is transmitted as a self-contained marshalled instance carrying its own
codebase, and is resolved by its endpoint's ClassLoader as a unit — unlike RMI, where codebase
annotations are interleaved with application data in a single stream and resolution then depends
on the call stack. JGDMS's `RFC3986URLClassLoader` (in `jgdms-pref-class-loader`) is also
substantially faster than the JDK's built-in `URLClassLoader`.

*Preferred classes* (`PreferredClassProvider`, `META-INF/PREFERRED.LIST`) were the earlier
(Jini 2.0) step in this direction — loading designated classes without delegating to the parent
first — but the mechanism that actually solves class resolution is placing responsibility at the
per-endpoint ClassLoader, as above.

**JERI sidesteps the classic RMI class-loading pitfalls.** Michael Warres's Sun Labs report
*Class Loading Issues in Java RMI and Jini Network Technology* (SMLI TR-2006-149, 2006 —
bundled in the repo at `jgdms-platform/.../net/jini/loader/smli_tr-2006-149.pdf`) catalogues the
failure modes of the standard `RMIClassLoader` model. JERI avoids their root causes by the
endpoint-ClassLoader model above: resolution is the responsibility of the loader assigned to the
endpoint — the **defining loader of the proxy (client side) or exported object (server side)** —
rather than RMI/JRMP's heuristic of "the closest non-bootstrap loader on the call stack", and a
proxy is resolved as a unit from its own marshalled stream rather than from in-band annotations
mixed into the application data.

| RMI class-loading pitfall (Warres §4) | How JERI / JGDMS avoids it |
|---|---|
| **Type conflicts** — classes from different codebases are distinct, incompatible types | Each proxy's classes resolve in the single ClassLoader assigned to its endpoint, not scattered across sibling loaders driven by in-stream annotations; public API types stay shared abstract interfaces |
| **Codebase annotation loss** — relaying an object through an intermediary drops its source URL | The proxy travels as a self-contained marshalled instance with its own codebase, separate from the transport stream — there is no in-band annotation to lose when it is relayed |
| **Codebase annotation mixing** — mixed local/downloaded object graphs split across loaders | Each proxy resolves as a unit in its endpoint ClassLoader, so a graph is not split across sibling loaders by mixed in-stream annotations |
| **Undesired local class resolution** — delegation silently prefers a local class over the intended remote implementation | Resolution is the endpoint ClassLoader's responsibility, keyed to the proxy's defining loader — not the call stack or parent-first delegation |
| **Codebase content changes** — stale classes reach clients (loader-table retention, `jar:` caching) | Content-addressed `httpmd` URLs (and DirtyChai `DigestCodeSource`, §4) make identity change with content, so stale bytes cannot silently match |
| **Codebase configuration / availability** — error-prone, separately-configured `java.rmi.server.codebase` channel | The codebase is obtained from the authenticated service via its bootstrap proxy / `CodebaseAccessor`, not a hand-set `java.rmi.server.codebase` property |

The report (2006) predates this design: it analyses *preferred classes* as a partial fix and
notes (§5.4) they do not by themselves eliminate type conflicts. JGDMS's later move — making a
per-endpoint ClassLoader solely responsible for resolution, with each proxy carried in its own
marshalled stream — is what removes the in-band-annotation root cause the report describes.

**DirtyChai — make code loading a policy decision.** `LoadClassPermission` lets policy
whitelist which code sources (HTTP origins, JAR signers) may be loaded, instead of trusting
URL data. DirtyChai also removes the static permission grants that `URLClassLoader` and friends
used to apply, handing full control to `Policy` and the administrator. As it builds each
`ProtectionDomain`, `SecureClassLoader` also stamps the loaded artifact with a SHA-256 content
digest (see §4). Finally, DirtyChai's
modified `BuiltinClassLoader` supports the deliberate `org.apache.river.api.security`
split-package so existing JGDMS deployments resolve platform API contracts first while their
own classes still load from the classpath.

| | JGDMS | DirtyChai |
|---|---|---|
| Mechanism | Per-endpoint ClassLoader resolution (`ProxyCodebaseSpi`), separate proxy marshalled streams, `ClassLoading`, `RFC3986URLClassLoader`; `PreferredClassProvider`/`PreferredClassLoader` (earlier mechanism) | `LoadClassPermission`, removal of static loader grants, split-package fallthrough |
| Location | `jgdms-pref-class-loader/.../net/jini/loader/pref/`, `jgdms-platform/.../net/jini/loader/ClassLoading.java` | `au/zeus/jdk/authorization/guards/LoadClassPermission.java`, `BuiltinClassLoader` (see `JGDMS_COMPATIBILITY.md`) |

---

## 4. Codebase Integrity and Versioning

**The problem.** A client downloading a service proxy needs to know it received the *right*,
*untampered* code — RMI offers no integrity check on a codebase, no way to verify a version,
and no defence against an attacker substituting a malicious proxy.

**JGDMS — pin code by digest, defer trust.**
- **`httpmd` URLs** embed a message digest directly in the URL
  (`httpmd://host/service.jar;sha256=…`); `MdInputStream` verifies the bytes match as they are
  read and throws `WrongMessageDigestException` otherwise.
- **Bootstrap proxy → smart proxy separation.** `SafeServiceRegistrar.lookUp()` returns a
  lightweight *bootstrap proxy* (implementing `RemoteMethodControl`, `ServiceProxyAccessor`,
  `ServiceAttributesAccessor`, `CodebaseAccessor`) that lets the client authenticate the
  service and read attributes *before* downloading and deserializing the full smart proxy.
  `DownloadPermission` and `DeSerializationPermission` are granted only after trust is
  established.
- **Constraint baking** (3.1.1 constrainable proxies): method constraints are baked into the
  server stub at construction and re-verified on deserialization via
  `ConstrainableProxyUtil.verifyConsistentConstraints()`, so a stream that tampers with
  constraints in only one place is rejected.

**DirtyChai — content-addressed code identity at the platform.** Three mechanisms:

- *URL trustworthiness.* The RFC 3986 `Uri` class rejects path-traversal and encoding tricks
  that could spoof a `CodeSource`; validation failures fail secure (null `CodeSource` →
  unprivileged); and codebase comparison uses URI string matching rather than DNS resolution,
  removing a rebinding/TOCTOU window.
- *Content stamping.* `SecureClassLoader.getProtectionDomain()` promotes every located
  `CodeSource` to a `java.security.DigestCodeSource` by computing a SHA-256 digest of the
  artifact's content — walking every module entry via `ModuleReader` for `jrt:`/`jmod:` URLs, or
  reading the stream directly for `file:`/remote URLs — *before* the `LoadClassPermission` check.
  The per-domain cache key includes the digest, so two artifact *versions* served from the same
  URL produce distinct `ProtectionDomain`s. `DigestGrant` then matches permissions to code by
  content hash rather than location alone: a tampered or wrong-version JAR served from a trusted
  URL fails the digest comparison and is denied (fail-secure). Because `DigestCodeSource` is
  `Externalizable` in an `@AtomicSerial`-compatible layout, the digest travels on the
  `ProtectionDomain`, letting JGDMS JERI transmit an `AccessControlContext` that identifies code
  by content across remote endpoints.
- *API versioning.* DirtyChai re-exports the JGDMS authorization contracts from `java.base` so
  existing JGDMS binaries keep running without recompilation.

**Build-time complement — deterministic JARs.** Content digests are only stable if the same
source always produces the same bytes. `net.pack200.Normalize` (from the companion
`Pack200-ex-openjdk` project — a library replacement for the `jar --normalize` flag OpenJDK
removed in JDK 15 / JEP 367) produces a reproducible JAR whose SHA-256 depends only on the input
class/resource bytes, not on timestamps, entry order, or filesystem attributes, and supports
sign-then-pack workflows. Normalised, reproducible artifacts are what make `httpmd` digests and
`DigestCodeSource`/`DigestGrant` matching meaningful and repeatable across builds and machines.
The same determinism underlies the DER codec (§2), so serialized state and packaged code share
one reproducibility story.

| | JGDMS | DirtyChai |
|---|---|---|
| Mechanism | `httpmd` handler + `MdInputStream`, bootstrap/smart proxy split, `CodebaseAccessor`, constraint baking | `DigestCodeSource` content stamping in `SecureClassLoader`, `DigestGrant`, RFC 3986 `Uri`, fail-secure `CodeSource`, re-exported compatibility contracts |
| Location | `jgdms-url-integrity/.../net/jini/url/httpmd/`, `jgdms-lib-dl/.../proxy/AbstractSmartProxy.java`, `ConstrainableProxyUtil.java` | `java/security/DigestCodeSource.java`, `java/security/SecureClassLoader.java`, `org/apache/river/api/security/DigestGrant.java`, `au/zeus/jdk/net/Uri.java`; see `DIGEST_GRANT_PLAN.md`, `JGDMS_COMPATIBILITY.md` |
| Build tool | — | `net.pack200.Normalize` (`Pack200-ex-openjdk`) for reproducible JARs |

---

## 5. Remote Method Invocation (JERI)

**The problem.** Java RMI's invocation protocol is fixed. Its `RMISocketFactory` /
`RMIClientSocketFactory` hooks let you replace the *socket* layer — so TLS can be slipped
underneath the transport (e.g. `SslRMIClientSocketFactory`/`SslRMIServerSocketFactory`) — but
the wire protocol carried over those sockets (JRMP), its marshalling, and its dispatch are *not*
replaceable, and there is no hook for per-method security. Changing the invocation layer itself
means forking RMI.

**JGDMS — a pluggable invocation stack.** JERI (Jini Extensible Remote Invocation) separates
three independently swappable layers:
- **Transport** — `Endpoint`/`ServerEndpoint` implementations: `Tcp`, `Ssl`, `Kerberos`,
  `Http`, `Https`.
- **Invocation** — `InvocationLayerFactory` implementations (`AbstractILFactory`,
  `ProxyTrustILFactory`, `AtomicILFactory`) build matching client `InvocationHandler` /
  server `InvocationDispatcher` pairs.
- **Dispatch** — `BasicInvocationDispatcher` / `AtomicInvocationDispatcher` check constraints,
  unmarshal (using `AtomicMarshalInputStream` when `AtomicInputValidation` is set), enforce
  per-method permissions, and invoke the target.

A distinctive property: **every server-side dispatch thread carries the authenticated JAAS
`Subject` of the caller** for the lifetime of the call, so services get principal-based,
per-method access control with no boilerplate. JGDMS reports JERI outperforms Java RMI. Beyond
the protocol, JERI's class-resolution model also avoids the classic RMI class-loading pitfalls
(type conflicts, codebase annotation loss/mixing, unwanted local resolution) — see §3.

**DirtyChai — the trust substrate beneath JERI.** JERI's `checkClientPermission()` builds a
`ProtectionDomain` from the caller's principals and evaluates it against the policy — which is
exactly the `AccessController`/`Policy` machinery DirtyChai keeps alive and accelerates.

| | JGDMS | DirtyChai |
|---|---|---|
| Mechanism | `Endpoint`/`ServerEndpoint`, `InvocationLayerFactory`, `*InvocationDispatcher`, Subject-per-thread | `AccessController`, `Policy`, principal-based permission evaluation |
| Location | `jgdms-jeri/.../net/jini/jeri/` | `java/security/AccessController.java`, `ConcurrentPolicyFile.java` |

---

## 6. Per-Method Security Constraints

**The problem.** A custom RMI socket factory can encrypt a stub's traffic, but only
all-or-nothing for the whole stub — RMI cannot express that *this particular method* requires
client authentication or integrity, nor negotiate such a need as a requirement versus a
preference. Security becomes ad-hoc boilerplate, inconsistently applied.

**JGDMS — declarative invocation constraints.** `InvocationConstraints` separates mandatory
*requirements* from best-effort *preferences*. Constraint types include
`ServerAuthentication`, `ClientAuthentication`, `Confidentiality`, `Integrity`,
`ConfidentialityStrength.STRONG`, and `AtomicInputValidation`. A client attaches them via
`RemoteMethodControl.setConstraints(MethodConstraints)`; the endpoint checks them before
opening an `OutboundRequest` and throws `UnsupportedConstraintException` *before any bytes
leave the client JVM* if they cannot be met. Constrainable proxies translate constraints
between proxy-visible and server-side method names (`ConstrainableProxyUtil`).

**DirtyChai — the authorization decisions behind the constraints.** Enforcing a constraint
such as "only this principal may call this method" ultimately resolves to a permission check;
DirtyChai supplies the retained, hardened permission/policy mechanism that makes such
principal-conditioned grants meaningful.

| | JGDMS | DirtyChai |
|---|---|---|
| Mechanism | `InvocationConstraint(s)`, `MethodConstraints`, `RemoteMethodControl`, constrainable proxies | `Policy`/`Permission` evaluation, principal grants |
| Location | `jgdms-platform/.../net/jini/core/constraint/`, `jgdms-lib-dl/.../proxy/` | `au/zeus/jdk/authorization/` |

---

## 7. Service Discovery

**The problem.** Classic Jini multicast/unicast discovery had no authentication: a node could
spoof lookup-service announcements and redirect clients to a hostile service, with no integrity
check and weak IPv6 support.

**JGDMS — authenticated, integrity-checked discovery.** A pluggable SPI
(`DiscoveryFormatProvider`) offers formats spanning plaintext (legacy), TLS + SHA-224/256/384/512
hash verification, X.500 + digital signature (DSA/RSA/ECDSA variants), and Kerberos. Unicast
discovery runs over TLSv1.3 and the client verifies a digest over the `UnicastResponse` before
accepting it, defeating MITM response-substitution. Multicast discovery uses IPv6 with X.500
distinguished names and hash-function integrity checks.

**DirtyChai — keeps discovery's matching DNS-free.** Because discovery and policy matching use
RFC 3986 URIs rather than DNS resolution, the platform removes a class of rebinding/DoS
vectors from the codepaths discovery relies on.

| | JGDMS | DirtyChai |
|---|---|---|
| Mechanism | `DiscoveryFormatProvider` SPI, `UnicastDiscovery{Client,Server}`, hash/X.500/Kerberos formats | RFC 3986 URI matching, no DNS lookups |
| Location | `jgdms-discovery-providers/.../org/apache/river/discovery/` | `au/zeus/jdk/net/Uri.java` |

---

## 8. Authorization and Policy

**The problem.** The stock `Policy` is heavily synchronised, performs DNS during
`CodeSource.implies`, caches decisions (risking staleness), and cannot be updated at runtime.
And upstream Java removed authorization entirely in Java 24.

**JGDMS — dynamic, principal-aware authorization.**
- `ConcurrentPolicyFile` — lock-free, cache-free, high-throughput `Policy`.
- `RemotePolicyProvider` — grant permissions dynamically (e.g. to a freshly authenticated
  service) without a restart.
- `RevocablePolicy` — revoke grants at runtime (River added revocation via GC of unused grants).
- JAAS Subject-based grants: the user `Subject` is bound via `Subject.callAs()` (a `ScopedValue`
  that survives `doPrivileged`) and is folded into the effective `AccessControlContext` by
  `SubjectDomainCombiner.currentAll()` inside `AccessController.getContext()` — it is not carried
  on the ACC. `Security.getCurrentPrincipals()` / `GrantPermission.checkGuard()` read those bound
  principals into the check. Following OSGi's lead, a service can bundle the
  permissions it needs and have them granted automatically after authentication, still bounded
  by the administrator.

**DirtyChai — retain and harden the mechanism in the platform.**
- Keeps `SecurityManager`/`AccessController` and ships `ConcurrentPolicyFile` as the platform
  policy provider.
- Reimplements `AccessController.doPrivileged(...)` with `Permission` arguments to *reduce*
  privileges to a stated set (rather than granting full caller privileges), capturing the
  caller as a `jrt:/module/class` domain for debuggability.
- Makes `AccessControlContext` immutable and caches instances (needed for virtual-thread
  support).
- Carries the bound user `Subject` on a `ScopedValue` and folds it centrally in
  `AccessController.getContext()` (which `checkPermission` routes through), instead of attaching a
  `SubjectDomainCombiner` to the `doAs`/`doAsPrivileged` `AccessControlContext` as upstream OpenJDK
  does. Consequence: the stock `SecurityManager` and `CombinerSecurityManager` fold the bound
  subject identically, and `acc.getDomainCombiner()` is `null` by design. The ambient SPIFFE
  `WorkerSubject` is never folded by this path (it reaches `ProtectionDomain`s via class-load
  stamping / the verified TLS peer chain) and is rejected by `doAs`/`doAsPrivileged`/`callAs`;
  multi-party `callAs` binding is conjunctive (a multi-principal grant fires only when all bound
  principals are co-present — `PrincipalGrant.containsAll`).
- This rework exposed and fixed (2026-07-01) a latent inherited defect: `AccessControlContext.optimize()`
  carried an old OpenJDK shortcut dereferencing `acc.context[0]` that upstream never reached with an
  empty assigned context (its combiner-on-ACC routed `optimize()` down a different branch). With the
  combiner gone, `Subject.doAsPrivileged(subject, action, null)` — an empty assigned context
  (`NULL_PD_ARRAY`) — hit `[0]` on a zero-length array → `ArrayIndexOutOfBoundsException` on the first
  permission check inside the action, under the production `SecurityManager`. Guarded with
  `acc.context.length > 0`; DirtyChai-only, never affected stock OpenJDK. Regression:
  `qa/jtreg/org/apache/river/api/security/doAsPrivNullAcc`.
- `setSecurityManager(null)` throws `IllegalArgumentException`, so an injected privileged
  context cannot disable enforcement; custom SecurityManagers pass layered caller/stack/domain
  checks before installation.
- `SecurityPolicyWriter` (`polpAudit`, ported from JGDMS) auto-generates least-privilege policy
  by observing what an app actually requests in staging.

| | JGDMS | DirtyChai |
|---|---|---|
| Mechanism | `ConcurrentPolicyFile`, `RemotePolicyProvider`, `RevocablePolicy`, Subject-based grants, `GrantPermission` | Retained `SecurityManager`/`AccessController`, reduced-privilege `doPrivileged`, immutable `AccessControlContext`, `ScopedValue` subject-fold at `getContext()` (no combiner on the ACC), `SecurityPolicyWriter` |
| Location | `jgdms-platform/.../org/apache/river/api/security/` | `java/security/`, `javax/security/auth/Subject.java`, `au/zeus/jdk/authorization/policy/`, `.../tool/SecurityPolicyWriter.java` |

---

## 9. Process and Proxy Isolation

**The problem.** Running every service in one JVM means one compromised or buggy service can
corrupt others; permission checks alone cannot terminate a hostile thread or contain
shared-memory damage.

**JGDMS — isolate trust domains into separate processes.** Phoenix (the Jini `rmid`
equivalent) runs each `ActivationGroup` as a separate OS process with its own policy file, and
persists state in a crash-safe `ReliableLog`. The (under-development) codebase-safety tier puts
the Bytecode Analysis Engine in a dedicated, network-restricted group that scans downloaded
JAR constant pools for dangerous APIs and submits a *signed* verdict to a separate
`VerdictRegistry`, which applies a quorum policy with fail-safe `DANGEROUS` propagation. At the
proxy level, the bootstrap/smart-proxy split keeps untrusted proxy code out of the client until
trust is verified.

**DirtyChai — least privilege within each process.** Inside any one JVM, DirtyChai's guards
(`LoadClassPermission`, `SerialObjectPermission`, `NativeInvocationPermission`, thread-creation
permissions) plus per-service policy files minimise what a compromised service can reach.
DirtyChai is explicit that in-process enforcement cannot stop resource exhaustion,
shared-memory corruption, side channels, or `Unsafe`/JNI escapes — which is precisely why it
recommends layering JGDMS process isolation on top.

| | JGDMS | DirtyChai |
|---|---|---|
| Mechanism | Phoenix activation groups, `ReliableLog`, BAE + `VerdictRegistry` quorum, bootstrap proxies | Per-service least-privilege policy, in-process guards |
| Location | `phoenix-activation/`, `services/bytecode-analysis-engine/`, `services/verdict-registry/` | `au/zeus/jdk/authorization/guards/`; see `PROCESS_ISOLATION.md` |

---

## 10. Transport Security

**The problem.** RPC over untrusted networks needs confidentiality, integrity, and mutual
authentication, expressed per call rather than globally.

**JGDMS — TLSv1.3 endpoints driven by constraints.** `SslEndpoint`/`SslServerEndpoint`
provide stateless encrypted endpoints supporting `ServerAuthentication`, `ClientAuthentication`,
`Confidentiality`, `Integrity`, and `ConfidentialityStrength.STRONG`; `FilterX509TrustManager`
adds validation beyond the JDK default, and HTTP proxies are rejected by default for SSL
endpoints. Kerberos endpoints provide GSSAPI authentication, with per-user connection keying so
different users never share a connection.

**DirtyChai — provides the underlying TLS/JSSE stack** unchanged, while ensuring the
credentials and keystores those endpoints use are themselves access-controlled (e.g. property
and key access gated by policy).

| | JGDMS | DirtyChai |
|---|---|---|
| Mechanism | `SslEndpoint`, `KerberosEndpoint`, `FilterX509TrustManager`, constraint enforcement | Platform JSSE; property/credential permission gating |
| Location | `jgdms-jeri/.../net/jini/jeri/ssl/`, `.../kerberos/` | platform `javax.net.ssl`, `au/zeus/jdk/authorization/` |

---

## 11. Native Code (JNI / FFM) Boundary

**The problem.** Native code bypasses all Java-level guards; the Foreign Function & Memory API
makes off-heap memory and native symbol resolution broadly reachable.

**DirtyChai (platform-only).** Two new guards control the native boundary:
- `NativeInvocationPermission` gates native symbol resolution (`ClassLoader.findNative`,
  `SymbolLookup`, `SystemLookup`).
- `NativeMemoryPermission` gates off-heap access (`Arena.global()`,
  `MemorySegment.reinterpret*()`).

This is a problem only the platform can solve; JGDMS inherits the protection by running on
DirtyChai.

| | DirtyChai |
|---|---|
| Mechanism | `NativeInvocationPermission`, `NativeMemoryPermission` |
| Location | `au/zeus/jdk/authorization/guards/` |

---

## 12. URI Handling and DNS Removal

**The problem.** Permission decisions that depend on DNS are slow, non-deterministic, and open
to rebinding attacks; lax URL parsing enables path-traversal/encoding tricks that match
unintended policy grants.

**Both layers, shared lineage.** The RFC 3986 `Uri` (with RFC 5952 and RFC 6874 support)
originated in JGDMS and is present in DirtyChai. URLs are compared as normalised strings, not
resolved to IP addresses, eliminating DNS from the policy `implies` path. Even string
case-folding was reduced to bit-shift operations after profiling identified it as a hotspot in
URI normalisation. DirtyChai additionally moved `SocketPermission` canonical-host resolution to
an eager init step to remove a DNS-based DoS vector from access checks.

| | JGDMS | DirtyChai |
|---|---|---|
| Mechanism | RFC3986 `Uri`, no DNS in discovery/policy | RFC 3986/5952/6874 `Uri`, no DNS in `CodeSource`, eager `SocketPermission` init |
| Location | `jgdms-platform/.../org/apache/river/api/net/Uri.java` | `au/zeus/jdk/net/Uri.java` |

---

## 13. Performance and Scalability

**The problem.** The 1990s-era security implementations were written for single-threaded
machines: synchronised, contended, DNS-bound. Authorization acquired a reputation for being
slow.

**JGDMS.** Lock-free concurrent collections, an RFC3986 URL classloader faster than the
built-in one, atomic serialization that outperforms standard Java serialization, JERI that
outperforms RMI, and a lookup method that delays or avoids unnecessary codebase downloads.

**DirtyChai.** `ConcurrentPolicyFile` is designed for high-throughput concurrent access with
**no permission cache** (caching limits scalability and risks staleness) and **no DNS calls**;
all identified hotspots in URI normalisation were removed. Reported authorization overhead is
**under 1%**.

---

## 14. Platform Survival (Java 24 SecurityManager Removal)

**The problem.** Upstream OpenJDK deprecated and then removed `SecurityManager`, on the grounds
that too few developers used it to justify the maintenance burden. That removal makes
authorization-dependent frameworks like JGDMS unrunnable on modern Java.

**DirtyChai's reason for existing.** It keeps the authorization infrastructure alive,
modernises it (virtual-thread support, immutable contexts, RFC 3986 URIs, reduced-privilege
`doPrivileged`), maintains the guard hooks throughout the JDK, and supplies tooling
(`PolicyWriter`) so least-privilege policy is practical rather than trial-and-error. The longer
-term goal is a community redesign of the Authorization API as a preview feature for eventual
return to the mainline.

---

## Division of Responsibility (Summary)

| Concern | Solved primarily by |
|---------|---------------------|
| Safe object construction during deserialization | **JGDMS** (`@AtomicSerial`) |
| Deterministic, language-neutral (polyglot) wire format | **JGDMS** (DER codec, `jgdms-der`) |
| Which classes may be deserialized | **DirtyChai** (`SerialObjectPermission`) |
| Per-endpoint class visibility / isolation | **JGDMS** (per-endpoint ClassLoader, separate proxy streams) |
| Which code sources may load code | **DirtyChai** (`LoadClassPermission`) |
| Codebase integrity (digest-pinned download) | **JGDMS** (`httpmd`, bootstrap proxies) |
| Content-addressed code identity (digest-stamped domains) | **DirtyChai** (`DigestCodeSource` / `DigestGrant`) |
| Reproducible JAR bytes for stable digests | **`net.pack200.Normalize`** (Pack200-ex-openjdk) |
| Codebase URL validation / no DNS | **Both** (RFC 3986 `Uri`) |
| Pluggable, constraint-driven RPC | **JGDMS** (JERI) |
| Per-method security constraints | **JGDMS** (`InvocationConstraints`) |
| Authenticated discovery (IPv6) | **JGDMS** |
| Dynamic / revocable / remote policy | **JGDMS**, now in **DirtyChai** (`ConcurrentPolicyFile`) |
| Keeping SecurityManager/AccessController alive | **DirtyChai** |
| Native (JNI/FFM) boundary control | **DirtyChai** |
| Process isolation between trust domains | **JGDMS** (Phoenix) |
| Least-privilege policy generation | **JGDMS** tool, now in **DirtyChai** (`PolicyWriter`/`polpAudit`) |

---

## Out of Scope (Non-Goals)

Neither project attempts to **sandbox untrusted code**. The model is: vet and audit code
before deployment (static analysis + `PolicyWriter`), then run *approved* code under least
privilege so that a flaw in it has minimal reachable attack surface. In-process permission
checks also cannot, by design, address: resource exhaustion by an already-running thread,
carrier-thread starvation, shared-memory corruption, side channels, or escapes via
`Unsafe`/JNI/FFM/JVMTI. Those require the layered defence both projects recommend — per-service
policy, process isolation (JGDMS activation groups), and OS/network controls.

---

## References

**DirtyChai (this repository):**
- `README.md` — overview, key features, hardening roadmap
- `VULNERABILITIES_ADDRESSED.md` — vulnerability-by-vulnerability mitigation catalogue
- `SECURITY_MODEL.md`, `SECURITY_ANALYSIS.md` — threat model and validation layers
- `JGDMS_COMPATIBILITY.md` — re-exported contracts, split-package handling
- `DIGEST_GRANT_PLAN.md` — `DigestCodeSource` / `DigestGrant` design and integration
- `PROCESS_ISOLATION.md` — what in-process enforcement can and cannot do
- `PHILOSOPHY.md`, `PERFORMANCE_ANALYSIS.md` — design rationale and benchmarks

**JGDMS (`../JGDMS`):**
- `README.md` — security feature summary
- `ARCHITECTURE.md` — module map, JERI, Phoenix, codebase-safety tier
- `SERVICE_AND_PROXY_LIFE_CYCLES.md`, `PROXY_ISOLATION.md` — discovery and proxy lifecycles
- Source: `jgdms-platform/`, `jgdms-jeri/`, `jgdms-der/`, `jgdms-pref-class-loader/`,
  `jgdms-url-integrity/`, `jgdms-discovery-providers/`, `phoenix-activation/`

**Companion tooling (`../Pack200-ex-openjdk`):**
- `net.pack200.Normalize` — reproducible JAR normalisation (`Options.reproducible()`),
  replacing the `jar --normalize` flag removed by JEP 367; `docs/normalize.md`

**External:**
- Warres, *Class Loading Issues in Java RMI and Jini Network Technology* (Sun Labs
  SMLI TR-2006-149, 2006) — catalogues the RMI class-loading failure modes JERI avoids; bundled
  at `JGDMS/jgdms-platform/src/main/java/net/jini/loader/smli_tr-2006-149.pdf`
- RFC 3986 (URI), RFC 5952 (IPv6 text), RFC 6874 (IPv6 zone IDs)
- X.690 (ASN.1 BER/CER/DER encoding rules)
- JEP 367 (removal of Pack200 tools and API)
- CVE-2021-44228 (Log4Shell); ysoserial; OWASP Deserialization Cheat Sheet

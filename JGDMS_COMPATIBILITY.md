# JGDMS Compatibility on Dirty Chai

**Last Reviewed:** 2026-04-23

Dirty Chai re-exports key JGDMS authorization API contracts from the platform `java.base` module so existing JGDMS applications can run without recompilation.

## Re-exported API Surface

Dirty Chai provides the following types in `org.apache.river.api.security`:

- `ScalableNestedPolicy` (interface)
- `PermissionGrant` (abstract class)
- `PermissionGrantBuilder` (interface)

These are the compatibility contracts used by JGDMS policy components and by Dirty Chai's authorization implementation.

## ClassLoader Hierarchy and Automatic Substitution

At runtime, class resolution follows parent-first delegation:

1. Bootstrap / platform loaders are consulted first.
2. Application ClassLoader is consulted afterward.

Because Dirty Chai defines the compatibility contracts in `java.base`, references to these API types resolve to the platform definitions automatically. JGDMS implementation classes loaded by the application ClassLoader can still implement and use these same contracts transparently.

Result: JGDMS applications run on Dirty Chai without recompilation while using Dirty Chai's policy engine behavior.

## `defineClassInPackage` Permission Considerations

JGDMS publishes additional classes in `org.apache.river.api.security`. When those classes are defined by application loaders under an active `SecurityManager`, package-definition checks may require:

- `RuntimePermission "defineClassInPackage.org.apache.river.api.security"`

This is not a practical blocker for deployment workflows because Dirty Chai's `SecurityPolicyWriter` (`-Djava.security.manager=polpAudit`) automatically discovers required grants during staged execution and appends them to policy output for review.

In other words, package-definition permissions are handled by the normal least-privilege audit cycle rather than by manual guesswork.

## Deployment Workflow for JGDMS Applications

1. Run the application in staging with `polpAudit` enabled.
2. Exercise real startup and operational paths so required permissions are observed.
3. Review generated policy output, tighten broad grants where needed.
4. Deploy with `-Djava.security.manager=default` and a reviewed policy file.

This workflow preserves least privilege and captures any required `defineClassInPackage` grants automatically.

## Performance Benefits for JGDMS Workloads

When running on Dirty Chai, JGDMS applications benefit from:

- Lock-free policy evaluation in `ConcurrentPolicyFile`
- Reduced contention through concurrent and cached permission checks
- RFC 3986 URI-based matching (no DNS lookups in policy implication path)
- Optimizations for virtual-thread and high-concurrency workloads

Since compatibility contracts are resolved from the platform loader, these performance gains are available without recompiling JGDMS code.

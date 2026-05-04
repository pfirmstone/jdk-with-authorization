# JGDMS Compatibility on Dirty Chai

**Last Reviewed:** 2026-05-03

Dirty Chai re-exports key JGDMS authorization API contracts from the platform `java.base` module so existing JGDMS applications can run without recompilation.

## Re-exported API Surface

Dirty Chai provides the following types in `org.apache.river.api.security`:

* `ScalableNestedPolicy` (interface)
* `PermissionGrant` (abstract class)
* `PermissionGrantBuilder` (interface)

These are the compatibility contracts used by JGDMS policy components and by Dirty Chai's authorization implementation.

## Split Package: `org.apache.river.api.security`

The package `org.apache.river.api.security` is intentionally split between `java.base` and the unnamed module (classpath). This is a deliberate design decision, not an oversight.

Classes in this package that require privileged access to platform internals — for example, `SocketPermission.init()` and other security-sensitive APIs — cannot reside in a named application module because the platform access they require is only granted to code in `java.base`. These classes are therefore defined in `java.base` in Dirty Chai.

However, JGDMS has historically published additional classes in this same package — such as `AbstractPolicy` — that have no relevance to Dirty Chai's platform implementation but must remain loadable by the application classloader for binary compatibility with existing JGDMS deployments.

## ClassLoader Hierarchy and the Split Package Exemption

The Java Platform Module System (JPMS) prohibits split packages between two **named** modules. However, the unnamed module (classpath) is explicitly exempt from this prohibition — this is a deliberate JPMS concession for backward compatibility, documented in the Java module system specification.

Dirty Chai takes advantage of this exemption. `org.apache.river.api.security` is owned by `java.base` as a named module, but additional classes in the same package can still be loaded from the classpath via the unnamed module. Dirty Chai modifies `BuiltinClassLoader.loadClassOrNull()` to support this: when the platform loader cannot find a class in `java.base` for this specific package, loading falls through to the application classpath rather than failing. The check is gated precisely on the package name `org.apache.river.api.security` so no other module-owned package is affected.

Class resolution at runtime therefore works as follows:

1. `AppClassLoader.loadClassOrNull()` finds `org.apache.river.api.security` in `packageToModule`, owned by `java.base`.
2. It delegates to the platform loader.
3. The platform loader searches `java.base` — classes defined there (e.g. `PermissionGrant`, `ScalableNestedPolicy`, `PermissionGrantBuilder`) are returned immediately, preserving platform precedence.
4. For classes not present in `java.base` (e.g. `AbstractPolicy`), the platform loader returns `null`.
5. Dirty Chai's modified `BuiltinClassLoader` detects the null result for this package and falls through to the application classpath, where the JGDMS JAR is found.

Platform types always take precedence. Classpath classes in this package can never shadow or replace types already defined in `java.base`.

## Security Considerations

Allowing classpath classes to be loaded into a module-owned package is a controlled relaxation of the default JPMS split-package prohibition. The security implications are:

* Classpath classes in `org.apache.river.api.security` are loaded by the application classloader into the **unnamed module** — they do not gain any platform module permissions.
* They cannot replace or shadow the platform types in `java.base`, which are always resolved first.
* In a Dirty Chai deployment using `LoadClassPermission`, the policy controls which code sources are permitted to define classes at all, providing a meaningful defence-in-depth layer that makes the relaxed split-package behaviour safe in practice.
* The fallthrough in `BuiltinClassLoader` is gated on an exact package name match, minimising the scope of the exemption to only the affected package.

## Future Modularisation of JGDMS

If JGDMS is later modularised, the split package constraint must be respected: two **named** modules cannot share a package. The recommended approach is:

* Modularise the bulk of JGDMS as a named module (e.g. `org.apache.river.api`) with its own packages.
* Keep the `org.apache.river.api.security` classes that require platform access, or that exist solely for binary compatibility with the classpath, in a **separate unnamed JAR on the classpath**.

This preserves the unnamed module exemption indefinitely and keeps privileged platform-access code physically separated from the rest of the JGDMS module graph — which is desirable from an audit and least-privilege perspective regardless of the compatibility requirement. The `BuiltinClassLoader` modification in Dirty Chai remains valid under this arrangement without further changes.

## `defineClassInPackage` Permission Considerations

JGDMS publishes additional classes in `org.apache.river.api.security`. When those classes are defined by application loaders under an active `SecurityManager`, package-definition checks may require:

* `RuntimePermission "defineClassInPackage.org.apache.river.api.security"`

This is handled by the normal least-privilege audit cycle. Dirty Chai's `SecurityPolicyWriter` (`-Djava.security.manager=polpAudit`) automatically discovers required grants during staged execution and appends them to policy output for review.

## Obtaining a Pre-Built DirtyChai JDK

A pre-built linux-x64 release JDK is published as a rolling GitHub Release
whenever the **Build JDK for JGDMS** workflow is run.

### Download URL

```
https://github.com/pfirmstone/DirtyChai/releases/download/dirty-chai-latest/jdk-linux-x64.tar.gz
```

A SHA-256 checksum file is also published alongside the bundle:

```
https://github.com/pfirmstone/DirtyChai/releases/download/dirty-chai-latest/jdk-linux-x64.tar.gz.sha256
```

### Verification and installation (shell)

```sh
wget -q https://github.com/pfirmstone/DirtyChai/releases/download/dirty-chai-latest/jdk-linux-x64.tar.gz
wget -q https://github.com/pfirmstone/DirtyChai/releases/download/dirty-chai-latest/jdk-linux-x64.tar.gz.sha256
sha256sum -c jdk-linux-x64.tar.gz.sha256
mkdir -p dirty-chai-jdk
tar -xf jdk-linux-x64.tar.gz -C dirty-chai-jdk --strip-components=1
export DIRTY_CHAI_JAVA_HOME="$(pwd)/dirty-chai-jdk"
"$DIRTY_CHAI_JAVA_HOME/bin/java" -version
```

### Using DirtyChai as the JDK in a JGDMS Maven/Gradle build

Point your build tool at the DirtyChai JDK by setting `JAVA_HOME` before
invoking the build:

```sh
export JAVA_HOME="$DIRTY_CHAI_JAVA_HOME"
mvn test            # Maven
./gradlew test      # Gradle
```

Or pass it explicitly to Maven:

```sh
mvn -Djvm="$DIRTY_CHAI_JAVA_HOME/bin/java" test
```

### Triggering a fresh build

The workflow can be triggered manually from the **Actions** tab of the
DirtyChai repository:

1. Navigate to **Actions → Build JDK for JGDMS**.
2. Click **Run workflow**.
3. Wait for the run to complete (typically 30–60 minutes).
4. The `dirty-chai-latest` release is updated automatically.

---

## Deployment Workflow for JGDMS Applications

1. Run the application in staging with `polpAudit` enabled.
2. Exercise real startup and operational paths so required permissions are observed.
3. Review generated policy output, tighten broad grants where needed.
4. Deploy with `-Djava.security.manager=default` and a reviewed policy file.

## Performance Benefits for JGDMS Workloads

When running on Dirty Chai, JGDMS applications benefit from:

* Lock-free policy evaluation in `ConcurrentPolicyFile`
* Reduced contention through concurrent and cached permission checks
* RFC 3986 URI-based matching (no DNS lookups in policy implication path)
* Optimisations for virtual-thread and high-concurrency workloads

Since compatibility contracts are resolved from the platform loader, these performance gains are available without recompiling JGDMS code.

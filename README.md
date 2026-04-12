# OpenJDK with Authorization (SecurityManager)
This project's objectives are to maintain a community fork of OpenJDK that retains Authorization functionality. No attempt will be made to sandbox untrusted code; instead, the goals of the project are:
- Prevent loading of untrusted code.
- Prevent gadget attack chains from completing.
- Prevent injection attacks, e.g., whitelist URLs.
- Maintain guard hooks throughout OpenJDK for permission checks and add additional ones where necessary.
- Research improvements to Authorization.
- High performance and scalability.
- Provide a workable practical implementation to improve Java security against injection-style attacks using POLP whitelisting, rather than theoretical vaporware.
- People interested in sandboxing untrusted code should consider investigating Graal Expresso [GraalVM Expresso](https://www.graalvm.org/latest/reference-manual/espresso/).

## Principle of Least Privilege Policy Writer
- This tool automates the writing of your policy files using principles of least privilege, creating a minefield of SecurityExceptions for attackers to navigate inside your perimeter defenses.
- Permissions will not be granted to load transitive dependencies or modules you don't use; Serialization will be limited to only the classes used in your deployment staging environment.

### In your deployment staging environment, run your program with the following command line options:
-Djava.security.manager=polpAudit,\
-DpolpAudit.path.properties=${your.path}audit.properties,

### Other system properties you should set:
- java.security.policy
- javax.net.ssl.trustStore
- javax.net.ssl.trustStoreType
- javax.net.ssl.trustStorePassword

### Auditing
- Audit your policy file for possible security issues.
- Deploy using your automatically generated and audited policy files.
- When auditing your policy files, identify permissions with limited scope that will need expanding, such as FilePermission for temporary files or SocketPermission.
- Run the auditing tool multiple times, each time marking where the last policy was updated; this will help identify permissions that require a wider scope as these permissions will be added each audit test cycle.

### Deploy with high scaling, efficient implementations of SecurityManager and Policy.
-Djava.security.manager=default,
-Djava.security.policy==path/security.policy
- Unlike PolicyFile, with double equals "==" specified in "java.security.policy," ConcurrentPolicyFile doesn't also include `<JAVA_HOME>/lib/security/default.policy`.
- `<JAVA_HOME>/lib/security/default.policy` contains a lot of AllPermission grants, which are undesirable. For now, they remain for testing purposes; however, this policy should contain only minimal permissions, if any.

## Development
- The trunk branch is where our development occurs; we branch off and rebase to trunk in our development branches.

### What Makes JDK-with-Authorization Compelling:

1. **Enterprise Security Gap**
   - Modern Java lacks fine-grained authorization (SecurityManager is deprecated).
   - JDK-with-Authorization uses an RFC 3986-compliant, defense-in-depth approach.
   - Target: Enterprises requiring strict access control (financial, healthcare, government).

2. **Zero-Trust Architecture Ready**
   - Multi-layer validation (caller, stack, CodeSource, policy).
   - Perfect for high-security deployments.
   - Target: Organizations implementing zero-trust security models.

3. **Compliance & Audit Requirements**
   - Fine-grained permission controls enable compliance tracking.
   - Target: Regulated industries (fintech, healthcare, critical infrastructure).

4. **Performance-Conscious**
   - ConcurrentPolicyFile designed for high-throughput.
   - No caching overhead.
   - Target: High-performance systems requiring authorization.

## Suggested Customer Segments

| Segment | Use Case | Pain Point |
|---------|----------|-----------|
| **Financial Services** | Microservices security | No fine-grained Java auth |
| **Healthcare (HIPAA)** | Access control compliance | Audit trail requirements |
| **Government (Federal)** | FedRAMP/DoD compliance | Defense-in-depth mandates |
| **Critical Infrastructure** | Nuclear, power, water | Zero-trust requirements |
| **Cloud Platforms** | Container orchestration | Tenant isolation |
| **Defense Contractors** | Security-critical systems | TS/SCI requirements |

## Vulnerabilities Addressed
- JNDI LDAP dynamic code downloading and object serialization (root cause of Log4j vulnerability), secured without disablement or removal of functionality. By removing static permission grants in ClassLoader's, i.e., URLClassLoader, policy can instead whitelist allowed URLs by granting URLPermission, restrict dynamic code to signed jar files using LoadClassPermission, and limit object serialization to whitelists using SerialObjectPermission.

## Plans / Research to Security Harden VM
- Replace default policy provider with concurrent policy provider from JGDMS ✔
- Reduce the size of the trusted platform. ✔
- Add PolicyWriter tool from JGDMS to simplify deployment using principles of least privilege. ✔
- System.setSecurityManager(null) now throws NullPointerException, preventing injection attacks (vulnerabilities) from utilizing privileged context to disable SecurityManager. ✔
- Add policy tests from JGDMS.
- Add strict RFC3986, RFC6874, and RFC5952 URI support and remove DNS lookups from CodeSource.
- Add support for Virtual threads when SecurityManager is enabled. ✔
- Reimplement AccessController::getContext to use StackWalker - this was tried but wasn't stable and caused test failures. 🪓
- Reimplement AccessController::doPrivileged to use ScopedValue for context - this was tried but wasn't stable and caused test failures. 🪓
- Make AccessControlContext immutable, add static builder methods to allow reuse, modify the VM to call builder methods. ✔
- Simplify AccessControlContext similar to its original design. ✔
- Update AccessControlContext equals and hashCode implementations. ✔
- Create DomainIdentity subclass of ProtectionDomain that implements equals and hashCode methods. ✔
- Reimplement AccessController::doPrivileged methods with Permission arguments to strictly limit permissions, instead of allowing privileged callers to use their privileges. Capture the caller and use DomainIdentity and "jrt:/module/class" to represent the domain of the caller restricting permissions. ✔
- Allow Policy to grant additional permissions to those hard-coded in AccessController::doPrivileged methods with Permission arguments. ✔
- Create a cache of AccessControlContext instances to avoid duplication; this is necessary to support virtual threads, instantiate only when SecurityManager is enabled. ✔
- Remove the ProtectionDomain cache from SubjectDomainCombiner, use the non-blocking AccessControlContext cache and DomainIdentity to replace this functionality. ✔
- Update CombinerSecurityManager to use Virtual threads to hand off permission checks. ✔
- Add LoadClassPermission to SecureClassLoader to allow HTTP and jar file signers to control which code can be loaded by policy. ✔
- Add SerialObjectPermission for Java Serialization, automating class whitelisting. ✔
- Remove XML parsing from trusted code to allow authorization decisions to be made on authenticated users instead. This can be performed now by either preventing loading using LoadClassPermission, or since the XML modules are no longer part of the trusted code, can be assigned permissions. ✔
- Add netmask wildcards to SocketPermission.
- Follow and review OpenJDK changes.
- Maintain Authorization and Authentication APIs.
- Research improvements and ideas for Authorization and Authentication APIs.
- Sandboxing untrusted code is a non-goal; our focus is user authorization, ensuring users only have authorization when using approved code, preventing loading of untrusted code, and providing an auditing tool to assess privileges that third-party code intends to use. Developers interested in sandboxing untrusted code need to consider using Graal process isolation.

## Relevant Presentations
- [Presentation 1](https://www.youtube.com/watch?v=uVob-4aXbxY)
- [Presentation 2](https://www.youtube.com/watch?v=sIuVbVbjZcw)
- [Presentation 3](https://www.youtube.com/watch?v=8Qyghv00vEQ)
- [Presentation 4](https://www.youtube.com/watch?v=Y8a5nB-vy78)
- [Presentation 5](https://www.youtube.com/watch?v=0h8DWiOWGGA)

## Security Tooling
- It is not recommended to run unaudited, untrusted code in a deployed environment, but how many programs today are downloading code their developers haven't audited? Is it even practical for small development teams to audit hundreds of thousands or millions of lines of code? The PolicyWriter tool from JGDMS allows administrators to test untrusted code (following static analysis) in a safe environment (e.g., a test machine) to determine the privileges code will access.
- Following auditing with static analysis ([SpotBugs](https://github.com/spotbugs/spotbugs) < 4.9.0 since doPrivileged bugs are no longer reported) and PolicyWriter, code that is deemed safe to run should be executed using the principle of least privilege, utilizing policy files generated with PolicyWriter to limit the possibility of exploits successfully leveraging flaws in code.
- PolicyWriter generates policy files; editing is simple, and the files are easily understood. While the existing SecurityManager Authorization infrastructure isn't perfect, until something better is designed, it's the best tool we have to audit third-party code and establish a level of trust in that code prior to deployment, while also switching off unused or unwanted features that require privileges to operate, such as network communication, file system access, agents, parsing XML, or reading secret keys, so that an attacker is unlikely to be able to leverage them.

## Complexity and Maintenance
- Concurrency is a complex topic; however, programmers are motivated to learn. There are significant performance benefits, and much time has been spent developing and refining the Java memory model and providing libraries to simplify and support concurrency. In contrast, there is little motivation to spend similar resources developing security; instead, security budgets go towards addressing zero-day vulnerabilities and other problems. No new tools have been written for Java Authorization since the late 1990s when it was developed; the only tool that existed was Policy Tool, a small editor to add permissions by hand. However, the problem with this design was that one had to discover the required permissions through trial and error, leading to the overuse of AllPermission. In 2004, the Jini project created a Debug Policy tool, which wrote out each permission required; the administrator had to then manually add each Permission to their policy files. PolicyWriter was inspired by Debug Policy Tool; instead, it appends missing permissions to policy files, avoiding the need for a Policy Tool.
- One of the problems with the existing PrivilegedAction model is that many developers will call methods that require privileges without encapsulating that call in a PrivilegedAction. Also, programmers often forget to preserve the security context between threads, and by default, Executors don't inherit the calling thread's context unless a PrivilegedThreadFactory is used. PolicyWriter makes it easy to read policy files and identify where Permissions are leaking into code that shouldn't have those Permissions; it provides visibility. Once there is visibility, there is less complexity. In hindsight, it would have been better if the methods in the Java API that required privileges required a PrivilegedAction method parameter to warn the programmer not to leak information. Executors can use ThreadFactory's that use the calling thread's context; this could be done by default, and a permission could be required to use a ThreadFactory without the caller's context, as this is, in fact, a form of privileged call.
- An alternative to the privileged action model would have been privileged calls, such that a privileged call was required to call privileged methods, so that no privileges are granted unless a privileged call has been made.
- JGDMS contains some interesting Authorization APIs, such as ScalableNestedPolicy and PermissionGrant, which utilize immutability and safe publication.
- One root cause of problems is the fact that SecurityManager was not enabled by default. The practical reason was simple: there were no decent tools for managing policy. Perhaps policy was too complex; the design was developed prior to annotations. Perhaps a more declarative approach would allow an annotation processor to assist with policy generation and development.
- Another issue is that every domain ends up with some permission, so programs typically operate with a minimum set of permissions. If everything has a minimum set of permissions, then why regulate them? Missing PrivilegedActions are the cause, but the effect is that the user's permissions are in force and could be used for privilege escalation if an attacker can take advantage of a data parsing vulnerability, as the attacker is domainless. A slightly different model is privileged calls; outside a privileged call, there are no permissions. The code developer and the user need to be trustworthy enough not to leak privileged information. In the real world, if someone is untrustworthy, permissions are revoked.
- The complexity of authorization can be significantly reduced for developers with tooling and static analysis to identify missing PrivilegedActions in developer code; however, this would need to be performed at compile time to encourage all developers to use it.
- The greatest complexity is for the OpenJDK development team, implementing guards and preserving context across threads while trying to avoid privilege escalation. Reducing the size of Java's trusted codebase would reduce the risk somewhat, as might centralizing the location of access to resources external to the JVM.
- We learned from JGDMS, Jini, and Apache River that combining Authorization best practices and policy tooling made the use of SecurityManager relatively simple once learned. The largest maintenance component was maintaining policy files, but that became relatively simple and useful once tooling was provided, as it brought auditing benefits as well. Jini also introduced dynamic policy, which allowed policy to be changed after deployment. River introduced revocation, which removed policy grants using garbage collection when they were no longer in use. JGDMS adopted OSGi's method of appending permissions required by a service proxy by appending those permissions in the proxy jar file, following authentication. The administrator gives users the ability to dynamically grant a restricted set of permissions to authenticated services using GrantPermission, so granting necessary permissions for services to function becomes a simple automated process, which is limited by the administrator. Since most users will grant whatever permission they're asked to grant in order to complete some task, these permissions are granted automatically following authentication.
- OpenJDK is reluctant to provide any hooks to allow an authorization framework to place guards due to the maintenance burden. Without guards, an authorization framework that limits network, file system, properties, etc., is not possible. It is my hope that OpenJDK will be prepared to allow us to have these hooks in OpenJDK if we maintain them ourselves.

## Simplification
- In Java 1.2, Permissions were static; they could be defined by Policy; however, they were stored as immutable within a ProtectionDomain. ClassLoaders assigned Permissions to ProtectionDomains, and there was an assumption that if a caller had RuntimePermission "createClassLoader," the caller would scrutinize URL data. The ClassLoader would assign Permissions not listed in policy files, removing the possibility of administrator control. Vulnerabilities such as those in JNDI and the more recent Log4J have shown that we cannot safely assume that URL data will be sanitized. Static Permissions were beneficial to applet ClassLoaders as assumptions were made about the applet being able to connect to the URL from which it originated; however, this assumption isn't relevant to modern code and only serves to complicate and introduce vulnerabilities.
- Later in Java 1.4, Policy would also be consulted during implies calls. I believe this decision was made for the release of Jini 2.0 to allow for DynamicPolicy. It has become apparent that static permissions are a mistake and add unnecessary complexity.
- With Java 1.8, new doPrivileged methods were added to AccessController; these accepted a Permission array argument allowing a caller to reduce their Permissions to the passed-in array. The implementation added significant complexity to AccessControlContext, making it unreasonable to support Virtual threads. However, by simply pushing a new ProtectionDomain onto the stack with the restricting list of permissions, it's possible to provide the same function without the added complexity, aiding in the debugging of missing permissions. The caller's Module and class can be captured in jrt:/module/classname URL syntax.
- Removing static Permissions and the removal of ClassLoaders directly assigning Permissions during construction allows full control to be given to Policy and Policy administrators, allowing the administrator to whitelist safe domains, for example. It is no longer a code or developer concern and instead becomes an administrative concern.
- Removal of static Permissions also assists developers in reasoning about what is a user concern, what is a code concern, and how to differentiate between what belongs inside a PrivilegedAction and what doesn't.
- Use PrivilegedThreadFactory's when SecurityManager is active by default, so programmers don't need to remember to preserve context.
- A cache of immutable AccessControlContext's would significantly reduce the number of contexts required to support Virtual threads...
- Stay tuned...

## Performance
- OpenJDK Policy and PermissionCollection implementations are heavily contended and synchronized. DNS calls are made during CodeSource.implies calls. Back when the implementations were created in the late 1990s, most computers Java 1.2 ran on were single-threaded.
- On the other hand, JGDMS policy implementation is high scaling modern concurrent code, taking advantage of mutability and thread confinement. RFC3986 URIs are used instead of DNS calls; all hotspots have been analyzed and removed, even string case conversion uses bitshift operations. Yes, that's correct, string case conversion was a hotspot in RFC3986 URI normalization. Considering Java's implementation uses DNS calls, the performance difference between these implementations is incomparable. The performance cost of Authorization is less than 1%.

## Ultimate Goal
- Community-based redesign of Authorization API for Java as a preview feature and integration.

## Why OpenJDK Removed Authorization
- Not enough developers use it; the work required to maintain it only services a small section of the Java ecosystem.

# This is a project-specific security refinement that should be documented.

# Welcome to the JDK!

For build instructions, please see the
[online documentation](https://git.openjdk.org/jdk/blob/master/doc/building.md),
or either of these files:

- [doc/building.html](doc/building.html) (HTML version)
- [doc/building.md](doc/building.md) (Markdown version)

See <https://openjdk.org/> for more information about the OpenJDK Community and the JDK, and see <https://bugs.openjdk.org> for JDK issue tracking.

# OpenJDK with Authorization (SecurityManager)
This project's objectives are to maintain a community fork of OpenJDK that retains Authorization functionality, no attempt will be made to sandbox untrusted code, instead, the goals of the project are:
- Prevent loading of untrusted code.
- Prevent gadget attack chains completing.
- Prevent injection attacks, eg whitelist URL's.
- Maintain guard hooks throughout OpenJDK for permission checks and add additional where necessary.
- Research improvements to Authorization.
- High performance and scalability.
- Provide a workable practical implementation to improve Java security against injection style attacks using POLP whitelisting, rather than theoretical vapourware.

## Principle of Least Privilege Policy Writer
- This tool automates writing of your policy files, using principles of least privilege, this creates a minefield of SecurityException's for attackers to navigate inside your perimeter defences.
- Permissions will not be granted to load transitive dependencies or modules you don't use, Serialization will be limited to only the classes used in your deployment staging environment.
### In your deployment staging environment run your program, with the following command line options:
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
- When auditing your policy files, identify permissions with limited scope that will need expanding, such as FilePermission of temporary files, or SocketPermission.
- Run the auditing tool multiple times, each time marking where the last policy was updated, this will help identify permissions that require a wider scope as these permissions will be added each audit test cycle.

### Deploy with high scaling, efficient implementations of SecurityManager and Policy.
-Djava.security.manager=default,

## Development
- The master branch is a fork of OpenJDK master, retaining SecurityManager functionality, this is not intended for use, we use this for merging or rebasing our trunk branch and testing the impact of upstream changes.
- The trunk branch is where our development occurs, we branch off and rebase to trunk in our development branches.

## Vulnerabilities addressed:
- JNDI LDAP dynamic code downloading and object serialziation (root cause of Log4j vulnerability), secured without disablement or removal of functionality.  By removing static permission grants in ClassLoader's, ie URLClassLoader, policy can instead whitelist allowed URL's by granting URLPermission, restrict dynamic code to signed jar files using LoadClassPermission and limit object serialization to whitelists using SerialObjectPermission.

## Plans / Research to Security Harden VM:
- Replace default policy provider with concurrent policy provider from JGDMS ✔
- Add httpmd URL handler to allow SHA256+ algorithms to be used to check jar file integrity. 
- Reduce the size of the trusted platform. ✔
- Add PolicyWriter tool from JGDMS, to simplify deployment using principles of least privilege. ✔
- Add policy tests from JGDMS.
- Add strict RFC3986 RFC6874 and RFC5952 URI support and Remove DNS lookups from CodeSource.
- Remove DNS lookups from SecureClassLoader, use RFC3986 URI instead.
- Add LoadClassPermission to SecureClassLoader, to allow httmpd and jar file signers to control which code can be loaded by policy. ✔
- Add SerialObjectPermission for Java Serialization, automating class whitelisting. ✔
- Remove XML parsing from trusted code, to allow authorization decisions to be made on authenticated users instead. - This can be performed now by either preventing loading using LoadClassPermission, or since the xml modules are no longer part of the trusted code, can be assigned permissions. ✔
- Add netmask wild cards to SocketPermission.
- Follow and review OpenJDK changes.
- Maintain Authorization and Authentication API's.
- Research improvements and ideas for Authorization and Authentication API's.
- Sandboxing untrusted code is a non goal, our focus is user authorization, and ensuring users only have authorization when using approved code, prevent loading of untrusted code and provide an auditing tool to assess privileges that third party code intends to use.

## Relevant Presentations
- https://www.youtube.com/watch?v=uVob-4aXbxY
- https://www.youtube.com/watch?v=sIuVbVbjZcw
- https://www.youtube.com/watch?v=8Qyghv00vEQ
- https://www.youtube.com/watch?v=Y8a5nB-vy78
- https://www.youtube.com/watch?v=0h8DWiOWGGA
  
## Security Tooling:
- It is not recommended to run unaudited, untrusted code in a deployed environment, but how many programs today are downloading code their developers haven't audited, is it even practical for small development teams to audit hundreds of thousands, or millions of lines of code?   The PolicyWriter tool from JGDMS, allows administrators to test untrusted code (following static analysis), in a safe environment (eg a test machine) to determine the privileges code will access.
- Following auditing with static analysis and PolicyWriter, code that is deemed safe to run, should be run using the principle of least privilege, using policy files generated with PolicyWriter, to limit the possiblity of exploits successfully leveraging flaws in code.
- PolicyWriter generates policy files, editing is simple and the files are easily understood, while the existing SecurityManager Authorization infrastructure isn't perfect, until something better is designed, it's the best tool we have to audit third party code and establish a level of trust in that code prior to deployment, while also switching off unused or unwanted features which require privileges to operate, such as network communication, file system access, agents, parsing XML or reading secret keys, so that an attacker is unlikely to be able to leverage them.

## Complexity and Maintenance
- Concurrency is a complex topic, however programmers are motivated to learn, there are significant performance benefits, much time has been spent developing and refining the Java memory model and providing libraries to simplify and support concurrency.   In contrast, there is little motivation to spend similar resources developing security, instead security budgets go towards addressing zero day vulnerabilities and other problems.  No new tools have been written for Java Authorization since the late 1990's when it was developed, the only tool that existed was Policy Tool, a small editor to add permissions by hand, but the problem with this design, was one had to discover the required permissions through trial and error, leading to the over use of AllPermission.   In 2004, the Jini project created a Debug Policy tool, which wrote out each permissions required, the administrator had to then manually add each Permission to their policy files. PolicyWriter was inspired by Debug Policy Tool, instead, it appends missing permissions to policy files, avoiding the need for a Policy Tool.
- One of the problems with the existing PrivilegedAction model, is many developers will call methods that require privileges, without encapsulating that call in a PrivilegedAction, also programmers often forget to preserve the security context between threads and by default, Executors don't inherit the calling threads context, unless a PrivilegedThreadFactory is used.  PolicyWriter makes it easy to read policy files and identify where Permissions are leaking into code that shouldn't have those Permissions, it provides visiblity.  Once there is visibility, there is less complexity, in hindsight, it would have been better if the methods in the Java API, that required privileges, required a PrivilegedAction method parameter, to warn the programmer to not leak information.  Executors can use ThreadFactory's that use the calling threads context, this could be done by default and a permission be required to use a ThreadFactory without the callers context, as this is in fact a form of privileged call.
- An alternative to the privileged action model would have been privileged calls, such that a privileged call was required to call privileged methods, so that no privileges are granted unless a privileged call has been made.
- JGDMS contains some interesting Authorization API's, such as ScalableNestedPolicy and PermissionGrant, which utilise immutability and safe publication.
- One root cause of problems, is the fact that SecurityManager was not enabled by default, the practical reason was simple, there were no decent tools for managing policy, perhaps policy was too complex, the design was developed prior to annotations, perhaps a more declarative approach would allow an annotation processor to assist with policy generation and development.
- Another issue is every domain ends up with some permission, so programs typically operate with a minimum set of permissions, if everything has a minimum set of permissions, then why regulate them?  Missing PrivilegedAction's are the cause, but the effect is that the users permissions are in force and could be used for privilege escallation if an attacker can take advantage of a data parsing vulnerability, as the attacker is domainless.  A slightly different model is privileged calls, outside a privileged call there are no permissions, the code developer and the user need to be trustworthy enough to not leak privileged information, in the real world if someone is untrustworthy, permissions are revoked.
- The complexity of authorization can be significantly reduced for developers with tooling and static analysis to identify missing PrivilegedAction's in developer code, however this would need to be performed at compile time to encourage all developers to use it.
- The greatest complexity is for the OpenJDK development team, implementing guards and preserving context accross threads, while trying to avoid privilege escallation, reducing the size of Java's trusted codebase would reduce the risk somewhat, as might centralizing the location of access to resources external to the jvm.
- We learned from JGDMS, Jini and Apache River, that combining Authorization best practises and policy tooling, use of SecurityManager was relatively simple once learned the largest maintenance component was maintaining policy files, but that became relatively simple and useful once tooling was provided, as it brought auditing benefits as well.  Jini also introduce dynamic policy, which allowed policy to be changed after deployment, River introduced revocation, which removed policy grants using garbarge collection, when they were no longer in use.  JGDMS adopted OSGi's method of appending permissions required by a service proxy, by appending those permissions in the proxy jar file, following authentication.  The administrator gives users the ability to dynamically grant a restricted set of permission's to authenticated services using GrantPermission, so granting of necessary permissions for services to function becomes a simple automated process, which is limited by the administrator.  Since most users will grant whatever permission they're asked to grant, in order to complete some task, these permissions are granted automatically following authentication.
- OpenJDK is reluctant to provide any hooks to allow an authorization framework to place guards, due to the maintenance burden.  Without guards, an authorization framework that limits network, file system, properties, etc, is not possible.   It is my hope that OpenJDK will be prepared to allow us to have these hooks in OpenJDK if we maintain them ourselves.
## Simplification
- In Java 1.2, Permission's were static, they could be defined by Policy, however they were stored as immutable within a ProtectionDomain.  ClassLoaders assigned Permissions to ProtectionDomains, and there was an assumption that, if a caller had RutimePermission "createClassLoader" that the caller would scruitinize URL data, the ClassLoader would assign Permission's not listed in policy files removing the possiblity of administrator control.  Vulnerabilities such as those in JNDI and the more recent Log4J, have shown that we cannot safely assume that URL data will be sanitised.  Static Permission's were beneficial to applet ClassLoader's as assumptions were made about the applet being able to connect to the URL from which it originated, however this assumption isn't relevant to modern code and only servs to complicate and introduce vulnerabilities.
- Later in Java 1.4, Policy would also be consulted during implies calls, I believe this decision was made for the release of Jini 2.0, to allow for DyanmicPolicy.  It has become apparrent that static permissions are a mistake and add uneccessary complexity.
- Removing static Permissions, removing ClassLoader assignment of Permissions, allows full control to be given to Policy and Policy administrators, allowing the administrator to whitelist safe domains for example, it is no longer a code or developer concern and instead becomes an administrative concern.
- Removal of static Permissions also assists developers in reasoning about what is a user concern, what is a code concern and how to differentiate between what belongs inside a PrivilegedAction and what doesn't.
- Use PrivilegedThreadFactory's when SecurityManager is active by default, so programmer's don't need to remember to preserve context.
- Stay tuned...
## Performance
- OpenJDK Policy and PermissionCollection implementations are heavily contended and synchronized, DNS calls are made during CodeSource.implies calls, back when the implementations were created in the late 1990's most computers Java 1.2 ran on were single threaded.
- On the other hand, JGDMS policy implementation is high scaling modern concurrent code, taking advantage of mutability and thread confinement, RFC3986 URI are used instead of DNS calls, all hotspots have been analysed and removed, even string case conversion uses bitshift operations.  Yes, that's correct, string case conversion was a hot spot, in RFC3986 URI normalization.   Considering Java's implementation uses DNS calls, the performance difference between these implementation is uncomparable.  The performance cost of Authorization is less than 1%.
## Ultimate Goal
- Community based redesign of Authorization API for Java as a preview feature and integration.

## Why OpenJDK removed Authorization
- Not enough developers use it, the work required to maintain it only services a small section of the Java ecosystem.

# Welcome to the JDK!

For build instructions please see the
[online documentation](https://openjdk.org/groups/build/doc/building.html),
or either of these files:

- [doc/building.html](doc/building.html) (html version)
- [doc/building.md](doc/building.md) (markdown version)

See <https://openjdk.org/> for more information about the OpenJDK
Community and the JDK and see <https://bugs.openjdk.org> for JDK issue
tracking.

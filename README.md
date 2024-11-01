# Plans / Research to Security Harden VM:
- Replace default policy provider with concurrent policy provider from JGDMS
- Add httpmd URL handler to allow SHA256+ algorithms to be used to check jar file integrity.
- Reduce the size of the trusted platform.
- Add PolicyWriter tool from JGDMS, to simplify deployment using principles of least privilege.
- Add strict RFC3986 RFC6874 and RFC5952 URI support and Remove DNS lookups from CodeSource.
- Remove DNS lookups from SecureClassLoader, use RFC3986 URI instead.
- Add LoadClassPermission to SecureClassLoader, to allow httmpd and jar file signers to control which code can be loaded by policy.
- Add ParsePermission for XML and Serialization implementations, remove their implementations from trusted code, to allow authorization decisions to be made on authenticated users instead.
- Add netmask wild cards to SocketPermission.
- Follow and review OpenJDK changes.
- Maintain Authorization and Authentication API's.
- Sandboxing untrusted code is a non goal, our focus is user authorization, and ensuring users only have authorization when using approved code, prevent loading of untrusted code and provide an auditing tool to assess privileges that third party code intends to use.
- https://www.youtube.com/watch?v=uVob-4aXbxY
- https://www.youtube.com/watch?v=sIuVbVbjZcw
  
## Security Tooling:
- It is not recommended to run unaudited, untrusted code in a deployed environment, but how many programs today are downloading code their developers haven't audited, is it even practical for small development teams to audit thousands of lines of code?   The PolicyWriter tool from JGDMS, allows administrators to test untrusted code (following static analysis), in a safe environment (eg a test machine) to determine the privileges code will access.
- Following auditing with static analysis and PolicyWriter, code that is deemed safe to run, should be run using the principle of least privilege, using policy files generated with PolicyWriter, to limit the possiblity of exploits successfully leveraging flaws in code.
- PolicyWriter generates policy files, editing is simple and the files are easily understood, while the existing SecurityManager Authorization infrastructure isn't perfect, until something better is designed, it's the best tool we have to audit third party code and establish a level of trust in that code prior to deployment, while also switching off unused or unwanted features which require privileges to operate, such as network communication, file system access, agents, parsing XML or reading secret keys, so that an attacker is unlikely to be able to leverage them.

## Complexity
- Concurrency is a complex topic, however programmers are motivated to learn, there are significant performance benefits, much time has been spent developing and refining the Java memory model and providing libraries to simplify and support concurrency.   In contrast, there is little motivation to spend similar resources developing security, instead security budgets go towards addressing zero day vulnerabilities and other problems.  No new tools have been written for Java Authorization since the late 1990's when it was developed, the only tool that existed was Policy Tool, a small editor to add permissions by hand, but the problem with this design, was one had to discover the required permissions through trial and error, leading to the over use of AllPermission.   In 2004, the Jini project created a Debug Policy tool, which wrote out each permissions required, the administrator had to then manually add each Permission to their policy files. PolicyWriter was inspired by Debug Policy Tool, instead, it appends missing permissions to policy files, avoiding the need for a Policy Tool.
- One of the problems with the existing PrivilegedAction model, is many developers will call methods that require privileges, without encapsulating that call in a PrivilegedAction, also programmers often forget to preserve the security context between threads.  PolicyWriter makes it easy to read policy files and identify where Permissions are leaking into code that shouldn't have those Permissions, it provides visiblity.  Once there is visibility, there is less complexity, in hindsight, it would have been better if the methods in the Java API, that required privileges, required a PrivilegedAction method parameter, to warn the programmer to not leak information.  Also PrivilegedAction should have been merged with Runnable and Callable, to remind developers to preserve the current thread's context if necessary.
- An alternative to the privileged action model would have been privileged calls, such that a privileged call was required to call privileged methods, so that no privileges are granted unless a privileged call has been made.
- JGDMS contains some interesting Authorization API's, such as ScalableNestedPolicy and PermissionGrant, which utilise mutability and safe publication.

## Ultimate Goal
- Community based redesign of Authorization API for Java as a preview feature and integration.

# Welcome to the JDK!

For build instructions please see the
[online documentation](https://openjdk.org/groups/build/doc/building.html),
or either of these files:

- [doc/building.html](doc/building.html) (html version)
- [doc/building.md](doc/building.md) (markdown version)

See <https://openjdk.org/> for more information about the OpenJDK
Community and the JDK and see <https://bugs.openjdk.org> for JDK issue
tracking.

# Plans to Security Harden VM:
- Replace default policy provider with concurrent policy provider from JGDMS
- Add httpmd handler to allow SHA256+ algorithms to be used to check jar file integrity.
- Reduce the size of the trusted platform.
- Add PolicyWriter tool from JGDMS, to simplify deployment using principles of least privilege.
- Add strict RFC3986 RFC6874 and RFC5952 URI support and Remove DNS lookups from CodeSource.
- Remove DNS lookups from SecureClassLoader, use RFC3986 URI instead.
- Add LoadClassPermission to SecureClassLoader, to allow httmpd and jar file signers to control which code can be loaded by policy.
- Add ParsePermission for XML and Serialization implementations, remove them from trusted code, to allow authorization decisions to be made on authenticated users instead.
- Add netmask wild cards to SocketPermission.
- Follow and review OpenJDK changes.
- Maintain Authorization and Authentication API's.
- Sandboxed code is a non goal, our focus is user authorization, and ensuring users only have authorization when using approved code.

# Welcome to the JDK!

For build instructions please see the
[online documentation](https://openjdk.org/groups/build/doc/building.html),
or either of these files:

- [doc/building.html](doc/building.html) (html version)
- [doc/building.md](doc/building.md) (markdown version)

See <https://openjdk.org/> for more information about the OpenJDK
Community and the JDK and see <https://bugs.openjdk.org> for JDK issue
tracking.

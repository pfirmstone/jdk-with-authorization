# Philosophy & Design Decisions

**Last Reviewed:** 2026-04-22

## Complexity and Maintenance

Concurrency is a complex topic — yet programmers are motivated to learn it because of the significant performance benefits. Much investment has gone into the Java memory model and concurrency libraries. Authorization is also complex, but unlike concurrency, there are few frameworks available to assist programmers.

One of the problems with the existing `PrivilegedAction` model is that many developers call methods requiring privileges without encapsulating those calls in a `PrivilegedAction`. Programmers also tend to wrap large sections of code in `PrivilegedAction` blocks, rather than granularly wrapping only the specific operations that require privileges. This widens the attack surface.

An alternative to the privileged action model would have been explicit privileged calls, where no privileges are granted unless a privileged call has been made — so that outside a privileged call stack frame, code always runs unprivileged. This would have been more intuitive and would have encouraged developers to granularly request privileges.

JGDMS contains interesting Authorization APIs — such as `ScalableNestedPolicy` and `PermissionGrant` — that leverage immutability and safe publication.

One root cause of the SecurityManager's adoption problems is that it was never enabled by default. The practical reason was simple: there were no adequate tools for managing policy. Policy may also be too coarse-grained for typical deployments.

Another issue is that every protection domain ends up with some permissions, so programs typically operate with a minimum permission set. If everything has a minimum permission set, why regulate them?

Authorization complexity for developers could be significantly reduced with tooling and compile-time static analysis to identify missing `PrivilegedAction` wrappers. The greatest complexity falls on policy writers — not developers.

Experience from JGDMS, Jini, and Apache River demonstrates that combining Authorization best practices with policy tooling made SecurityManager relatively simple to use once understood. The large volume of authorization-related historical issues is often due to misunderstanding, not inherent flaws.

OpenJDK is reluctant to provide hooks for an authorization framework to place guards due to the maintenance burden. Without those guards, an authorization framework that controls network access, file access, and other sensitive operations is nearly impossible.

---

## Simplification

In Java 1.2, permissions were static: defined by Policy but stored as immutable within a `ProtectionDomain`. `ClassLoader`s assigned permissions to `ProtectionDomain`s under the assumption that a class's `ProtectionDomain` would not change during its lifetime.

Later, in Java 1.4, Policy began being consulted during `implies` calls. This decision was made for the Jini 2.0 release to support `DynamicPolicy`. It has become clear that static permissions are the simpler model.

In Java 1.8, new `doPrivileged` methods were added to `AccessController` that accept a `Permission` array, allowing a caller to reduce its permissions to the specified set. That implementation added significant complexity.

Removing static permissions and eliminating direct `ClassLoader` permission assignment at construction time gives full control to Policy and policy administrators. Administrators can whitelist safe code and deny privileges for everything else.

Removing static permissions also helps developers reason about what belongs inside a `PrivilegedAction` — and what the difference is between a user concern and a code concern.

`PrivilegedThreadFactory`s should be used by default when SecurityManager is active, so programmers do not need to manually preserve context when creating threads.

A cache of immutable `AccessControlContext` instances would significantly reduce the number of context objects needed to support Virtual threads — stay tuned.

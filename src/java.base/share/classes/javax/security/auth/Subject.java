/*
 * Copyright (c) 1998, 2025, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package javax.security.auth;

import au.zeus.jdk.authorization.spire.SpiffeCredentialManager;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamField;
import java.security.*;
import java.text.MessageFormat;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletionException;

import sun.security.util.ResourcesMgr;

/**
 * <p> A {@code Subject} represents a grouping of related information
 * for a single entity, such as a person.
 * Such information includes the Subject's identities as well as
 * its security-related attributes
 * (passwords and cryptographic keys, for example).
 *
 * <p> Subjects may potentially have multiple identities.
 * Each identity is represented as a {@code Principal}
 * within the {@code Subject}.  Principals simply bind names to a
 * {@code Subject}.  For example, a {@code Subject} that happens
 * to be a person, Alice, might have two Principals:
 * one which binds "Alice Bar", the name on her driver license,
 * to the {@code Subject}, and another which binds,
 * "999-99-9999", the number on her student identification card,
 * to the {@code Subject}.  Both Principals refer to the same
 * {@code Subject} even though each has a different name.
 *
 * <p> A {@code Subject} may also own security-related attributes,
 * which are referred to as credentials.
 * Sensitive credentials that require special protection, such as
 * private cryptographic keys, are stored within a private credential
 * {@code Set}.  Credentials intended to be shared, such as
 * public key certificates or Kerberos server tickets are stored
 * within a public credential {@code Set}.  Different permissions
 * are required to access and modify the different credential Sets.
 *
 * <p> To retrieve all the Principals associated with a {@code Subject},
 * invoke the {@code getPrincipals} method.  To retrieve
 * all the public or private credentials belonging to a {@code Subject},
 * invoke the {@code getPublicCredentials} method or
 * {@code getPrivateCredentials} method, respectively.
 * To modify the returned {@code Set} of Principals and credentials,
 * use the methods defined in the {@code Set} class.
 * For example:
 * <pre>
 *      Subject subject;
 *      Principal principal;
 *      Object credential;
 *
 *      // add a Principal and credential to the Subject
 *      subject.getPrincipals().add(principal);
 *      subject.getPublicCredentials().add(credential);
 * </pre>
 *
 * <p> This {@code Subject} class implements {@code Serializable}.
 * While the Principals associated with the {@code Subject} are serialized,
 * the credentials associated with the {@code Subject} are not.
 * Note that the {@code java.security.Principal} class
 * does not implement {@code Serializable}.  Therefore, all concrete
 * {@code Principal} implementations associated with Subjects
 * must implement {@code Serializable}.
 *
 * <h2>Identity Model — Workload and User Subjects</h2>
 *
 * <p> The following methods in this class for user-based authorization
 * that are dependent on Security Manager APIs are deprecated:
 * <ul>
 *     <li>{@link #getSubject(AccessControlContext)}
 *     <li>{@link #doAs(Subject, PrivilegedAction)}
 *     <li>{@link #doAs(Subject, PrivilegedExceptionAction)}
 *     <li>{@link #doAsPrivileged(Subject, PrivilegedAction, AccessControlContext)}
 *     <li>{@link #doAsPrivileged(Subject, PrivilegedExceptionAction, AccessControlContext)}
 * </ul>
 * Methods {@link #current()} and {@link #callAs(Subject, Callable)}
 * are replacements for these methods, where {@code current}
 * is mostly equivalent to {@code getSubject(AccessController.getContext())}
 * and {@code callAs} is similar to {@code doAs} except that the
 * input type and exceptions thrown are slightly different.
 *
 * @since 1.4
 * @see java.security.Principal
 * @see java.security.DomainCombiner
 */
public sealed class Subject implements java.io.Serializable permits 
        WorkerSubject, UserSubject {

    @java.io.Serial
    private static final long serialVersionUID = -8308522755600156056L;

    /**
     * A {@code Set} that provides a view of all of this
     * Subject's Principals
     *
     * @serial Each element in this set is a
     *          {@code java.security.Principal}.
     *          The set is a {@code Subject.SecureSet}.
     */
    @SuppressWarnings("serial") // Not statically typed as Serializable
    Set<Principal> principals;

    /**
     * Sets that provide a view of all of this
     * Subject's Credentials
     */
    transient Set<Object> pubCredentials;
    transient Set<Object> privCredentials;

    /**
     * Whether this Subject is read-only
     *
     * @serial
     */
    private volatile boolean readOnly;
    private transient volatile int hashCode;

    private static final int PRINCIPAL_SET = 1;
    private static final int PUB_CREDENTIAL_SET = 2;
    private static final int PRIV_CREDENTIAL_SET = 3;

    private static final ProtectionDomain[] NULL_PD_ARRAY
        = new ProtectionDomain[0];

    /**
     * Create an instance of a {@code Subject}
     * with an empty {@code Set} of Principals and empty
     * Sets of public and private credentials.
     *
     * <p> The newly constructed Sets check whether this {@code Subject}
     * has been set read-only before permitting subsequent modifications.
     * The newly created Sets also prevent illegal modifications
     * by ensuring that callers have sufficient permissions.  These Sets
     * also prohibit null elements, and attempts to add, query, or remove
     * a null element will result in a {@code NullPointerException}.
     *
     * <p> To modify the Principals Set, the caller must have
     * {@code AuthPermission("modifyPrincipals")}.
     * To modify the public credential Set, the caller must have
     * {@code AuthPermission("modifyPublicCredentials")}.
     * To modify the private credential Set, the caller must have
     * {@code AuthPermission("modifyPrivateCredentials")}.
     */
    public Subject() {

        this.principals = Collections.synchronizedSet
                        (new SecureSet<>(this, PRINCIPAL_SET));
        this.pubCredentials = Collections.synchronizedSet
                        (new SecureSet<>(this, PUB_CREDENTIAL_SET));
        this.privCredentials = Collections.synchronizedSet
                        (new SecureSet<>(this, PRIV_CREDENTIAL_SET));
    }

    /**
     * Create an instance of a {@code Subject} with
     * Principals and credentials.
     *
     * <p> The Principals and credentials from the specified Sets
     * are copied into newly constructed Sets.
     * These newly created Sets check whether this {@code Subject}
     * has been set read-only before permitting subsequent modifications.
     * The newly created Sets also prevent illegal modifications
     * by ensuring that callers have sufficient permissions.  These Sets
     * also prohibit null elements, and attempts to add, query, or remove
     * a null element will result in a {@code NullPointerException}.
     *
     * <p> To modify the Principals Set, the caller must have
     * {@code AuthPermission("modifyPrincipals")}.
     * To modify the public credential Set, the caller must have
     * {@code AuthPermission("modifyPublicCredentials")}.
     * To modify the private credential Set, the caller must have
     * {@code AuthPermission("modifyPrivateCredentials")}.
     *
     * @param readOnly true if the {@code Subject} is to be read-only,
     *          and false otherwise.
     *
     * @param principals the {@code Set} of Principals
     *          to be associated with this {@code Subject}.
     *
     * @param pubCredentials the {@code Set} of public credentials
     *          to be associated with this {@code Subject}.
     *
     * @param privCredentials the {@code Set} of private credentials
     *          to be associated with this {@code Subject}.
     *
     * @throws NullPointerException if the specified
     *          {@code principals}, {@code pubCredentials},
     *          or {@code privCredentials} are {@code null},
     *          or a null value exists within any of these three
     *          Sets.
     */
    public Subject(boolean readOnly, Set<? extends Principal> principals,
                   Set<?> pubCredentials, Set<?> privCredentials) {
        LinkedList<Principal> principalList
                = collectionNullClean(principals);
        LinkedList<Object> pubCredsList
                = collectionNullClean(pubCredentials);
        LinkedList<Object> privCredsList
                = collectionNullClean(privCredentials);

        this.principals = Collections.synchronizedSet(
                new SecureSet<>(this, PRINCIPAL_SET, principalList));
        this.pubCredentials = Collections.synchronizedSet(
                new SecureSet<>(this, PUB_CREDENTIAL_SET, pubCredsList));
        this.privCredentials = Collections.synchronizedSet(
                new SecureSet<>(this, PRIV_CREDENTIAL_SET, privCredsList));
        this.readOnly = readOnly;
        if (readOnly) hashCode = computeHashCode();
    }

    /**
     * Set this {@code Subject} to be read-only.
     *
     * <p> Modifications (additions and removals) to this Subject's
     * {@code Principal} {@code Set} and
     * credential Sets will be disallowed.
     * The {@code destroy} operation on this Subject's credentials will
     * still be permitted.
     *
     * <p> Subsequent attempts to modify the Subject's {@code Principal}
     * and credential Sets will result in an
     * {@code IllegalStateException} being thrown.
     * Also, once a {@code Subject} is read-only,
     * it can not be reset to being writable again.
     *
     * @throws SecurityException if a security manager is installed and the
     *         caller does not have an
     *         {@link AuthPermission#AuthPermission(String)
     *         AuthPermission("setReadOnly")} permission to set this
     *         {@code Subject} to be read-only.
     */
    public void setReadOnly() {
        @SuppressWarnings("removal")
        java.lang.SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(AuthPermissionHolder.SET_READ_ONLY_PERMISSION);
        }
        synchronized (this){
            if (readOnly) return;
            this.readOnly = true;
            this.hashCode = computeHashCode();
        }
        
    }

    /**
     * Query whether this {@code Subject} is read-only.
     *
     * @return true if this {@code Subject} is read-only, false otherwise.
     */
    public boolean isReadOnly() {
        return this.readOnly;
    }
    
    /**
     * Non standard JAVA API.
     * 
     * Returns the Spiffe system process WorkerSubject.  Note that this Subject will
     * expire, it should be obtained each time it's needed, it should not be
     * relied upon for long running processes.
     * 
     * @return the system process WorkerSubject.
     */
    public Subject processWorker() {
        java.lang.SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(AuthPermissionHolder.GET_SUBJECT_PERMISSION);
        }
        return processWorkerNoCheck();
    }
    
    private Subject processWorkerNoCheck(){
        return SpiffeCredentialManager.getInstance().getSubject();
    }

    /**
     * Get the {@code Subject} associated with the provided
     * {@code AccessControlContext}.
     *
     * <p> The {@code AccessControlContext} may contain many
     * Subjects (from nested {@code doAs} calls).
     * In this situation, the most recent {@code Subject} associated
     * with the {@code AccessControlContext} is returned.
     * <p> Deprecated since 17, removed or disabled since 24,
     * retained and maintained operational for Authorization.
     *
     * @param  acc the {@code AccessControlContext} from which to retrieve
     *          the {@code Subject}.
     *
     * @return  the {@code Subject} associated with the provided
     *          {@code AccessControlContext}, or {@code null}
     *          if no {@code Subject} is associated
     *          with the provided {@code AccessControlContext}.
     *
     * @throws SecurityException if a security manager is installed and the
     *          caller does not have an
     *          {@link AuthPermission#AuthPermission(String)
     *          AuthPermission("getSubject")} permission to get the
     *          {@code Subject}.
     *
     * @throws NullPointerException if the provided
     *          {@code AccessControlContext} is {@code null}.
     */
    @SuppressWarnings("removal")
//    @Deprecated(since="17", forRemoval=true)
    public static Subject getSubject(final AccessControlContext acc) {

        java.lang.SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(AuthPermissionHolder.GET_SUBJECT_PERMISSION);
        }

        Objects.requireNonNull(acc, ResourcesMgr.getString
                ("invalid.null.AccessControlContext.provided"));

        // return the Subject from the DomainCombiner of the provided context
        DomainCombiner dc = Context.combiner(acc);
        if (dc instanceof SubjectDomainCombiner sdc) return sdc.subject();
        return null;
    }

    private static final ScopedValue<Subject []> SCOPED_SUBJECT =
            ScopedValue.newInstance();

    /**
     * Returns the {@code Subject} bound to the period of the execution of the current
     * thread.
     * 
     * <p> This method is recommended for obtaining user Subject's originating from
     * {@code LoginContext}.
     *
     * <p> The current subject is installed by the {@link #callAs} method.
     * When {@code callAs(subject, action)} is called, {@code action} is
     * executed with {@code subject} as its current subject which can be
     * retrieved by this method. After {@code action} is finished, the current
     * subject is reset to its previous value. The current
     * subject is {@code null} before the first call of {@code callAs()}.
     *
     * <p> Throws SecurityException if a security manager is installed and the
     *  caller does not have an {@link AuthPermission#AuthPermission(String)
     *  AuthPermission("getSubject")} permission to get the {@code Subject}.
     *
     * @return the current subject, or {@code null} if a current subject is
     *      not installed or the current subject is set to {@code null}.
     * @throws SecurityException if a security manager is installed and the
     *          caller does not have an
     *          {@link AuthPermission#AuthPermission(String)
     *          AuthPermission("getSubject")} permission to get the
     *          {@code Subject}.
     * @see #callAs(Subject, Callable)
     * @since 18
     */
    @SuppressWarnings("removal")
    public static Subject current() {
        java.lang.SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(AuthPermissionHolder.GET_SUBJECT_PERMISSION);
        }
        Subject [] subject = NoCheck.current();
        return subject != null && subject.length > 0 ? subject[0] : null;
    }
    
    /**
     * Non standard Java API.
     * 
     * Returns the {@code Subject} bound to the period of the execution of the current
     * thread.
     * 
     * <p> This method is recommended for obtaining user Subject's originating from
     * {@code LoginContext}.
     *
     * <p> The current subjects are installed by the {@link #callAs} method.
     * When {@code callAs(action, subject)} is called, {@code action} is
     * executed with {@code subject} as its current subject which can be
     * retrieved by this method. After {@code action} is finished, the current
     * subject is reset to its previous value. The current
     * subject is {@code null} before the first call of {@code callAs()}.
     *
     * <p> Throws SecurityException if a security manager is installed and the
     *  caller does not have an {@link AuthPermission#AuthPermission(String)
     *  AuthPermission("getSubject")} permission to get the {@code Subject}.
     *
     * @return an array containing the current subjects, or an empty array
     *      if a current subject is not installed or the current subject is
     *      set to {@code null}.
     * @throws SecurityException if a security manager is installed and the
     *          caller does not have an
     *          {@link AuthPermission#AuthPermission(String)
     *          AuthPermission("getSubject")} permission to get the
     *          {@code Subject}.
     * @see #callAs
     * @since 27
     */
    public static Subject [] currentAll() {
        java.lang.SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(AuthPermissionHolder.GET_SUBJECT_PERMISSION);
        }
        return NoCheck.current().clone();
    }
    
    /**
     * Internal implementation class that provides access to SCOPED_SUBJECT
     * without permission checks.
     */
    public static abstract sealed class NoCheck permits AccessController.SubjectAccess, 
            Thread.SubjectAccess {
        
        /**
         * Protected constructor.
         */
        protected NoCheck(){}
        
        /**
         * Static method that returns the current Subject if set.
         * @return the Scoped Subject
         */
        protected static Subject [] current(){
            return SCOPED_SUBJECT.isBound() ? SCOPED_SUBJECT.get() : new Subject[0];
        }
        
        /**
         * Static method that returns getSubject from SubjectDomainCombiner
         * @param sdc - SubjectDomainCombiner
         * @return Subject
         */
        protected static Subject getSubject(SubjectDomainCombiner sdc){
            return sdc.subject();
        }
        
        /**
         * Performs callAs without a permission check.
         * 
         * @param <T> - the result of the action.
         * @param subject the Subject
         * @param action - the Callable action
         * @return the result.
         * @throws CompletionException if {@code action.call()} throws any exception;
         *         the thrown exception is available via {@link CompletionException#getCause()}
         */
        protected static <T> T callAs(final Callable<T> action, final Subject ... subject) throws CompletionException {
            return callNoCheck(action, subject);
        }
        
    }

    /**
     * Executes a {@code Callable} with {@code subject} as the current subject
     * for the duration of the call on the current thread.
     *
     * <p> This is the recommended method for executing code under the identity
     * of a user {@code Subject} obtained from a {@link javax.security.auth.login.LoginContext}.
     * When a {@link java.security.Policy} grants permissions based on both code
     * source and {@code Principal}s, binding a {@code Subject} via this method
     * will affect the permissions available during the execution of {@code action}
     * — grants that require the presence of specific {@code Principal}s will apply
     * only when a matching {@code Subject} is current.
     *
     * <p> Unlike {@link #doAs(Subject, PrivilegedAction)}, this method does not
     * establish a privileged execution boundary; no {@code AccessControlContext}
     * snapshot is taken and the current subject is carried as a
     * {@link ScopedValue} for the duration of {@code action}, remaining
     * available across any {@code doPrivileged} calls made within {@code action}.
     * Calls to {@code callAs} may be nested with different {@code Subject}s; each
     * nested call shadows the previous current subject for its duration, restoring
     * it when {@code action} completes, whether normally or exceptionally.
     *
     * <p> This method is intended for user identity. For workload identity in a
     * two-Subject model, use {@link #doAs(Subject, PrivilegedAction)} instead,
     * which establishes a privileged execution boundary and embeds the
     * {@code Subject} structurally in the {@code AccessControlContext} via a
     * {@link SubjectDomainCombiner}.
     *
     * <strong>Thread propagation</strong>
     *
     * <p> Any threads spawned during the execution of {@code action} will
     * inherit the current subject, which is re-established as a
     * {@link ScopedValue} binding for the duration of the spawned thread's
     * task. This ensures that principal-scoped policy grants apply consistently
     * to child threads without requiring explicit propagation by the caller.
     * The inherited subject is active for exactly the lifetime of the spawned
     * task and cannot leak beyond it.
     *
     * <p> Note that this propagation behaviour differs from the OpenJDK
     * reference implementation, in which the user {@code Subject} established
     * by {@code callAs} is not propagated to threads started with
     * {@code new Thread(...).start()} outside of a
     * {@link java.util.concurrent.StructuredTaskScope}. In this implementation,
     * propagation occurs for all spawned threads regardless of whether structured
     * concurrency is used.
     *
     * <p> Tasks submitted to an {@link java.util.concurrent.Executor} do not
     * inherit the current subject; the {@link ScopedValue} binding is not in
     * effect in the worker thread, and the submitted task should explicitly call
     * {@code callAs} if it requires the same subject to be current.
     *
     * <p> If a security manager is installed, the caller must have
     * {@link AuthPermission}{@code ("doAs")} to invoke this method.
     *
     * <p> If {@code subject} is read-only, its identity is efficiently available
     * to authorization checks without synchronization overhead.
     *
     * @param subject the {@code Subject} to associate with the execution of
     *                {@code action}, or {@code null} to execute with no current
     *                subject.
     * @param action  the code to execute as {@code subject}. Must not be
     *                {@code null}.
     * @param <T>     the type of value returned by {@code action.call()}
     *
     * @return the value returned by {@code action.call()}
     *
     * @throws NullPointerException if {@code action} is {@code null}
     * @throws SecurityException if a security manager is installed and the caller
     *         does not have {@link AuthPermission}{@code ("doAs")}
     * @throws CompletionException if {@code action.call()} throws any exception;
     *         the thrown exception is available via
     *         {@link CompletionException#getCause()}
     *
     * @see #current()
     * @see #doAs(Subject, PrivilegedAction)
     * @see #doAs(Subject, PrivilegedExceptionAction)
     * @since 18
     */
    public static <T> T callAs(final Subject subject,
            final Callable<T> action) throws CompletionException {
        Objects.requireNonNull(action);
        if (subject instanceof WorkerSubject)
                throw new IllegalArgumentException(
                    "LocalWorkerSubject must not be passed to callAs() — " +
                    "local process identity is ambient");
        java.lang.SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(AuthPermissionHolder.CALL_AS_PERMISSION);
        }
        return callNoCheck(action, subject);
    }

    /**
     * Executes a {@code Callable} with the provided subjects as the current
     * scoped identity for the duration of the call on the current thread.
     * 
     * <p> Supports multi-party transactions — multiple UserSubjects may be bound
     * simultaneously. Subject.current() returns subject[0] (the primary user).
     *
     * <p> WorkerSubject cannot be passed — the type parameter enforces this at
     * compile time. WorkerSubject process identity is ambient, baked into
     * ProtectionDomains at class load time by SecureClassLoader.
     *
     * @param action  the code to execute; must not be null
     * @param subject zero or more UserSubject instances; must not be null;
     *                no element may be null, the array may be empty so
     *                no subject is set.
     *
     * @param <T>     the type of value returned by {@code action.call()}
     *
     * @return the value returned by {@code action.call()}
     *
     * @throws NullPointerException if action is null, subject is null,
     *         or any element of subject is null
     * @throws IllegalArgumentException if any element of {@code subjects}
     *         is a {@code WorkerSubject}
     */
    public static <T> T callAs(Callable<T> action, UserSubject... subject)
        throws CompletionException {
        Objects.requireNonNull(action, "action");
        Objects.requireNonNull(subject, "subjects");
        for (int i = 0; i < subject.length; i++) {
            Objects.requireNonNull(subject[i],
                "subjects[" + i + "] must not be null");
        }
        java.lang.SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(AuthPermissionHolder.CALL_AS_PERMISSION);
        }
        return callNoCheck(action, subject);
    }

    private static <T> T callNoCheck(final Callable<T> action,
            final Subject ... subject) throws CompletionException {
        try {
            return ScopedValue.where(SCOPED_SUBJECT, subject).call(action::call);
        } catch (Exception e) {
            throw new CompletionException(e);
        }
    }

    /**
     * Performs work as a particular {@code Subject}.
     *
     * <p> This method is intended for establishing a <em>workload</em> identity —
     * the identity of a service or principal under which dispatched work executes.
     * It snapshots the current thread's {@code AccessControlContext} via
     * {@link AccessController#getContext()}, associates the provided {@code subject}
     * with it via a {@link SubjectDomainCombiner}, and invokes
     * {@link AccessController#doPrivileged(PrivilegedAction, AccessControlContext)},
     * establishing a privileged execution boundary.
     *
     * <p> Because a privileged boundary is established, only the snapshotted
     * {@code AccessControlContext} and the {@code Subject}'s {@code Principal}s
     * participate in permission checks within {@code action} — the caller's
     * stack beyond the {@code doPrivileged} boundary is not consulted. When a
     * {@link java.security.Policy} grants permissions based on both code source
     * and {@code Principal}s, the {@code Subject}'s principals will enable
     * principal-scoped grants for all code executing within {@code action}.
     *
     * <p> The {@link SubjectDomainCombiner} established by this method is not
     * preserved across nested {@link AccessController#doPrivileged(PrivilegedAction)}
     * calls within {@code action} — the combiner associated with the current
     * {@code AccessControlContext} is silently dropped at each such boundary.
     * To preserve the workload identity across a nested privileged boundary, use
     * {@link AccessController#doPrivilegedWithCombiner(PrivilegedAction)}, which
     * explicitly retrieves and carries forward the current {@link DomainCombiner}.
     * Alternatively, an explicit {@code AccessControlContext} carrying the
     * {@link SubjectDomainCombiner} may be passed to
     * {@link AccessController#doPrivileged(PrivilegedAction, AccessControlContext)},
     * though this requires the caller to manage the context explicitly.
     *
     * <p> Any threads spawned within {@code action} inherit the
     * {@code AccessControlContext} containing the {@link SubjectDomainCombiner},
     * ensuring the workload identity propagates to child threads automatically.
     * Tasks submitted to an {@link java.util.concurrent.Executor} do not inherit
     * this context and must explicitly re-establish the workload identity if required.
     *
     * <p> This method is intended for workload identity. For user identity in a
     * two-Subject model, use {@link #callAs(Subject, Callable)} instead, which
     * carries the user {@code Subject} as a {@link ScopedValue} without
     * establishing a privileged boundary, remains available across nested
     * {@code doPrivileged} calls, and correctly shadows across nested invocations
     * with different {@code Subject}s.
     *
     * @param subject the {@code Subject} to associate with the execution of
     *                {@code action}. May be {@code null}.
     * @param action  the code to be run as the specified {@code Subject}.
     *                Must not be {@code null}.
     * @param <T>     the type of the value returned by {@code action.run()}
     *
     * @return the value returned by {@code action.run()}
     *
     * @throws NullPointerException if {@code action} is {@code null}
     * @throws SecurityException if a security manager is installed and the caller
     *         does not have {@link AuthPermission}{@code ("doAs")}
     *
     * @see #callAs(Subject, Callable)
     * @see #doAsPrivileged(Subject, PrivilegedAction, AccessControlContext)
     * @see AccessController#doPrivilegedWithCombiner(PrivilegedAction)
     */
    @SuppressWarnings("removal")
    public static <T> T doAs(final Subject subject,
                             final java.security.PrivilegedAction<T> action) {
        if (subject instanceof WorkerSubject)
            throw new IllegalArgumentException(
                "WorkerSubject is established by SPIRE infrastructure");
        if (subject instanceof UserSubject)
            throw new IllegalArgumentException(
                "UserSubject must use Subject.callAs()");
        
        java.lang.SecurityManager sm = System.getSecurityManager();
        if (sm != null) sm.checkPermission(AuthPermissionHolder.DO_AS_PERMISSION);
        Objects.requireNonNull(action, ResourcesMgr.getString("invalid.null.action.provided"));
        return java.security.AccessController.doPrivileged(
                action, createContext(subject, AccessController.getContext()));
    }

    /**
     * Performs work as a particular {@code Subject}.
     *
     * <p> This method is identical to
     * {@link #doAs(Subject, PrivilegedAction)} except that the action
     * is expressed as a {@link PrivilegedExceptionAction}, permitting
     * the action to throw checked exceptions. Any checked exception
     * thrown by {@code action.run()} is wrapped in a
     * {@link PrivilegedActionException} and re-thrown from this method.
     *
     * <p> This method is intended for establishing a <em>workload</em> identity —
     * the identity of a service or principal under which dispatched work executes.
     * It snapshots the current thread's {@code AccessControlContext} via
     * {@link AccessController#getContext()}, associates the provided {@code subject}
     * with it via a {@link SubjectDomainCombiner}, and invokes
     * {@link AccessController#doPrivileged(PrivilegedExceptionAction, AccessControlContext)},
     * establishing a privileged execution boundary.
     *
     * <p> Because a privileged boundary is established, only the snapshotted
     * {@code AccessControlContext} and the {@code Subject}'s {@code Principal}s
     * participate in permission checks within {@code action} — the caller's
     * stack beyond the {@code doPrivileged} boundary is not consulted. When a
     * {@link java.security.Policy} grants permissions based on both code source
     * and {@code Principal}s, the {@code Subject}'s principals will enable
     * principal-scoped grants for all code executing within {@code action}.
     *
     * <p> The {@link SubjectDomainCombiner} established by this method is not
     * preserved across nested {@link AccessController#doPrivileged(PrivilegedExceptionAction)}
     * calls within {@code action} — the combiner associated with the current
     * {@code AccessControlContext} is silently dropped at each such boundary.
     * To preserve the workload identity across a nested privileged boundary, use
     * {@link AccessController#doPrivilegedWithCombiner(PrivilegedExceptionAction)},
     * which explicitly retrieves and carries forward the current
     * {@link DomainCombiner}. Alternatively, an explicit {@code AccessControlContext}
     * carrying the {@link SubjectDomainCombiner} may be passed to
     * {@link AccessController#doPrivileged(PrivilegedExceptionAction, AccessControlContext)},
     * though this requires the caller to manage the context explicitly.
     *
     * <p> Any threads spawned within {@code action} inherit the
     * {@code AccessControlContext} containing the {@link SubjectDomainCombiner},
     * ensuring the workload identity propagates to child threads automatically.
     * Tasks submitted to an {@link java.util.concurrent.Executor} do not inherit
     * this context and must explicitly re-establish the workload identity if required.
     *
     * <p> This method is intended for workload identity. For user identity in a
     * two-Subject model, use {@link #callAs(Subject, Callable)} instead, which
     * carries the user {@code Subject} as a {@link ScopedValue} without
     * establishing a privileged boundary, remains available across nested
     * {@code doPrivileged} calls, and correctly shadows across nested invocations
     * with different {@code Subject}s.
     *
     * @param subject the {@code Subject} to associate with the execution of
     *                {@code action}. May be {@code null}.
     * @param action  the code to be run as the specified {@code Subject}.
     *                Must not be {@code null}.
     * @param <T>     the type of the value returned by {@code action.run()}
     *
     * @return the value returned by {@code action.run()}
     *
     * @throws NullPointerException if {@code action} is {@code null}
     * @throws PrivilegedActionException if {@code action.run()} throws a
     *         checked exception. The thrown exception is available via
     *         {@link PrivilegedActionException#getException()}
     * @throws SecurityException if a security manager is installed and the caller
     *         does not have {@link AuthPermission}{@code ("doAs")}
     *
     * @see #doAs(Subject, PrivilegedAction)
     * @see #callAs(Subject, Callable)
     * @see #doAsPrivileged(Subject, PrivilegedExceptionAction, AccessControlContext)
     * @see AccessController#doPrivilegedWithCombiner(PrivilegedExceptionAction)
     */
    @SuppressWarnings("removal")
    public static <T> T doAs(final Subject subject,
                        final java.security.PrivilegedExceptionAction<T> action)
                        throws java.security.PrivilegedActionException {
        if (subject instanceof WorkerSubject)
            throw new IllegalArgumentException(
                "WorkerSubject is established by SPIRE infrastructure");
        if (subject instanceof UserSubject)
            throw new IllegalArgumentException(
                "UserSubject must use Subject.callAs()");
        java.lang.SecurityManager sm = System.getSecurityManager();
        if (sm != null) sm.checkPermission(AuthPermissionHolder.DO_AS_PERMISSION);
        Objects.requireNonNull(action, ResourcesMgr.getString("invalid.null.action.provided"));
        return java.security.AccessController.doPrivileged(
                action, createContext(subject, AccessController.getContext()));
    }

    /**
     * Performs work as a particular {@code Subject} using an explicitly
     * provided {@code AccessControlContext}.
     *
     * <p> This method behaves identically to
     * {@link #doAs(Subject, PrivilegedAction)} except that rather than
     * snapshotting the current thread's {@code AccessControlContext}, it
     * uses the explicitly provided {@code acc} as the base context. This
     * allows the caller to control precisely which stack context participates
     * in permission checks within {@code action}, enabling delegation patterns
     * where the security context must be constructed or constrained explicitly
     * rather than inherited from the current thread.
     *
     * <p> If {@code acc} is {@code null}, the action is executed with an
     * empty {@code AccessControlContext} containing no {@code ProtectionDomain}s.
     * This discards all caller stack context entirely, producing a stronger
     * privilege boundary than {@link #doAs(Subject, PrivilegedAction)} —
     * only the {@code Subject}'s principals and the permissions of code
     * executing within {@code action} itself will be considered. This should
     * be used deliberately and with care, as it eliminates all constraints
     * from the calling context.
     *
     * <p> When a {@link java.security.Policy} grants permissions based on
     * both code source and {@code Principal}s, the {@code Subject}'s principals
     * will enable principal-scoped grants for all code executing within
     * {@code action}.
     *
     * <p> The {@link SubjectDomainCombiner} established by this method is not
     * preserved across nested {@link AccessController#doPrivileged(PrivilegedAction)}
     * calls within {@code action} — the combiner associated with the current
     * {@code AccessControlContext} is silently dropped at each such boundary.
     * To preserve the workload identity across a nested privileged boundary, use
     * {@link AccessController#doPrivilegedWithCombiner(PrivilegedAction)}, which
     * explicitly retrieves and carries forward the current {@link DomainCombiner}.
     * Alternatively, an explicit {@code AccessControlContext} carrying the
     * {@link SubjectDomainCombiner} may be passed to
     * {@link AccessController#doPrivileged(PrivilegedAction, AccessControlContext)},
     * though this requires the caller to manage the context explicitly.
     *
     * <p> Any threads spawned within {@code action} inherit the
     * {@code AccessControlContext} containing the {@link SubjectDomainCombiner},
     * ensuring the workload identity propagates to child threads automatically.
     * Tasks submitted to an {@link java.util.concurrent.Executor} do not inherit
     * this context and must explicitly re-establish the workload identity if required.
     *
     * <p> This method is intended for workload identity. For user identity in a
     * two-Subject model, use {@link #callAs(Subject, Callable)} instead, which
     * carries the user {@code Subject} as a {@link ScopedValue} without
     * establishing a privileged boundary, remains available across nested
     * {@code doPrivileged} calls, and correctly shadows across nested invocations
     * with different {@code Subject}s.
     *
     * @param subject the {@code Subject} to associate with the execution of
     *                {@code action}. May be {@code null}.
     * @param action  the code to be run as the specified {@code Subject}.
     *                Must not be {@code null}.
     * @param acc     the {@code AccessControlContext} to use as the base context
     *                for permission checks within {@code action}. If {@code null},
     *                an empty context is used, discarding all caller stack context.
     * @param <T>     the type of the value returned by {@code action.run()}
     *
     * @return the value returned by {@code action.run()}
     *
     * @throws NullPointerException if {@code action} is {@code null}
     * @throws SecurityException if a security manager is installed and the caller
     *         does not have {@link AuthPermission}{@code ("doAsPrivileged")}
     *
     * @see #doAs(Subject, PrivilegedAction)
     * @see #callAs(Subject, Callable)
     * @see #doAsPrivileged(Subject, PrivilegedExceptionAction, AccessControlContext)
     * @see AccessController#doPrivilegedWithCombiner(PrivilegedAction)
     */
    @SuppressWarnings("removal")
    public static <T> T doAsPrivileged(final Subject subject,
                        final java.security.PrivilegedAction<T> action,
                        final java.security.AccessControlContext acc) {
        if (subject instanceof WorkerSubject)
            throw new IllegalArgumentException(
                "WorkerSubject is established by SPIRE infrastructure");
        if (subject instanceof UserSubject)
            throw new IllegalArgumentException(
                "UserSubject must use Subject.callAs()");
        java.lang.SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(AuthPermissionHolder.DO_AS_PRIVILEGED_PERMISSION);
        }

        Objects.requireNonNull(action,
                ResourcesMgr.getString("invalid.null.action.provided"));

            // set up the new Subject-based AccessControlContext
            // for doPrivileged
            final AccessControlContext callerAcc =
                    (acc == null ?
                            Context.create(NULL_PD_ARRAY) :
                            acc);

            // call doPrivileged and push this new context on the stack
            return java.security.AccessController.doPrivileged
                    (action,
                            createContext(subject, callerAcc));
    }
    
    /**
     * Performs work as a particular {@code Subject} using an explicitly
     * provided {@code AccessControlContext}.
     *
     * <p> This method is identical to
     * {@link #doAsPrivileged(Subject, PrivilegedAction, AccessControlContext)}
     * except that the action is expressed as a {@link PrivilegedExceptionAction},
     * permitting the action to throw checked exceptions. Any checked exception
     * thrown by {@code action.run()} is wrapped in a
     * {@link PrivilegedActionException} and rethrown from this method.
     *
     * <p> This method behaves identically to
     * {@link #doAs(Subject, PrivilegedExceptionAction)} except that rather than
     * snapshotting the current thread's {@code AccessControlContext}, it
     * uses the explicitly provided {@code acc} as the base context. This
     * allows the caller to control precisely which stack context participates
     * in permission checks within {@code action}, enabling delegation patterns
     * where the security context must be constructed or constrained explicitly
     * rather than inherited from the current thread.
     *
     * <p> If {@code acc} is {@code null}, the action is executed with an
     * empty {@code AccessControlContext} containing no {@code ProtectionDomain}s.
     * This discards all caller stack context entirely, producing a stronger
     * privilege boundary than {@link #doAs(Subject, PrivilegedExceptionAction)} —
     * only the {@code Subject}'s principals and the permissions of code
     * executing within {@code action} itself will be considered. This should
     * be used deliberately and with care, as it eliminates all constraints
     * from the calling context.
     *
     * <p> When a {@link java.security.Policy} grants permissions based on
     * both code source and {@code Principal}s, the {@code Subject}'s principals
     * will enable principal-scoped grants for all code executing within
     * {@code action}.
     *
     * <p> The {@link SubjectDomainCombiner} established by this method is not
     * preserved across nested {@link AccessController#doPrivileged(PrivilegedExceptionAction)}
     * calls within {@code action} — the combiner associated with the current
     * {@code AccessControlContext} is silently dropped at each such boundary.
     * To preserve the workload identity across a nested privileged boundary, use
     * {@link AccessController#doPrivilegedWithCombiner(PrivilegedExceptionAction)},
     * which explicitly retrieves and carries forward the current
     * {@link DomainCombiner}. Alternatively, an explicit {@code AccessControlContext}
     * carrying the {@link SubjectDomainCombiner} may be passed to
     * {@link AccessController#doPrivileged(PrivilegedExceptionAction, AccessControlContext)},
     * though this requires the caller to manage the context explicitly.
     *
     * <p> Any threads spawned within {@code action} inherit the
     * {@code AccessControlContext} containing the {@link SubjectDomainCombiner},
     * ensuring the workload identity propagates to child threads automatically.
     * Tasks submitted to an {@link java.util.concurrent.Executor} do not inherit
     * this context and must explicitly re-establish the workload identity if required.
     *
     * <p> This method is intended for workload identity. For user identity in a
     * two-Subject model, use {@link #callAs(Subject, Callable)} instead, which
     * carries the user {@code Subject} as a {@link ScopedValue} without
     * establishing a privileged boundary, remains available across nested
     * {@code doPrivileged} calls, and correctly shadows across nested invocations
     * with different {@code Subject}s.
     *
     * @param subject the {@code Subject} to associate with the execution of
     *                {@code action}. May be {@code null}.
     * @param action  the code to be run as the specified {@code Subject}.
     *                Must not be {@code null}.
     * @param acc     the {@code AccessControlContext} to use as the base context
     *                for permission checks within {@code action}. If {@code null},
     *                an empty context is used, discarding all caller stack context.
     * @param <T>     the type of the value returned by {@code action.run()}
     *
     * @return the value returned by {@code action.run()}
     *
     * @throws NullPointerException if {@code action} is {@code null}
     * @throws PrivilegedActionException if {@code action.run()} throws a
     *         checked exception. The thrown exception is available via
     *         {@link PrivilegedActionException#getException()}
     * @throws SecurityException if a security manager is installed and the caller
     *         does not have {@link AuthPermission}{@code ("doAsPrivileged")}
     *
     * @see #doAsPrivileged(Subject, PrivilegedAction, AccessControlContext)
     * @see #doAs(Subject, PrivilegedExceptionAction)
     * @see #callAs(Subject, Callable)
     * @see AccessController#doPrivilegedWithCombiner(PrivilegedExceptionAction)
     */
    @SuppressWarnings("removal")
    public static <T> T doAsPrivileged(final Subject subject,
                        final java.security.PrivilegedExceptionAction<T> action,
                        final java.security.AccessControlContext acc)
                        throws java.security.PrivilegedActionException {
        if (subject instanceof WorkerSubject)
            throw new IllegalArgumentException(
                "WorkerSubject is established by SPIRE infrastructure");
        if (subject instanceof UserSubject)
            throw new IllegalArgumentException(
                "UserSubject must use Subject.callAs()");
        java.lang.SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(AuthPermissionHolder.DO_AS_PRIVILEGED_PERMISSION);
        }

        Objects.requireNonNull(action,
                ResourcesMgr.getString("invalid.null.action.provided"));

            // set up the new Subject-based AccessControlContext for doPrivileged
            final AccessControlContext callerAcc =
                    (acc == null ?
                            Context.create(NULL_PD_ARRAY) :
                            acc);

            // call doPrivileged and push this new context on the stack
            return java.security.AccessController.doPrivileged
                    (action,
                            createContext(subject, callerAcc));
    }

    @SuppressWarnings("removal")
    private static AccessControlContext createContext(final Subject subject,
                                                      final AccessControlContext acc) {
        if (subject == null) return Context.create(acc, null);
        // Reuse existing combiner if it already wraps the same Subject,
        // avoiding a redundant SubjectDomainCombiner instance and cache miss.
        DomainCombiner existing = Context.combiner(acc);
        if (existing instanceof SubjectDomainCombiner sdc
                && subject.equals(sdc.getSubject())) {
            return acc;
        }
        return Context.create(acc, new SubjectDomainCombiner(subject));
    }
    
    /**
     * Builds AccessControlContext instances or obtains from cache, without
     * permission checks.
     */
    public final static class Context extends AccessControlContext.ContextBuilder {
        
        Context(){}
        
        static final AccessControlContext.ContextBuilder builder = new Context();
        
        static AccessControlContext create(ProtectionDomain [] context){
            return builder.build(context);
        }
        
        static AccessControlContext create(AccessControlContext acc,
                                             DomainCombiner combiner) {
            return builder.build(acc, combiner);
        }
        
        static DomainCombiner combiner(AccessControlContext acc){
            return builder.getCombiner(acc);
        }
    }

    /**
     * Return the {@code Set} of Principals associated with this
     * {@code Subject}.  Each {@code Principal} represents
     * an identity for this {@code Subject}.
     *
     * <p> The returned {@code Set} is backed by this Subject's
     * internal {@code Principal} {@code Set}.  Any modification
     * to the returned {@code Set} affects the internal
     * {@code Principal} {@code Set} as well.
     *
     * <p> If a security manager is installed, the caller must have a
     * {@link AuthPermission#AuthPermission(String)
     * AuthPermission("modifyPrincipals")} permission to modify
     * the returned set, or a {@code SecurityException} will be thrown.
     *
     * @return  the {@code Set} of Principals associated with this
     *          {@code Subject}.
     */
    public Set<Principal> getPrincipals() {

        // always return an empty Set instead of null
        // so LoginModules can add to the Set if necessary
        return principals;
    }

    /**
     * Return a {@code Set} of Principals associated with this
     * {@code Subject} that are instances or subclasses of the specified
     * {@code Class}.
     *
     * <p> The returned {@code Set} is not backed by this Subject's
     * internal {@code Principal} {@code Set}.  A new
     * {@code Set} is created and returned for each method invocation.
     * Modifications to the returned {@code Set}
     * will not affect the internal {@code Principal} {@code Set}.
     *
     * @param <T> the type of the class modeled by {@code c}
     *
     * @param c the returned {@code Set} of Principals will all be
     *          instances of this class.
     *
     * @return a {@code Set} of Principals that are instances of the
     *          specified {@code Class}.
     *
     * @throws NullPointerException if the specified {@code Class}
     *          is {@code null}.
     */
    public <T extends Principal> Set<T> getPrincipals(Class<T> c) {

        Objects.requireNonNull(c,
                ResourcesMgr.getString("invalid.null.Class.provided"));

        // always return an empty Set instead of null
        // so LoginModules can add to the Set if necessary
        return new ClassSet<>(PRINCIPAL_SET, c);
    }

    /**
     * Return the {@code Set} of public credentials held by this
     * {@code Subject}.
     *
     * <p> The returned {@code Set} is backed by this Subject's
     * internal public Credential {@code Set}.  Any modification
     * to the returned {@code Set} affects the internal public
     * Credential {@code Set} as well.
     *
     * <p> If a security manager is installed, the caller must have a
     * {@link AuthPermission#AuthPermission(String)
     * AuthPermission("modifyPublicCredentials")} permission to modify
     * the returned set, or a {@code SecurityException} will be thrown.
     *
     * @return  a {@code Set} of public credentials held by this
     *          {@code Subject}.
     */
    public Set<Object> getPublicCredentials() {

        // always return an empty Set instead of null
        // so LoginModules can add to the Set if necessary
        return pubCredentials;
    }

    /**
     * Return the {@code Set} of private credentials held by this
     * {@code Subject}.
     *
     * <p> The returned {@code Set} is backed by this Subject's
     * internal private Credential {@code Set}.  Any modification
     * to the returned {@code Set} affects the internal private
     * Credential {@code Set} as well.
     *
     * <p> If a security manager is installed, the caller must have a
     * {@link AuthPermission#AuthPermission(String)
     * AuthPermission("modifyPrivateCredentials")} permission to modify
     * the returned set, or a {@code SecurityException} will be thrown.
     *
     * <p> While iterating through the {@code Set},
     * a {@code SecurityException} is thrown if a security manager is installed
     * and the caller does not have a {@link PrivateCredentialPermission}
     * to access a particular Credential.  The {@code Iterator}
     * is nevertheless advanced to the next element in the {@code Set}.
     *
     * @return  a {@code Set} of private credentials held by this
     *          {@code Subject}.
     */
    public Set<Object> getPrivateCredentials() {

        // XXX
        // we do not need a security check for
        // AuthPermission(getPrivateCredentials)
        // because we already restrict access to private credentials
        // via the PrivateCredentialPermission.  all the extra AuthPermission
        // would do is protect the set operations themselves
        // (like size()), which don't seem security-sensitive.

        // always return an empty Set instead of null
        // so LoginModules can add to the Set if necessary
        return privCredentials;
    }

    /**
     * Return a {@code Set} of public credentials associated with this
     * {@code Subject} that are instances or subclasses of the specified
     * {@code Class}.
     *
     * <p> The returned {@code Set} is not backed by this Subject's
     * internal public Credential {@code Set}.  A new
     * {@code Set} is created and returned for each method invocation.
     * Modifications to the returned {@code Set}
     * will not affect the internal public Credential {@code Set}.
     *
     * @param <T> the type of the class modeled by {@code c}
     *
     * @param c the returned {@code Set} of public credentials will all be
     *          instances of this class.
     *
     * @return a {@code Set} of public credentials that are instances
     *          of the  specified {@code Class}.
     *
     * @throws NullPointerException if the specified {@code Class}
     *          is {@code null}.
     */
    public <T> Set<T> getPublicCredentials(Class<T> c) {

        Objects.requireNonNull(c,
                ResourcesMgr.getString("invalid.null.Class.provided"));

        // always return an empty Set instead of null
        // so LoginModules can add to the Set if necessary
        return new ClassSet<>(PUB_CREDENTIAL_SET, c);
    }

    /**
     * Return a {@code Set} of private credentials associated with this
     * {@code Subject} that are instances or subclasses of the specified
     * {@code Class}.
     *
     * <p> If a security manager is installed, the caller must have a
     * {@link PrivateCredentialPermission} to access all of the requested
     * Credentials, or a {@code SecurityException} will be thrown.
     *
     * <p> The returned {@code Set} is not backed by this Subject's
     * internal private Credential {@code Set}.  A new
     * {@code Set} is created and returned for each method invocation.
     * Modifications to the returned {@code Set}
     * will not affect the internal private Credential {@code Set}.
     *
     * @param <T> the type of the class modeled by {@code c}
     *
     * @param c the returned {@code Set} of private credentials will all be
     *          instances of this class.
     *
     * @return a {@code Set} of private credentials that are instances
     *          of the  specified {@code Class}.
     *
     * @throws NullPointerException if the specified {@code Class}
     *          is {@code null}.
     */
    public <T> Set<T> getPrivateCredentials(Class<T> c) {

        // XXX
        // we do not need a security check for
        // AuthPermission(getPrivateCredentials)
        // because we already restrict access to private credentials
        // via the PrivateCredentialPermission.  all the extra AuthPermission
        // would do is protect the set operations themselves
        // (like size()), which don't seem security-sensitive.

        Objects.requireNonNull(c,
                ResourcesMgr.getString("invalid.null.Class.provided"));

        // always return an empty Set instead of null
        // so LoginModules can add to the Set if necessary
        return new ClassSet<>(PRIV_CREDENTIAL_SET, c);
    }

    /**
     * Compares the specified Object with this {@code Subject}
     * for equality.  Returns true if the given object is also a Subject
     * and the two {@code Subject} instances are equivalent.
     * More formally, two {@code Subject} instances are
     * equal if their {@code Principal} and {@code Credential}
     * Sets are equal.
     *
     * @param o Object to be compared for equality with this
     *          {@code Subject}.
     *
     * @return true if the specified Object is equal to this
     *          {@code Subject}.
     *
     * @throws SecurityException if a security manager is installed and the
     *         caller does not have a {@link PrivateCredentialPermission}
     *         permission to access the private credentials for this
     *         {@code Subject} or the provided {@code Subject}.
     */
    @Override
    public boolean equals(Object o) {

        if (this == o) {
            return true;
        }

        if (o instanceof final Subject that) {

            // check the principal and credential sets
            Set<Principal> thatPrincipals;
            synchronized(that.principals) {
                // avoid deadlock from dual locks
                thatPrincipals = new HashSet<>(that.principals);
            }
            if (!principals.equals(thatPrincipals)) {
                return false;
            }

            Set<Object> thatPubCredentials;
            synchronized(that.pubCredentials) {
                // avoid deadlock from dual locks
                thatPubCredentials = new HashSet<>(that.pubCredentials);
            }
            if (!pubCredentials.equals(thatPubCredentials)) {
                return false;
            }

            Set<Object> thatPrivCredentials;
            synchronized(that.privCredentials) {
                // avoid deadlock from dual locks
                thatPrivCredentials = new HashSet<>(that.privCredentials);
            }
            return privCredentials.equals(thatPrivCredentials);
        }
        return false;
    }

    /**
     * Return the String representation of this {@code Subject}.
     *
     * @return the String representation of this {@code Subject}.
     */
    @Override
    public String toString() {
        return toString(true);
    }

    /**
     * package private convenience method to print out the Subject
     * without firing off a security check when trying to access
     * the Private Credentials
     */
    String toString(boolean includePrivateCredentials) {

        String s = ResourcesMgr.getString("Subject.");
        String suffix = "";

        synchronized(principals) {
            for (Principal p : principals) {
                suffix = suffix + ResourcesMgr.getString(".Principal.") +
                        p.toString() + ResourcesMgr.getString("NEWLINE");
            }
        }

        synchronized(pubCredentials) {
            for (Object o : pubCredentials) {
                suffix = suffix +
                        ResourcesMgr.getString(".Public.Credential.") +
                        o.toString() + ResourcesMgr.getString("NEWLINE");
            }
        }

        if (includePrivateCredentials) {
            synchronized(privCredentials) {
                Iterator<Object> pI = privCredentials.iterator();
                while (pI.hasNext()) {
                    try {
                        Object o = pI.next();
                        suffix += ResourcesMgr.getString
                                        (".Private.Credential.") +
                                        o.toString() +
                                        ResourcesMgr.getString("NEWLINE");
                    } catch (SecurityException se) {
                        suffix += ResourcesMgr.getString
                                (".Private.Credential.inaccessible.");
                        break;
                    }
                }
            }
        }
        return s + suffix;
    }

    /**
     * {@return a hashcode for this {@code Subject}}
     *
     * @throws SecurityException if a security manager is installed and the
     *         caller does not have a {@link PrivateCredentialPermission}
     *         permission to access this Subject's private credentials.
     */
    @Override
    public int hashCode() {
        if ( readOnly) return hashCode;
        return computeHashCode();
    }
    
    private int computeHashCode(){

        /*
         * The hashcode is derived exclusive or-ing the
         * hashcodes of this Subject's Principals and credentials.
         *
         * If a particular credential was destroyed
         * ({@code credential.hashCode()} throws an
         * {@code IllegalStateException}),
         * the hashcode for that credential is derived via:
         * {@code credential.getClass().toString().hashCode()}.
         */

        int hashCode = 0;

        synchronized(principals) {
            for (Principal p : principals) {
                hashCode ^= p.hashCode();
            }
        }

        synchronized(pubCredentials) {
            for (Object pubCredential : pubCredentials) {
                hashCode ^= getCredHashCode(pubCredential);
            }
        }
        return hashCode;
    }

    /**
     * get a credential's hashcode
     */
    private int getCredHashCode(Object o) {
        try {
            return o.hashCode();
        } catch (IllegalStateException ise) {
            return o.getClass().toString().hashCode();
        }
    }

    /**
     * Writes this object out to a stream (i.e., serializes it).
     *
     * @param  oos the {@code ObjectOutputStream} to which data is written
     * @throws IOException if an I/O error occurs
     */
    @java.io.Serial
    private void writeObject(java.io.ObjectOutputStream oos)
                throws java.io.IOException {
        synchronized(principals) {
            oos.defaultWriteObject();
        }
    }

    /**
     * Reads this object from a stream (i.e., deserializes it)
     *
     * @param  s the {@code ObjectInputStream} from which data is read
     * @throws IOException if an I/O error occurs
     * @throws ClassNotFoundException if a serialized class cannot be loaded
     */
    @SuppressWarnings("unchecked")
    @java.io.Serial
    private void readObject(java.io.ObjectInputStream s)
                throws java.io.IOException, ClassNotFoundException {

        ObjectInputStream.GetField gf = s.readFields();

        readOnly = gf.get("readOnly", false);

        Set<Principal> inputPrincs = (Set<Principal>)gf.get("principals", null);

        Objects.requireNonNull(inputPrincs,
                ResourcesMgr.getString("invalid.null.input.s."));

        // Rewrap the principals into a SecureSet
        try {
            LinkedList<Principal> principalList = collectionNullClean(inputPrincs);
            principals = Collections.synchronizedSet(new SecureSet<>
                                (this, PRINCIPAL_SET, principalList));
        } catch (NullPointerException npe) {
            // Sometimes people deserialize the principals set only.
            // Subject is not accessible, so just don't fail.
            principals = Collections.synchronizedSet
                        (new SecureSet<>(this, PRINCIPAL_SET));
        }

        // The Credential {@code Set} is not serialized, but we do not
        // want the default deserialization routine to set it to null.
        this.pubCredentials = Collections.synchronizedSet
                        (new SecureSet<>(this, PUB_CREDENTIAL_SET));
        this.privCredentials = Collections.synchronizedSet
                        (new SecureSet<>(this, PRIV_CREDENTIAL_SET));
        if (readOnly) hashCode = computeHashCode();
    }

    /**
     * Tests for null-clean collections (both non-null reference and
     * no null elements)
     *
     * @param coll A {@code Collection} to be tested for null references
     *
     * @throws NullPointerException if the specified collection is either
     *            {@code null} or contains a {@code null} element
     */
    private static <E> LinkedList<E> collectionNullClean(
            Collection<? extends E> coll) {

        Objects.requireNonNull(coll,
                ResourcesMgr.getString("invalid.null.input.s."));

        LinkedList<E> output = new LinkedList<>();
        for (E e : coll) {
            output.add(Objects.requireNonNull(e,
                    ResourcesMgr.getString("invalid.null.input.s.")));
        }
        return output;
    }

    /**
     * Prevent modifications unless caller has permission.
     *
     * @serial include
     */
    private static class SecureSet<E>
        implements Set<E>, java.io.Serializable {

        @java.io.Serial
        private static final long serialVersionUID = 7911754171111800359L;

        /**
         * @serialField this$0 Subject The outer Subject instance.
         * @serialField elements LinkedList The elements in this set.
         */
        @java.io.Serial
        private static final ObjectStreamField[] serialPersistentFields = {
            new ObjectStreamField("this$0", Subject.class),
            new ObjectStreamField("elements", LinkedList.class),
            new ObjectStreamField("which", int.class)
        };

        Subject subject;
        LinkedList<E> elements;

        /**
         * @serial An integer identifying the type of objects contained
         *      in this set.  If {@code which == 1},
         *      this is a Principal set and all the elements are
         *      of type {@code java.security.Principal}.
         *      If {@code which == 2}, this is a public credential
         *      set and all the elements are of type {@code Object}.
         *      If {@code which == 3}, this is a private credential
         *      set and all the elements are of type {@code Object}.
         */
        private int which;

        SecureSet(Subject subject, int which) {
            this.subject = subject;
            this.which = which;
            this.elements = new LinkedList<>();
        }

        SecureSet(Subject subject, int which, LinkedList<E> list) {
            this.subject = subject;
            this.which = which;
            this.elements = list;
        }

        public int size() {
            return elements.size();
        }

        public Iterator<E> iterator() {
            final LinkedList<E> list = elements;
            return new Iterator<>() {
                final ListIterator<E> i = list.listIterator(0);

                public boolean hasNext() {
                    return i.hasNext();
                }

                public E next() {
                    if (which != Subject.PRIV_CREDENTIAL_SET) {
                        return i.next();
                    }

                    @SuppressWarnings("removal")
                    SecurityManager sm = System.getSecurityManager();
                    if (sm != null) {
                        try {
                            sm.checkPermission(new PrivateCredentialPermission
                                (list.get(i.nextIndex()).getClass().getName(),
                                subject.getPrincipals()));
                        } catch (SecurityException se) {
                            i.next();
                            throw (se);
                        }
                    }
                    return i.next();
                }

                public void remove() {

                    if (subject.isReadOnly()) {
                        throw new IllegalStateException(ResourcesMgr.getString
                                ("Subject.is.read.only"));
                    }

                    @SuppressWarnings("removal")
                    java.lang.SecurityManager sm = System.getSecurityManager();
                    if (sm != null) {
                        switch (which) {
                        case Subject.PRINCIPAL_SET:
                            sm.checkPermission(AuthPermissionHolder.MODIFY_PRINCIPALS_PERMISSION);
                            break;
                        case Subject.PUB_CREDENTIAL_SET:
                            sm.checkPermission(AuthPermissionHolder.MODIFY_PUBLIC_CREDENTIALS_PERMISSION);
                            break;
                        default:
                            sm.checkPermission(AuthPermissionHolder.MODIFY_PRIVATE_CREDENTIALS_PERMISSION);
                            break;
                        }
                    }
                    i.remove();
                }
            };
        }

        public boolean add(E o) {

            Objects.requireNonNull(o,
                    ResourcesMgr.getString("invalid.null.input.s."));

            if (subject.isReadOnly()) {
                throw new IllegalStateException
                        (ResourcesMgr.getString("Subject.is.read.only"));
            }

            @SuppressWarnings("removal")
            java.lang.SecurityManager sm = System.getSecurityManager();
            if (sm != null) {
                switch (which) {
                case Subject.PRINCIPAL_SET:
                    sm.checkPermission(AuthPermissionHolder.MODIFY_PRINCIPALS_PERMISSION);
                    break;
                case Subject.PUB_CREDENTIAL_SET:
                    sm.checkPermission(AuthPermissionHolder.MODIFY_PUBLIC_CREDENTIALS_PERMISSION);
                    break;
                default:
                    sm.checkPermission(AuthPermissionHolder.MODIFY_PRIVATE_CREDENTIALS_PERMISSION);
                    break;
                }
            }

            switch (which) {
            case Subject.PRINCIPAL_SET:
                if (!(o instanceof Principal)) {
                    throw new SecurityException(ResourcesMgr.getString
                        ("attempting.to.add.an.object.which.is.not.an.instance.of.java.security.Principal.to.a.Subject.s.Principal.Set"));
                }
                break;
            default:
                // ok to add Objects of any kind to credential sets
                break;
            }

            // check for duplicates
            if (!elements.contains(o))
                return elements.add(o);
            else {
                return false;
        }
        }

        @SuppressWarnings("removal")
        public boolean remove(Object o) {

            Objects.requireNonNull(o,
                    ResourcesMgr.getString("invalid.null.input.s."));

            final Iterator<E> e = iterator();
            while (e.hasNext()) {
                E next;
                if (which != Subject.PRIV_CREDENTIAL_SET) {
                    next = e.next();
                } else {
                    next = java.security.AccessController.doPrivileged
                        (new java.security.PrivilegedAction<E>() {
                        public E run() {
                            return e.next();
                        }
                    });
                }

                if (next.equals(o)) {
                    e.remove();
                    return true;
                }
            }
            return false;
        }

        @SuppressWarnings("removal")
        public boolean contains(Object o) {

            Objects.requireNonNull(o,
                    ResourcesMgr.getString("invalid.null.input.s."));

            final Iterator<E> e = iterator();
            while (e.hasNext()) {
                E next;
                if (which != Subject.PRIV_CREDENTIAL_SET) {
                    next = e.next();
                } else {

                    // For private credentials:
                    // If the caller does not have read permission
                    // for o.getClass(), we throw a SecurityException.
                    // Otherwise, we check the private cred set to see whether
                    // it contains the Object

                    SecurityManager sm = System.getSecurityManager();
                    if (sm != null) {
                        sm.checkPermission(new PrivateCredentialPermission
                                                (o.getClass().getName(),
                                                subject.getPrincipals()));
                    }
                    next = java.security.AccessController.doPrivileged
                        (new java.security.PrivilegedAction<E>() {
                        public E run() {
                            return e.next();
                        }
                    });
                }

                if (next.equals(o)) {
                    return true;
                }
            }
            return false;
        }

        public boolean addAll(Collection<? extends E> c) {
            boolean result = false;

            c = collectionNullClean(c);

            for (E item : c) {
                result |= this.add(item);
            }

            return result;
        }

        @SuppressWarnings("removal")
        public boolean removeAll(Collection<?> c) {
            c = collectionNullClean(c);

            boolean modified = false;
            final Iterator<E> e = iterator();
            while (e.hasNext()) {
                E next;
                if (which != Subject.PRIV_CREDENTIAL_SET) {
                    next = e.next();
                } else {
                    next = java.security.AccessController.doPrivileged
                        (new java.security.PrivilegedAction<E>() {
                        public E run() {
                            return e.next();
                        }
                    });
                }

                for (Object o : c) {
                    if (next.equals(o)) {
                        e.remove();
                        modified = true;
                        break;
                    }
                }
            }
            return modified;
        }

        public boolean containsAll(Collection<?> c) {
            c = collectionNullClean(c);

            for (Object item : c) {
                if (!this.contains(item)) {
                    return false;
                }
            }

            return true;
        }

        @SuppressWarnings("removal")
        public boolean retainAll(Collection<?> c) {
            c = collectionNullClean(c);

            boolean modified = false;
            final Iterator<E> e = iterator();
            while (e.hasNext()) {
                E next;
                if (which != Subject.PRIV_CREDENTIAL_SET) {
                    next = e.next();
                } else {
                    next = java.security.AccessController.doPrivileged
                        (new java.security.PrivilegedAction<E>() {
                        public E run() {
                            return e.next();
                        }
                    });
                }

                if (c.contains(next) == false) {
                    e.remove();
                    modified = true;
                }
            }

            return modified;
        }

        @SuppressWarnings("removal")
        public void clear() {
            final Iterator<E> e = iterator();
            while (e.hasNext()) {
                E next;
                if (which != Subject.PRIV_CREDENTIAL_SET) {
                    next = e.next();
                } else {
                    next = java.security.AccessController.doPrivileged
                        (new java.security.PrivilegedAction<E>() {
                        public E run() {
                            return e.next();
                        }
                    });
                }
                e.remove();
            }
        }

        public boolean isEmpty() {
            return elements.isEmpty();
        }

        public Object[] toArray() {
            final Iterator<E> e = iterator();
            while (e.hasNext()) {
                // The next() method performs a security manager check
                // on each element in the SecureSet.  If we make it all
                // the way through we should be able to simply return
                // element's toArray results.  Otherwise, we'll let
                // the SecurityException pass up the call stack.
                e.next();
            }

            return elements.toArray();
        }

        public <T> T[] toArray(T[] a) {
            final Iterator<E> e = iterator();
            while (e.hasNext()) {
                // The next() method performs a security manager check
                // on each element in the SecureSet.  If we make it all
                // the way through we should be able to simply return
                // element's toArray results.  Otherwise, we'll let
                // the SecurityException pass up the call stack.
                e.next();
            }

            return elements.toArray(a);
        }

        @Override
        public boolean equals(Object o) {
            if (o == this) {
                return true;
            }

            if (!(o instanceof Set)) {
                return false;
            }

            Collection<?> c = (Collection<?>) o;
            if (c.size() != size()) {
                return false;
            }

            try {
                return containsAll(c);
            } catch (ClassCastException | NullPointerException unused) {
                return false;
            }
        }

        @Override
        public int hashCode() {
            int h = 0;
            for (E obj : this) {
                h += Objects.hashCode(obj);
            }
            return h;
        }

        /**
         * Writes this object out to a stream (i.e., serializes it).
         *
         * @serialData If this is a private credential set,
         *      a security check is performed to ensure that
         *      the caller has permission to access each credential
         *      in the set.  If the security check passes,
         *      the set is serialized.
         *
         * @param  oos the {@code ObjectOutputStream} to which data is written
         * @throws IOException if an I/O error occurs
         */
        @java.io.Serial
        private void writeObject(java.io.ObjectOutputStream oos)
                throws java.io.IOException {

            if (which == Subject.PRIV_CREDENTIAL_SET) {
                // check permissions before serializing
                Iterator<E> i = iterator();
                while (i.hasNext()) {
                    i.next();
                }
            }
            ObjectOutputStream.PutField fields = oos.putFields();
            fields.put("this$0", subject);
            fields.put("elements", elements);
            fields.put("which", which);
            oos.writeFields();
        }

        /**
         * Restores the state of this object from the stream.
         *
         * @param  ois the {@code ObjectInputStream} from which data is read
         * @throws IOException if an I/O error occurs
         * @throws ClassNotFoundException if a serialized class cannot be loaded
         */
        @SuppressWarnings("unchecked")
        @java.io.Serial
        private void readObject(ObjectInputStream ois)
            throws IOException, ClassNotFoundException
        {
            ObjectInputStream.GetField fields = ois.readFields();
            subject = (Subject) fields.get("this$0", null);
            which = fields.get("which", 0);

            LinkedList<E> tmp = (LinkedList<E>) fields.get("elements", null);

            elements = Subject.collectionNullClean(tmp);
        }

    }

    /**
     * This class implements a {@code Set} which returns only
     * members that are an instance of a specified Class.
     */
    private class ClassSet<T> extends AbstractSet<T> {

        private final int which;
        private final Class<T> c;
        private final Set<T> set;

        ClassSet(int which, Class<T> c) {
            this.which = which;
            this.c = c;
            set = new LinkedHashSet<>();

            switch (which) {
            case Subject.PRINCIPAL_SET:
                synchronized(principals) { populateSet(); }
                break;
            case Subject.PUB_CREDENTIAL_SET:
                synchronized(pubCredentials) { populateSet(); }
                break;
            default:
                synchronized(privCredentials) { populateSet(); }
                break;
            }
        }

        @SuppressWarnings({"removal","unchecked"})     /*To suppress warning from line 1374*/
        private void populateSet() {
            final Iterator<?> iterator;
            switch(which) {
            case Subject.PRINCIPAL_SET:
                iterator = Subject.this.principals.iterator();
                break;
            case Subject.PUB_CREDENTIAL_SET:
                iterator = Subject.this.pubCredentials.iterator();
                break;
            default:
                iterator = Subject.this.privCredentials.iterator();
                break;
            }

            // Check whether the caller has permission to get
            // credentials of Class c

            while (iterator.hasNext()) {
                Object next;
                if (which == Subject.PRIV_CREDENTIAL_SET) {
                    next = java.security.AccessController.doPrivileged
                        (new java.security.PrivilegedAction<>() {
                        public Object run() {
                            return iterator.next();
                        }
                    });
                } else {
                    next = iterator.next();
                }
                if (c.isAssignableFrom(next.getClass())) {
                    if (which != Subject.PRIV_CREDENTIAL_SET) {
                        set.add((T)next);
                    } else {
                        // Check permission for private creds
                        SecurityManager sm = System.getSecurityManager();
                        if (sm != null) {
                            sm.checkPermission(new PrivateCredentialPermission
                                                (next.getClass().getName(),
                                                Subject.this.getPrincipals()));
                        }
                        set.add((T)next);
                    }
                }
            }
        }

        @Override
        public int size() {
            return set.size();
        }

        @Override
        public Iterator<T> iterator() {
            return set.iterator();
        }

        @Override
        public boolean add(T o) {

            if (!c.isAssignableFrom(o.getClass())) {
                MessageFormat form = new MessageFormat(ResourcesMgr.getString
                        ("attempting.to.add.an.object.which.is.not.an.instance.of.class"));
                Object[] source = {c.toString()};
                throw new SecurityException(form.format(source));
            }

            return set.add(o);
        }
    }

    static final class AuthPermissionHolder {
        static final AuthPermission CALL_AS_PERMISSION =
            new AuthPermission("callAs");
        
        static final AuthPermission DO_AS_PERMISSION =
            new AuthPermission("doAs");

        static final AuthPermission DO_AS_PRIVILEGED_PERMISSION =
            new AuthPermission("doAsPrivileged");

        static final AuthPermission SET_READ_ONLY_PERMISSION =
            new AuthPermission("setReadOnly");

        static final AuthPermission GET_SUBJECT_PERMISSION =
            new AuthPermission("getSubject");

        static final AuthPermission MODIFY_PRINCIPALS_PERMISSION =
            new AuthPermission("modifyPrincipals");

        static final AuthPermission MODIFY_PUBLIC_CREDENTIALS_PERMISSION =
            new AuthPermission("modifyPublicCredentials");

        static final AuthPermission MODIFY_PRIVATE_CREDENTIALS_PERMISSION =
            new AuthPermission("modifyPrivateCredentials");
    }
}

/*
 * Copyright (c) 1999, 2021, Oracle and/or its affiliates. All rights reserved.
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

import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.ProtectionDomain;
import java.security.DomainIdentity;
import java.util.Set;
import java.util.HashSet;
import java.util.Iterator;
import sun.security.util.SecurityConstants;

/**
 * A {@code SubjectDomainCombiner} updates ProtectionDomains
 * with Principals from the {@code Subject} associated with this
 * {@code SubjectDomainCombiner}.
 *
 * <p> Deprecated since 17, removed or disabled since 24, 
 * retained and maintained operational for Authorization.
 * 
 * @since 1.4
 */
// * @deprecated This class is only useful in conjunction with
// *       {@linkplain SecurityManager the Security Manager}, which is deprecated
// *       and subject to removal in a future release. Consequently, this class
// *       is also deprecated and subject to removal. There is no replacement for
// *       the Security Manager or this class.
// */
@SuppressWarnings("removal")
//@Deprecated(since="17", forRemoval=true)
public class SubjectDomainCombiner implements java.security.DomainCombiner {

    private final Subject subject;
    private final int hashCode;
    private final Principal[] principals;

    private static final sun.security.util.Debug debug =
        sun.security.util.Debug.getInstance("combiner",
                                        "\t[SubjectDomainCombiner]");

    /**
     * Associate the provided {@code Subject} with this
     * {@code SubjectDomainCombiner}.
     *
     * @param subject the {@code Subject} to be associated with
     *          this {@code SubjectDomainCombiner}.
     */
    public SubjectDomainCombiner(Subject subject) {
        this(notNull(subject), true);
    }
    
    private SubjectDomainCombiner(Subject subject, boolean checked){
        this.subject = subject;

        if (subject.isReadOnly()) {
            Set<Principal> principalSet = subject.getPrincipals();
            principals = principalSet.toArray
                        (new Principal[principalSet.size()]);
            this.hashCode = subject.hashCode();
        } else {
            principals = null;
            this.hashCode = System.identityHashCode(subject);
        }
    }
    
    private static Subject notNull(Subject subject) throws NullPointerException {
        if (subject == null) throw new NullPointerException("Subject cannot be null");
        return subject;
    }

    /**
     * Get the {@code Subject} associated with this
     * {@code SubjectDomainCombiner}.
     *
     * @return the {@code Subject} associated with this
     *          {@code SubjectDomainCombiner}, or {@code null}
     *          if no {@code Subject} is associated with this
     *          {@code SubjectDomainCombiner}.
     *
     * @exception SecurityException if the caller does not have permission
     *          to get the {@code Subject} associated with this
     *          {@code SubjectDomainCombiner}.
     */
    public Subject getSubject() {
        java.lang.SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new AuthPermission
                ("getSubjectFromDomainCombiner"));
        }
        return subject;
    }

    /**
     * Update the relevant ProtectionDomains with the Principals
     * from the {@code Subject} associated with this
     * {@code SubjectDomainCombiner}.
     *
     * <p> A new {@code ProtectionDomain} instance is created
     * for each non-static {@code ProtectionDomain} (
     * (staticPermissionsOnly() == false)
     * in the {@code currentDomains} array.  Each new {@code ProtectionDomain}
     * instance is created using the {@code CodeSource},
     * {@code Permission}s and {@code ClassLoader}
     * from the corresponding {@code ProtectionDomain} in
     * {@code currentDomains}, as well as with the Principals from
     * the {@code Subject} associated with this
     * {@code SubjectDomainCombiner}. Static ProtectionDomains are
     * combined as-is and no new instance is created.
     *
     * <p> All of the ProtectionDomains (static and newly instantiated) are
     * combined into a new array.  The ProtectionDomains from the
     * {@code assignedDomains} array are appended to this new array,
     * and the result is returned.
     *
     * <p> Note that optimizations such as the removal of duplicate
     * ProtectionDomains may have occurred.
     * In addition, caching of ProtectionDomains may be permitted.
     *
     * @param currentDomains the ProtectionDomains associated with the
     *          current execution Thread, up to the most recent
     *          privileged {@code ProtectionDomain}.
     *          The ProtectionDomains are listed in order of execution,
     *          with the most recently executing {@code ProtectionDomain}
     *          residing at the beginning of the array. This parameter may
     *          be {@code null} if the current execution Thread
     *          has no associated ProtectionDomains.
     *
     * @param assignedDomains the ProtectionDomains inherited from the
     *          parent Thread, or the ProtectionDomains from the
     *          privileged {@code context}, if a call to
     *          {@code AccessController.doPrivileged(..., context)}
     *          had occurred  This parameter may be {@code null}
     *          if there were no ProtectionDomains inherited from the
     *          parent Thread, or from the privileged {@code context}.
     *
     * @return a new array consisting of the updated ProtectionDomains,
     *          or {@code null}.
     */
    public ProtectionDomain[] combine(ProtectionDomain[] currentDomains,
                                ProtectionDomain[] assignedDomains) {
        if (debug != null) {
            if (subject == null) {
                debug.println("null subject");
            } else {
                final Subject s = subject;
                AccessController.doPrivileged
                    (new java.security.PrivilegedAction<Void>() {
                    public Void run() {
                        debug.println(s.toString());
                        return null;
                    }
                });
            }
            printInputDomains(currentDomains, assignedDomains);
        }

        if (currentDomains == null || currentDomains.length == 0) {
            // No need to optimize assignedDomains because it should
            // have been previously optimized (when it was set).

            // Note that we are returning a direct reference
            // to the input array - since ACC does not clone
            // the arrays when it calls combiner.combine,
            // multiple ACC instances may share the same
            // array instance in this case

            return assignedDomains;
        }

        // optimize currentDomains
        //
        // No need to optimize assignedDomains because it should
        // have been previously optimized (when it was set).

        if (debug != null) {
            debug.println("after optimize");
            printInputDomains(currentDomains, assignedDomains);
        }

        if (currentDomains == null && assignedDomains == null) {
            return null;
        }

        int cLen = (currentDomains == null ? 0 : currentDomains.length);
        int aLen = (assignedDomains == null ? 0 : assignedDomains.length);
    
        Set<ProtectionDomain> domainSet = new HashSet<>(cLen + aLen);

        Principal [] principals;
        if (subject.isReadOnly()){
            principals = this.principals;
        } else { // Mutable Subject, got to check it every time.
            Set<Principal> newSet = subject.getPrincipals();

            principals = newSet.toArray
                    (new Principal[newSet.size()]);

            if (debug != null) {
                debug.println("Subject is mutable");
            }
        }

        for (int i = 0; i < cLen; i++) {
            ProtectionDomain pd = currentDomains[i];
            if (pd == null) continue;
            ProtectionDomain subjectPd;
            if (pd.staticPermissionsOnly() || pd.implies(SecurityConstants.ALL_PERMISSION)) {
                // keep static ProtectionDomain objects static, no point
                // adding Principals to privileged domains.
                subjectPd = pd;
            } else {
                subjectPd = new DomainIdentity(pd.getCodeSource(),
                                        pd.getPermissions(),
                                        pd.getClassLoader(),
                                        principals);
            }
            domainSet.add(subjectPd);
        }
        
        if (debug != null) {
            debug.println("updated current: ");
            Iterator<ProtectionDomain> it = domainSet.iterator();
            int i = 0;
            while (it.hasNext()) {
                debug.println("\tupdated[" + i + "] = " +
                                printDomain(it.next()));
                i++;
            }
        }

        // now add on the assigned domains
        for (int i = 0; i < aLen; i++) {
            ProtectionDomain domain = assignedDomains[i];
            if (domain == null) continue;
            domainSet.add(domain);
        }

        // the ProtectionDomains for the new AccessControlContext
        // that we will return
        ProtectionDomain[] newDomains = domainSet.toArray(new ProtectionDomain[domainSet.size()]);

        if (debug != null) {
            if (newDomains == null || newDomains.length == 0) {
                debug.println("returning null");
            } else {
                debug.println("combinedDomains: ");
                for (int i = 0; i < newDomains.length; i++) {
                    debug.println("newDomain " + i + ": " +
                                  printDomain(newDomains[i]));
                }
            }
        }

        // return the new ProtectionDomains
        if (newDomains == null || newDomains.length == 0) {
            return null;
        } else {
            return newDomains;
        }
    }

    private static void printInputDomains(ProtectionDomain[] currentDomains,
                                ProtectionDomain[] assignedDomains) {
        if (currentDomains == null || currentDomains.length == 0) {
            debug.println("currentDomains null or 0 length");
        } else {
            for (int i = 0; currentDomains != null &&
                        i < currentDomains.length; i++) {
                if (currentDomains[i] == null) {
                    debug.println("currentDomain " + i + ": SystemDomain");
                } else {
                    debug.println("currentDomain " + i + ": " +
                                printDomain(currentDomains[i]));
                }
            }
        }

        if (assignedDomains == null || assignedDomains.length == 0) {
            debug.println("assignedDomains null or 0 length");
        } else {
            debug.println("assignedDomains = ");
            for (int i = 0; assignedDomains != null &&
                        i < assignedDomains.length; i++) {
                if (assignedDomains[i] == null) {
                    debug.println("assignedDomain " + i + ": SystemDomain");
                } else {
                    debug.println("assignedDomain " + i + ": " +
                                printDomain(assignedDomains[i]));
                }
            }
        }
    }

    private static String printDomain(final ProtectionDomain pd) {
        if (pd == null) {
            return "null";
        }
        return AccessController.doPrivileged(new PrivilegedAction<String>() {
            public String run() {
                return pd.toString();
            }
        });
    }
}

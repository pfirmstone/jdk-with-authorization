/*
 * Copyright (c) 2000, 2022, Oracle and/or its affiliates. All rights reserved.
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

package javax.security.auth.kerberos;

import java.io.*;
import java.security.BasicPermission;
import java.security.Permission;
import java.security.PermissionCollection;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * This class is used to restrict the usage of the Kerberos
 * delegation model, ie: forwardable and proxiable tickets.
 * <p>
 * The target name of this {@code Permission} specifies a pair of
 * kerberos service principals. The first is the subordinate service principal
 * being entrusted to use the TGT. The second service principal designates
 * the target service the subordinate service principal is to
 * interact with on behalf of the initiating KerberosPrincipal. This
 * latter service principal is specified to restrict the use of a
 * proxiable ticket.
 * <p>
 * For example, to specify the "host" service use of a forwardable TGT the
 * target permission is specified as follows:
 *
 * <pre>
 *  DelegationPermission("\"host/foo.example.com@EXAMPLE.COM\" \"krbtgt/EXAMPLE.COM@EXAMPLE.COM\"");
 * </pre>
 * <p>
 * To give the "backup" service a proxiable nfs service ticket the target permission
 * might be specified:
 *
 * <pre>
 *  DelegationPermission("\"backup/bar.example.com@EXAMPLE.COM\" \"nfs/home.EXAMPLE.COM@EXAMPLE.COM\"");
 * </pre>
 *
 * @since 1.4
 */

public final class DelegationPermission 
        extends BasicPermission<DelegationPermission>{

    private transient String subordinate, service;

    /**
     * Create a new {@code DelegationPermission}
     * with the specified subordinate and target principals.
     *
     * @param principals the name of the subordinate and target principals
     *
     * @throws NullPointerException if {@code principals} is {@code null}.
     * @throws IllegalArgumentException if {@code principals} is empty,
     *      or does not contain a pair of principals, or is improperly quoted
     */
    public DelegationPermission(String principals) {
        this(principals, null);
    }

    /**
     * Create a new {@code DelegationPermission}
     * with the specified subordinate and target principals.
     *
     * @param principals the name of the subordinate and target principals
     *
     * @param actions should be null.
     *
     * @throws NullPointerException if {@code principals} is {@code null}.
     * @throws IllegalArgumentException if {@code principals} is empty,
     *      or does not contain a pair of principals, or is improperly quoted
     */
    public DelegationPermission(String principals, String actions) {
        this(new Init(principals), principals, actions);
    }
    
    private DelegationPermission(Init i, String principals, String actions){
        super(principals, actions);
        this.subordinate = i.subordinate;
        this.service = i.service;
    }
    
    /**
     * Initialize the DelegationPermission object.
     */
    private static class Init {
        private String subordinate, service;
        
        Init(String target){
            // 7 tokens in a string:
            //    "subordinate@R1" "service@R2"
            //    1<------2----->345<----6--->7
            StringTokenizer t = new StringTokenizer(target, "\"", true);
            try {
                if (!t.nextToken().equals("\"")) { // 1
                    throw new IllegalArgumentException("Illegal input [" + target
                            + "]: improperly quoted");
                }
                subordinate = t.nextToken(); // 2
                if (subordinate.equals("\"")) {
                    throw new IllegalArgumentException("Illegal input [" + target
                            + "]: bad subordinate name");
                }
                t.nextToken(); // 3
                if (!t.nextToken().trim().isEmpty()) { // 4
                    throw new IllegalArgumentException("Illegal input [" + target
                            + "]: improperly separated");
                }
                t.nextToken(); // 5
                service = t.nextToken(); // 6
                if (service.equals("\"")) {
                    throw new IllegalArgumentException("Illegal input [" + target
                            + "]: bad service name");
                }
                t.nextToken(); // 7
            } catch (NoSuchElementException e) {
                throw new IllegalArgumentException("Illegal input [" + target
                        + "]: not enough input");
            }
            if (t.hasMoreTokens()) {
                throw new IllegalArgumentException("Illegal input [" + target
                        + "]: extra input");
            }
        }
    }

    /**
     * Checks if this Kerberos delegation permission object "implies" the
     * specified permission.
     * <P>
     * This method returns true if this {@code DelegationPermission}
     * is equal to {@code p}, and returns false otherwise.
     *
     * @param p the permission to check against.
     *
     * @return true if the specified permission is implied by this object,
     * false if not.
     */
    @Override
    public boolean implies(Permission p) {
        return equals(p);
    }

    /**
     * Checks two DelegationPermission objects for equality.
     *
     * @param obj the object to test for equality with this object.
     *
     * @return true if {@code obj} is a DelegationPermission, and
     *  has the same subordinate and service principal as this
     *  DelegationPermission object.
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }

        return obj instanceof DelegationPermission that
                && this.subordinate.equals(that.subordinate)
                && this.service.equals(that.service);
    }

    /**
     * {@return the hash code value for this object}
     */
    @Override
    public int hashCode() {
        return Objects.hash(subordinate, service);
    }

    /**
     * Returns a PermissionCollection object for storing
     * DelegationPermission objects.
     * <br>
     * DelegationPermission objects must be stored in a manner that
     * allows them to be inserted into the collection in any order, but
     * that also enables the PermissionCollection implies method to
     * be implemented in an efficient (and consistent) manner.
     *
     * @return a new PermissionCollection object suitable for storing
     * DelegationPermissions.
     */
    @Override
    public PermissionCollection<DelegationPermission> newPermissionCollection() {
        return new KrbDelegationPermissionCollection();
    }
}


final class KrbDelegationPermissionCollection 
        extends PermissionCollection<DelegationPermission>{

    // Not serialized; see serialization section at end of class.
    private final ConcurrentHashMap<DelegationPermission, Boolean> perms;

    public KrbDelegationPermissionCollection() {
        perms = new ConcurrentHashMap<>();
    }

    /**
     * Check and see if this collection of permissions implies the permissions
     * expressed in "permission".
     *
     * @param permission the Permission object to compare
     *
     * @return true if "permission" is a proper subset of a permission in
     * the collection, false if not.
     */
    @Override
    public boolean implies(Permission permission) {
        if (! (permission instanceof DelegationPermission))
            return false;

        // if map contains key, then it automatically implies it
        return perms.containsKey(permission);
    }

    /**
     * Adds a permission to the DelegationPermissions. The key for
     * the hash is the name.
     *
     * @param permission the Permission object to add.
     *
     * @exception IllegalArgumentException - if the permission is not a
     *                                       DelegationPermission
     *
     * @exception SecurityException - if this PermissionCollection object
     *                                has been marked readonly
     */
    @Override
    public void add(DelegationPermission permission) {
        if (! (permission instanceof DelegationPermission))
            throw new IllegalArgumentException("invalid permission: "+
                                               permission);
        if (isReadOnly())
            throw new SecurityException("attempt to add a Permission to a readonly PermissionCollection");

        perms.put(permission, Boolean.TRUE);
    }

    /**
     * Returns an enumeration of all the DelegationPermission objects
     * in the container.
     *
     * @return an enumeration of all the DelegationPermission objects.
     */
    @Override
    public Enumeration<DelegationPermission> elements() {
        return perms.keys();
    }
}

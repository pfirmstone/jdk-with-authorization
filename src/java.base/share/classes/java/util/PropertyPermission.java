/*
 * Copyright (c) 1997, 2023, Oracle and/or its affiliates. All rights reserved.
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

package java.util;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamField;
import java.io.Serializable;
import java.security.*;
import java.util.concurrent.ConcurrentHashMap;
import sun.security.util.SecurityConstants;

/**
 * This class is for property permissions.
 *
 * <P>
 * The name is the name of the property ("java.home",
 * "os.name", etc). The naming
 * convention follows the  hierarchical property naming convention.
 * Also, an asterisk
 * may appear at the end of the name, following a ".", or by itself, to
 * signify a wildcard match. For example: "java.*" and "*" signify a wildcard
 * match, while "*java" and "a*b" do not.
 * <P>
 * The actions to be granted are passed to the constructor in a string containing
 * a list of one or more comma-separated keywords. The possible keywords are
 * "read" and "write". Their meaning is defined as follows:
 *
 * <DL>
 *    <DT> read
 *    <DD> read permission. Allows {@code System.getProperty} to
 *         be called.
 *    <DT> write
 *    <DD> write permission. Allows {@code System.setProperty} to
 *         be called.
 * </DL>
 * <P>
 * The actions string is converted to lowercase before processing.
 * <P>
 * Care should be taken before granting code permission to access
 * certain system properties.  For example, granting permission to
 * access the "java.home" system property gives potentially malevolent
 * code sensitive information about the system environment (the Java
 * installation directory).  Also, granting permission to access
 * the "user.name" and "user.home" system properties gives potentially
 * malevolent code sensitive information about the user environment
 * (the user's account name and home directory).
 *
 * @see java.security.BasicPermission
 * @see java.security.Permission
 * @see java.security.Permissions
 * @see java.security.PermissionCollection
 * @see java.lang.SecurityManager
 *
 *
 * @author Roland Schemers
 * @since 1.2
 *
 * @serial exclude
 */

public final class PropertyPermission extends BasicPermission<PropertyPermission> {

    /**
     * Read action.
     */
    private static final int READ    = 0x1;

    /**
     * Write action.
     */
    private static final int WRITE   = 0x2;
    /**
     * All actions (read,write);
     */
    private static final int ALL     = READ|WRITE;
    /**
     * No actions.
     */
    private static final int NONE    = 0x0;

    /**
     * The actions mask.
     *
     */
    private final int mask;

    /**
     * The actions string.
     *
     */
    private final String actions; // Left null as long as possible, then
                            // created and re-used in the getAction function.

    /**
     * initialize a PropertyPermission object. Common to all constructors.
     * Also called during de-serialization.
     *
     * @param mask the actions mask to use.
     *
     */
    private static int init(String name, int mask) {
        if ((mask & ALL) != mask)
            throw new IllegalArgumentException("invalid actions mask");

        if (mask == NONE)
            throw new IllegalArgumentException("invalid actions mask");

        if (name == null)
            throw new NullPointerException("name can't be null");

        return mask;
    }

    /**
     * Creates a new PropertyPermission object with the specified name.
     * The name is the name of the system property, and
     * <i>actions</i> contains a comma-separated list of the
     * desired actions granted on the property. Possible actions are
     * "read" and "write".
     *
     * @param name the name of the PropertyPermission.
     * @param actions the actions string.
     *
     * @throws NullPointerException if {@code name} is {@code null}.
     * @throws IllegalArgumentException if {@code name} is empty or if
     * {@code actions} is invalid.
     */
    public PropertyPermission(String name, String actions) {
        this(name, actions, init(name, getMask(actions)));
    }

    /**
     * Creates a PropertyPermission object with the specified name and
     * a pre-calculated mask. Avoids the overhead of re-computing the mask.
     * Called by PropertyPermissionCollection.
     */
    PropertyPermission(String name, int mask) {
        this(name, getActions(mask), mask);
    }
    
    private PropertyPermission(String name, String actions, int mask){
        super(name, actions);
        this.mask = mask;
        this.actions = getActions(mask);
    }

    /**
     * Checks if this PropertyPermission object "implies" the specified
     * permission.
     * <P>
     * More specifically, this method returns true if:
     * <ul>
     * <li> <i>p</i> is an instanceof PropertyPermission,
     * <li> <i>p</i>'s actions are a subset of this
     * object's actions, and
     * <li> <i>p</i>'s name is implied by this object's
     *      name. For example, "java.*" implies "java.home".
     * </ul>
     * @param p the permission to check against.
     *
     * @return true if the specified permission is implied by this object,
     * false if not.
     */
    @Override
    public boolean implies(Permission p) {
        // we get the effective mask. i.e., the "and" of this and that.
        // They must be equal to that.mask for implies to return true.
        return p instanceof PropertyPermission that
                && ((this.mask & that.mask) == that.mask)
                && super.implies(that);
    }

    /**
     * Checks two PropertyPermission objects for equality. Checks that <i>obj</i> is
     * a PropertyPermission, and has the same name and actions as this object.
     *
     * @param obj the object we are testing for equality with this object.
     * @return true if obj is a PropertyPermission, and has the same name and
     * actions as this PropertyPermission object.
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == this)
            return true;

        return obj instanceof PropertyPermission that
                && this.mask == that.mask
                && this.getName().equals(that.getName());
    }

    /**
     * Returns the hash code value for this object.
     * The hash code used is the hash code of this permissions name, that is,
     * {@code getName().hashCode()}, where {@code getName} is
     * from the Permission superclass.
     *
     * @return a hash code value for this object.
     */
    @Override
    public int hashCode() {
        return this.getName().hashCode();
    }

    /**
     * Converts an actions String to an actions mask.
     *
     * @param actions the action string.
     * @return the actions mask.
     */
    private static int getMask(String actions) {

        int mask = NONE;

        if (actions == null) {
            return mask;
        }

        // Use object identity comparison against known-interned strings for
        // performance benefit (these values are used heavily within the JDK).
        if (actions == SecurityConstants.PROPERTY_READ_ACTION) {
            return READ;
        } if (actions == SecurityConstants.PROPERTY_WRITE_ACTION) {
            return WRITE;
        } else if (actions == SecurityConstants.PROPERTY_RW_ACTION) {
            return READ|WRITE;
        }

        char[] a = actions.toCharArray();

        int i = a.length - 1;
        if (i < 0)
            return mask;

        while (i != -1) {
            char c;

            // skip whitespace
            while ((i!=-1) && ((c = a[i]) == ' ' ||
                               c == '\r' ||
                               c == '\n' ||
                               c == '\f' ||
                               c == '\t'))
                i--;

            // check for the known strings
            int matchlen;

            if (i >= 3 && (a[i-3] == 'r' || a[i-3] == 'R') &&
                          (a[i-2] == 'e' || a[i-2] == 'E') &&
                          (a[i-1] == 'a' || a[i-1] == 'A') &&
                          (a[i] == 'd' || a[i] == 'D'))
            {
                matchlen = 4;
                mask |= READ;

            } else if (i >= 4 && (a[i-4] == 'w' || a[i-4] == 'W') &&
                                 (a[i-3] == 'r' || a[i-3] == 'R') &&
                                 (a[i-2] == 'i' || a[i-2] == 'I') &&
                                 (a[i-1] == 't' || a[i-1] == 'T') &&
                                 (a[i] == 'e' || a[i] == 'E'))
            {
                matchlen = 5;
                mask |= WRITE;

            } else {
                // parse error
                throw new IllegalArgumentException(
                        "invalid permission: " + actions);
            }

            // make sure we didn't just match the tail of a word
            // like "ackbarfaccept".  Also, skip to the comma.
            boolean seencomma = false;
            while (i >= matchlen && !seencomma) {
                switch(a[i-matchlen]) {
                case ',':
                    seencomma = true;
                    break;
                case ' ': case '\r': case '\n':
                case '\f': case '\t':
                    break;
                default:
                    throw new IllegalArgumentException(
                            "invalid permission: " + actions);
                }
                i--;
            }

            // point i at the location of the comma minus one (or -1).
            i -= matchlen;
        }

        return mask;
    }


    /**
     * Return the canonical string representation of the actions.
     * Always returns present actions in the following order:
     * read, write.
     *
     * @return the canonical string representation of the actions.
     */
    static String getActions(int mask) {
        return switch (mask & (READ | WRITE)) {
            case READ         -> SecurityConstants.PROPERTY_READ_ACTION;
            case WRITE        -> SecurityConstants.PROPERTY_WRITE_ACTION;
            case READ | WRITE -> SecurityConstants.PROPERTY_RW_ACTION;
            default           -> "";
        };
    }

    /**
     * Returns the "canonical string representation" of the actions.
     * That is, this method always returns present actions in the following order:
     * read, write. For example, if this PropertyPermission object
     * allows both write and read actions, a call to {@code getActions}
     * will return the string "read,write".
     *
     * @return the canonical string representation of the actions.
     */
    @Override
    public String getActions() {
        return actions;
    }

    /**
     * Return the current action mask.
     * Used by the PropertyPermissionCollection
     *
     * @return the actions mask.
     */
    int getMask() {
        return mask;
    }

    /**
     * Returns a new PermissionCollection object for storing
     * PropertyPermission objects.
     *
     * @return a new PermissionCollection object suitable for storing
     * PropertyPermissions.
     */
    @Override
    public PermissionCollection<PropertyPermission> newPermissionCollection() {
        return new PropertyPermissionCollection();
    }
}

/**
 * A PropertyPermissionCollection stores a set of PropertyPermission
 * permissions.
 *
 * @see java.security.Permission
 * @see java.security.Permissions
 * @see java.security.PermissionCollection
 *
 *
 * @author Roland Schemers
 *
 * @serial include
 */
final class PropertyPermissionCollection extends PermissionCollection<PropertyPermission>
{

    /**
     * Key is property name; value is PropertyPermission.
     * Not serialized; see serialization section at end of class.
     */
    private final ConcurrentHashMap<String, PropertyPermission> perms;

    /**
     * Boolean saying if "*" is in the collection.
     *
     */
    private volatile boolean all_allowed;

    /**
     * Create an empty PropertyPermissionCollection object.
     */
    public PropertyPermissionCollection() {
        perms = new ConcurrentHashMap<>(32);     // Capacity for default policy
        all_allowed = false;
    }

    /**
     * Adds a permission to the PropertyPermissions. The key for the hash is
     * the name.
     *
     * @param permission the Permission object to add.
     *
     * @throws    IllegalArgumentException   if the permission is not a
     *                                       PropertyPermission
     *
     * @throws    SecurityException   if this PropertyPermissionCollection
     *                                object has been marked readonly
     */
    @Override
    public void add(PropertyPermission permission) {
        if (! (permission instanceof PropertyPermission pp))
            throw new IllegalArgumentException("invalid permission: "+
                                               permission);
        if (isReadOnly())
            throw new SecurityException(
                "attempt to add a Permission to a readonly PermissionCollection");

        String propName = pp.getName();

        // Add permission to map if it is absent, or replace with new
        // permission if applicable.
        perms.merge(propName, pp, (existingVal, newVal) -> {
                int oldMask = existingVal.getMask();
                int newMask = newVal.getMask();
                if (oldMask != newMask) {
                    int effective = oldMask | newMask;
                    if (effective == newMask) {
                        return newVal;
                    }
                    if (effective != oldMask) {
                        return new PropertyPermission(propName, effective);
                    }
                }
                return existingVal;
            }
        );

        if (!all_allowed) {
            if (propName.equals("*"))
                all_allowed = true;
        }
    }

    /**
     * Check and see if this set of permissions implies the permissions
     * expressed in "permission".
     *
     * @param permission the Permission object to compare
     *
     * @return true if "permission" is a proper subset of a permission in
     * the set, false if not.
     */
    @Override
    public boolean implies(Permission permission) {
        if (! (permission instanceof PropertyPermission pp))
            return false;

        PropertyPermission x;

        int desired = pp.getMask();
        int effective = 0;

        // short circuit if the "*" Permission was added
        if (all_allowed) {
            x = perms.get("*");
            if (x != null) {
                effective |= x.getMask();
                if ((effective & desired) == desired)
                    return true;
            }
        }

        // strategy:
        // Check for full match first. Then work our way up the
        // name looking for matches on a.b.*

        String name = pp.getName();
        //System.out.println("check "+name);

        x = perms.get(name);

        if (x != null) {
            // we have a direct hit!
            effective |= x.getMask();
            if ((effective & desired) == desired)
                return true;
        }

        // work our way up the tree...
        int last, offset;

        offset = name.length()-1;

        while ((last = name.lastIndexOf('.', offset)) != -1) {

            name = name.substring(0, last+1) + "*";
            //System.out.println("check "+name);
            x = perms.get(name);

            if (x != null) {
                effective |= x.getMask();
                if ((effective & desired) == desired)
                    return true;
            }
            offset = last -1;
        }

        // we don't have to check for "*" as it was already checked
        // at the top (all_allowed), so we just return false
        return false;
    }

    /**
     * Returns an enumeration of all the PropertyPermission objects in the
     * container.
     *
     * @return an enumeration of all the PropertyPermission objects.
     */
    @Override
    @SuppressWarnings("unchecked")
    public Enumeration<PropertyPermission> elements() {
        /**
         * Casting to rawtype since Enumeration<PropertyPermission>
         * cannot be directly cast to Enumeration<Permission>
         */
        return (Enumeration)perms.elements();
    }
}

/*
 * Copyright (c) 1997, 2024, Oracle and/or its affiliates. All rights reserved.
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

package java.security;

import java.util.List;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * A {@code UnresolvedPermissionCollection} stores a collection
 * of UnresolvedPermission permissions.
 *
 * @see java.security.Permission
 * @see java.security.Permissions
 * @see java.security.UnresolvedPermission
 *
 *
 * @author Roland Schemers
 * @since 1.2
 *
 * @serial include
 */

final class UnresolvedPermissionCollection
extends PermissionCollection<UnresolvedPermission>
{
    /**
     * Key is permission type, value is a list of the UnresolvedPermissions
     * of the same type.
     * Not serialized; see serialization section at end of class.
     */
    private transient ConcurrentHashMap<String, List<UnresolvedPermission>> perms;

    /**
     * Create an empty {@code UnresolvedPermissionCollection} object.
     *
     */
    public UnresolvedPermissionCollection() {
        perms = new ConcurrentHashMap<>(11);
    }

    /**
     * Adds a permission to this {@code UnresolvedPermissionCollection}.
     * The key for the hash is the unresolved permission's type (class) name.
     *
     * @param permission the Permission object to add.
     */
    @Override
    public void add(UnresolvedPermission unresolvedPermission) {
        // Add permission to map.
        perms.compute(unresolvedPermission.getName(), (key, oldValue) -> {
                if (oldValue == null) {
                    List<UnresolvedPermission> v = new CopyOnWriteArrayList<>();
                    v.add(unresolvedPermission);
                    return v;
                } else {
                    oldValue.add(unresolvedPermission);
                    return oldValue;
                }
            }
        );
    }

    /**
     * get any unresolved permissions of the same type as p,
     * and return the List containing them.
     */
    List<UnresolvedPermission> getUnresolvedPermissions(Permission p) {
        return perms.get(p.getClass().getName());
    }

    /**
     * always returns {@code false} for unresolved permissions
     *
     */
    @Override
    public boolean implies(Permission permission) {
        return false;
    }

    /**
     * Returns an enumeration of all the UnresolvedPermission lists in the
     * container.
     *
     * @return an enumeration of all the UnresolvedPermission objects.
     */
    @Override
    public Enumeration<UnresolvedPermission> elements() {
        List<UnresolvedPermission> results =
            new ArrayList<UnresolvedPermission>(); // where results are stored

        // Get iterator of Map values (which are lists of permissions)
        for (List<UnresolvedPermission> l : perms.values()) {
            results.addAll(l);
        }

        return Collections.enumeration(results);
    }
}

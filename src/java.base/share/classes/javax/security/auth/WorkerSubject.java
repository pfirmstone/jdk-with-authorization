/*
 * Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
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

import au.zeus.jdk.authorization.spire.SpiffeCredentialManager.SpiffeSubject;
import java.security.Principal;
import java.util.Set;

/**
 * LocalWorkerSubject
 * 
 * @author peter
 */
public sealed class WorkerSubject extends Subject permits SpiffeSubject, RemoteSubject{
    private static final long serialVersionUID = 1L;
    
    /**
     * Create an instance of a {@code WorkerSubject} with
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
    public WorkerSubject(boolean readOnly, Set<? extends Principal> principals,
                   Set<?> pubCredentials, Set<?> privCredentials) {
        super(readOnly, principals, pubCredentials, privCredentials);
    }
    
}

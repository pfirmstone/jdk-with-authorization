/*
 * Copyright (c) 1999, 2022, Oracle and/or its affiliates. All rights reserved.
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

package javax.crypto;

import java.security.*;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.NoSuchElementException;
import java.util.concurrent.ConcurrentHashMap;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.IOException;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * This class contains {@code CryptoPermission} objects, organized into
 * {@code PermissionCollection} objects according to algorithm names.
 *
 * <p>When the {@code add} method is called to add a
 * {@code CryptoPermission}, the {@code CryptoPermission} is stored in the
 * appropriate {@code PermissionCollection}. If no such
 * collection exists yet, the algorithm name associated with
 * the {@code CryptoPermission} object is
 * determined and the {@code newPermissionCollection} method
 * is called on the {@code CryptoPermission} or {@code CryptoAllPermission} class to
 * create the {@code PermissionCollection} and add it to the {@code Permissions} object.
 *
 * @see javax.crypto.CryptoPermission
 * @see java.security.PermissionCollection
 * @see java.security.Permissions
 *
 * @author Sharon Liu
 * @since 1.4
 */
final class CryptoPermissions extends PermissionCollection<CryptoPermission>
{
    
    private final ConcurrentHashMap<String,PermissionCollection<CryptoPermission>> perms;

    /**
     * Creates a new {@code CryptoPermissions} object containing
     * no {@code CryptoPermissionCollection} objects.
     */
    CryptoPermissions() {
        perms = new ConcurrentHashMap<>(7);
    }

    /**
     * Populates the crypto policy from the specified
     * {@code InputStream} into this {@code CryptoPermissions} object.
     *
     * @param in the InputStream to load from.
     *
     * @exception SecurityException if cannot load
     * successfully.
     */
    void load(InputStream in)
        throws IOException, CryptoPolicyParser.ParsingException {
        CryptoPolicyParser parser = new CryptoPolicyParser();
        parser.read(new BufferedReader(new InputStreamReader(in, UTF_8)));

        CryptoPermission[] parsingResult = parser.getPermissions();
        for (int i = 0; i < parsingResult.length; i++) {
            this.add(parsingResult[i]);
        }
    }

    /**
     * Returns {@code true} if this {@code CryptoPermissions} object doesn't
     * contain any {@code CryptoPermission} objects; otherwise, returns
     * {@code false}.
     */
    boolean isEmpty() {
        return perms.isEmpty();
    }

    /**
     * Adds a permission object to the
     * {@code PermissionCollection} for the algorithm returned by
     * {@code (CryptoPermission)permission.getAlgorithm()}.
     *
     * This method creates
     * a new {@code PermissionCollection} object (and adds the
     * permission to it) if an appropriate collection does not yet exist.
     *
     * @param permission the {@code Permission} object to add.
     *
     * @exception SecurityException if this {@code CryptoPermissions}
     * object is marked as readonly.
     *
     * @see PermissionCollection#isReadOnly
     */
    @Override
    public void add(CryptoPermission permission) {

        if (isReadOnly()) {
            throw new SecurityException("Attempt to add a Permission " +
                                        "to a readonly CryptoPermissions " +
                                        "object");
        }

        // For code compiled before generics.
        if (!(permission instanceof CryptoPermission cryptoPerm)) return;
        

        PermissionCollection<CryptoPermission> pc =
                        getPermissionCollection(cryptoPerm);
        pc.add(cryptoPerm);
        String alg = cryptoPerm.getAlgorithm();
        perms.putIfAbsent(alg, pc);
    }

    /**
     * Checks if this object's {@code PermissionCollection} for permissions
     * of the specified permission's algorithm implies the specified
     * permission. Returns {@code true} if the checking succeeded.
     *
     * @param permission the {@code Permission} object to check.
     *
     * @return {@code true} if {@code permission} is implied by the permissions
     * in the {@code PermissionCollection} it belongs to, {@code false} if not.
     *
     */
    @Override
    public boolean implies(Permission permission) {
        if (!(permission instanceof CryptoPermission cryptoPerm)) {
            return false;
        }

        PermissionCollection<CryptoPermission> pc =
            getPermissionCollection(cryptoPerm.getAlgorithm());

        if (pc != null) {
            return pc.implies(cryptoPerm);
        } else {
            // none found
            return false;
        }
    }

    /**
     * Returns an enumeration of all the {@code Permission} objects
     * in this {@code CryptoPermissions} object.
     * @return an enumeration of all the {@code Permission} objects.
     */
    @Override
    public Enumeration<CryptoPermission> elements() {
        // go through each Permissions in the hash table
        // and call their elements() function.
        return new PermissionsEnumerator(perms.elements());
    }

    /**
     * Returns a {@code CryptoPermissions} object which
     * represents the minimum of the specified
     * {@code CryptoPermissions} object and this
     * {@code CryptoPermissions} object.
     *
     * @param other the {@code CryptoPermission}
     * object to compare with this object.
     */
    CryptoPermissions getMinimum(CryptoPermissions other) {
        if (other == null) {
            return null;
        }

        if (this.perms.containsKey(CryptoAllPermission.ALG_NAME)) {
            return other;
        }

        if (other.perms.containsKey(CryptoAllPermission.ALG_NAME)) {
            return this;
        }

        CryptoPermissions ret = new CryptoPermissions();


        PermissionCollection<CryptoPermission> thatWildcard =
                other.perms.get(CryptoPermission.ALG_NAME_WILDCARD);
        int maxKeySize = 0;
        if (thatWildcard != null) {
            maxKeySize = thatWildcard.elements().nextElement().getMaxKeySize();
        }
        // For each algorithm in this CryptoPermissions,
        // find out if there is anything we should add into
        // ret.
        for (String alg : this.perms.keySet()) {
            PermissionCollection<CryptoPermission> thisPc = this.perms.get(alg);
            PermissionCollection<CryptoPermission> thatPc = other.perms.get(alg);

            CryptoPermission[] partialResult;

            if (thatPc == null) {
                if (thatWildcard == null) {
                    // The other CryptoPermissions
                    // doesn't allow this given
                    // algorithm at all. Just skip this
                    // algorithm.
                    continue;
                }
                partialResult = getMinimum(maxKeySize, thisPc);
            } else {
                partialResult = getMinimum(thisPc, thatPc);
            }

            for (int i = 0; i < partialResult.length; i++) {
                ret.add(partialResult[i]);
            }
        }

        PermissionCollection<CryptoPermission> thisWildcard =
                this.perms.get(CryptoPermission.ALG_NAME_WILDCARD);

        // If this CryptoPermissions doesn't
        // have a wildcard, we are done.
        if (thisWildcard == null) {
            return ret;
        }

        // Deal with the algorithms only appear
        // in the other CryptoPermissions.
        maxKeySize = thisWildcard.elements().nextElement().getMaxKeySize();
        for (String alg : other.perms.keySet()) {

            if (this.perms.containsKey(alg)) {
                continue;
            }

            PermissionCollection<CryptoPermission> thatPc = other.perms.get(alg);

            CryptoPermission[] partialResult;

            partialResult = getMinimum(maxKeySize, thatPc);

            for (int i = 0; i < partialResult.length; i++) {
                ret.add(partialResult[i]);
            }
        }
        return ret;
    }

    /**
     * Get the minimum of the two given {@code PermissionCollection}
     * {@code thisPc} and {@code thatPc}.
     *
     * @param thisPc the first given {@code PermissionCollection}
     * object.
     *
     * @param thatPc the second given {@code PermissionCollection}
     * object.
     */
    private CryptoPermission[] getMinimum(PermissionCollection<CryptoPermission> thisPc,
                                          PermissionCollection<CryptoPermission> thatPc) {
        ArrayList<CryptoPermission> permList = new ArrayList<>(2);

        Enumeration<CryptoPermission> thisPcPermissions = thisPc.elements();

        // For each CryptoPermission in
        // thisPc object, do the following:
        // 1) if this CryptoPermission is implied
        //     by thatPc, this CryptoPermission
        //     should be returned, and we can
        //     move on to check the next
        //     CryptoPermission in thisPc.
        // 2) otherwise, we should return
        //     all CryptoPermissions in thatPc
        //     which
        //     are implied by this CryptoPermission.
        //     Then we can move on to the
        //     next CryptoPermission in thisPc.
        while (thisPcPermissions.hasMoreElements()) {
            Permission thisCp = thisPcPermissions.nextElement();

            Enumeration<CryptoPermission> thatPcPermissions = thatPc.elements();
            while (thatPcPermissions.hasMoreElements()) {
                Permission thatCp = thatPcPermissions.nextElement();

                if (thatCp.implies(thisCp)) {
                    if(thisCp instanceof CryptoPermission p)
                        permList.add(p);
                    break;
                }
                if (thisCp.implies(thatCp)) {
                    if(thatCp instanceof CryptoPermission p)
                        permList.add(p);
                }
            }
        }

        return permList.toArray(new CryptoPermission[permList.size()]);
    }

    /**
     * Returns all the {@code CryptoPermission} objects in the given
     * {@code PermissionCollection} object
     * whose maximum keysize no greater than {@code maxKeySize}.
     * For all {@code CryptoPermission} objects with a maximum keysize
     * greater than {@code maxKeySize}, this method constructs a
     * corresponding {@code CryptoPermission} object whose maximum
     * keysize is set to {@code maxKeySize}, and includes that in
     * the result.
     *
     * @param maxKeySize the given maximum key size.
     *
     * @param pc the given {@code PermissionCollection} object.
     */
    private CryptoPermission[] getMinimum(int maxKeySize,
                                          PermissionCollection<CryptoPermission> pc) {
        ArrayList<CryptoPermission> permList = new ArrayList<>(1);

        Enumeration<CryptoPermission> enum_ = pc.elements();

        while (enum_.hasMoreElements()) {
            CryptoPermission cp = enum_.nextElement();
            if (cp.getMaxKeySize() <= maxKeySize) {
                permList.add(cp);
            } else {
                if (cp.getCheckParam()) {
                    permList.add(
                           new CryptoPermission(cp.getAlgorithm(),
                                                maxKeySize,
                                                cp.getAlgorithmParameterSpec(),
                                                cp.getExemptionMechanism()));
                } else {
                    permList.add(
                           new CryptoPermission(cp.getAlgorithm(),
                                                maxKeySize,
                                                cp.getExemptionMechanism()));
                }
            }
        }

        return permList.toArray(new CryptoPermission[0]);
    }

    /**
     * Returns the {@code PermissionCollection} for the
     * specified algorithm. Returns {@code null} if there
     * isn't such a {@code PermissionCollection}.
     *
     * @param alg the algorithm name.
     */
    PermissionCollection<CryptoPermission> getPermissionCollection(String alg) {
        // If this CryptoPermissions includes CryptoAllPermission,
        // we should return CryptoAllPermission.
        PermissionCollection<CryptoPermission> pc = perms.get(CryptoAllPermission.ALG_NAME);
        if (pc == null) {
            pc = perms.get(alg);

            // If there isn't a PermissionCollection for
            // the given algorithm,we should return the
            // PermissionCollection for the wildcard
            // if there is one.
            if (pc == null) {
                pc = perms.get(CryptoPermission.ALG_NAME_WILDCARD);
            }
        }
        return pc;
    }

    /**
     * Returns the {@code PermissionCollection} for the algorithm
     * associated with the specified {@code CryptoPermission}
     * object. Creates such a {@code PermissionCollection}
     * if such a {@code PermissionCollection} does not
     * exist yet.
     *
     * @param cryptoPerm the {@code CryptoPermission} object.
     */
    private PermissionCollection<CryptoPermission> getPermissionCollection(
                                          CryptoPermission cryptoPerm) {

        String alg = cryptoPerm.getAlgorithm();

        PermissionCollection<CryptoPermission> pc = perms.get(alg);

        if (pc == null) {
            pc = cryptoPerm.newPermissionCollection();
        }
        return pc;
    }
}

final class PermissionsEnumerator implements Enumeration<CryptoPermission> {

    // all the perms
    private final Enumeration<PermissionCollection<CryptoPermission>> perms;
    // the current set
    private Enumeration<CryptoPermission> permset;

    PermissionsEnumerator(Enumeration<PermissionCollection<CryptoPermission>> e) {
        perms = e;
        permset = getNextEnumWithMore();
    }

    @Override
    public synchronized boolean hasMoreElements() {
        // if we enter with permissionimpl null, we know
        // there are no more left.

        if (permset == null) {
            return  false;
        }

        // try to see if there are any left in the current one

        if (permset.hasMoreElements()) {
            return true;
        }

        // get the next one that has something in it...
        permset = getNextEnumWithMore();

        // if it is null, we are done!
        return (permset != null);
    }

    @Override
    public synchronized CryptoPermission nextElement() {
        // hasMoreElements will update permset to the next permset
        // with something in it...

        if (hasMoreElements()) {
            return permset.nextElement();
        } else {
            throw new NoSuchElementException("PermissionsEnumerator");
        }
    }

    private Enumeration<CryptoPermission> getNextEnumWithMore() {
        while (perms.hasMoreElements()) {
            PermissionCollection<CryptoPermission> pc = perms.nextElement();
            Enumeration<CryptoPermission> next = pc.elements();
            if (next.hasMoreElements()) {
                return next;
            }
        }
        return null;
    }
}

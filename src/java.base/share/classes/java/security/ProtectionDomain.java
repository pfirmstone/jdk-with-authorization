/*
 * Copyright (c) 1997, 2022, Oracle and/or its affiliates. All rights reserved.
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.WeakHashMap;
import jdk.internal.access.JavaSecurityAccess;
import jdk.internal.access.SharedSecrets;
import sun.security.action.GetPropertyAction;
import sun.security.provider.PolicyFile;
import sun.security.util.Debug;
import sun.security.util.FilePermCompat;
import sun.security.util.SecurityConstants;
import java.security.Permissions;
import au.zeus.jdk.net.Uri;
import au.zeus.jdk.authorization.policy.PermissionComparator;
import java.net.URL;
import java.net.URISyntaxException;
import java.security.Permission;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * The {@code ProtectionDomain} class encapsulates the characteristics of a
 * domain, which encloses a set of classes whose instances are granted a set
 * of permissions when being executed on behalf of a given set of Principals.
 *
 * @author Li Gong
 * @author Roland Schemers
 * @author Gary Ellison
 * @since 1.2
 */

public class ProtectionDomain {

    /**
     * If {@code true}, {@link #impliesWithAltFilePerm} will try to be
     * compatible on FilePermission checking even if a 3rd-party Policy
     * implementation is set.
     */
    private static final boolean filePermCompatInPD =
            "true".equals(GetPropertyAction.privilegedGetProperty(
                "jdk.security.filePermCompat"));

    private static class JavaSecurityAccessImpl implements JavaSecurityAccess {

        private JavaSecurityAccessImpl() {
        }

        @SuppressWarnings("removal")
        @Override
        public <T> T doIntersectionPrivilege(
                PrivilegedAction<T> action,
                final AccessControlContext stack,
                final AccessControlContext context) {
            if (action == null) {
                throw new NullPointerException();
            }

            return AccessController.doPrivileged(
                action,
                getCombinedACC(context, stack)
            );
        }

        @SuppressWarnings("removal")
        @Override
        public <T> T doIntersectionPrivilege(
                PrivilegedAction<T> action,
                AccessControlContext context) {
            return doIntersectionPrivilege(action,
                AccessController.getContext(), context);
        }

        @Override
        public ProtectionDomain[] getProtectDomains(@SuppressWarnings("removal") AccessControlContext context) {
            return context.getContext();
        }

        @SuppressWarnings("removal")
        private static AccessControlContext getCombinedACC(
            AccessControlContext context, AccessControlContext stack) {
            AccessControlContext acc =
                AccessControlContext.build(context, stack.getCombiner(), true);

            return AccessControlContext.build(stack.getContext(), acc).optimize();
        }
        
        // ProtectionDomainCache is only used by the sun PolicyFile implementation.
        @Override
        public ProtectionDomainCache getProtectionDomainCache() {
            return new ProtectionDomainCache() {
                private final Map<Key, PermissionCollection<Permission>> map =
                        Collections.synchronizedMap(new WeakHashMap<>());
                @Override
                public void put(ProtectionDomain pd,
                                PermissionCollection<Permission> pc) {
                    map.put((pd == null ? null : pd.key), pc);
                }
                @Override
                public PermissionCollection<Permission> get(ProtectionDomain pd) {
                    return pd == null ? map.get(null) : map.get(pd.key);
                }
            };
        }
    }

    static {
        // Set up JavaSecurityAccess in SharedSecrets
        SharedSecrets.setJavaSecurityAccess(new JavaSecurityAccessImpl());
    }

    /* CodeSource */
    private final CodeSource codesource ;

    /* ClassLoader the protection domain was consed from */
    private final ClassLoader classloader;

    /* Principals running-as within this protection domain */
    private final Principal[] principals;

    /* the rights this protection domain is granted */
    private final PermissionCollection<Permission> permissions;

    /* if the permissions object has AllPermission */
    private final boolean hasAllPerm;
    
    /* the PermissionCollection is static (pre 1.4 constructor)
       or dynamic (via a policy refresh) */
    private final boolean staticPermissions;
    
    private final int hashcode;
    
    private final UriCodeSource uriCS;

    /*
     * An object used as a key when the ProtectionDomain is stored in a Map.
     */
    final Key key = new Key();

    /**
     * Creates a new {@code ProtectionDomain} with the given {@code CodeSource}
     * and permissions. If permissions is not {@code null}, then
     * {@code setReadOnly()} will be called on the passed in
     * permissions.
     * <p>
     * The permissions granted to this domain include both the permissions
     * passed to this constructor, and any permissions granted to this domain
     * by the current policy at the time a permission is checked.
     * <p>
     * If permissions is not null {@code null} and codesource is null {@code null}
     * then permissions will be used to identity this domain.
     * <p>
     * If no codesource is associated with this domain, then
     * 
     * @param codesource the codesource associated with this domain, if any.
     * @param permissions the permissions granted to this domain
     */
    @SuppressWarnings("unchecked")
    public ProtectionDomain(CodeSource codesource,
                            PermissionCollection<? extends Permission> permissions) {
        this.codesource = codesource;
        this.uriCS = codesource!= null ? new UriCodeSource(codesource) : null;
        boolean hasAllP = false;
        if (permissions != null) permissions.setReadOnly();
        this.permissions = (PermissionCollection<Permission>) permissions;
        if (permissions instanceof Permissions &&
            ((Permissions)permissions).allPermission()) {
            hasAllP = true;
        }
        this.hasAllPerm = hasAllP;
        this.classloader = null;
        this.principals = new Principal[0];
        int hash = 7;
        hash = 83 * hash + Objects.hashCode(this.uriCS);
        if (codesource == null){ // permissions become part of identity.
            hash = 83 * hash + permissionsHashCode(this.permissions);
        }
        hashcode = hash;
        staticPermissions = true;
    }

    /**
     * Creates a new {@code ProtectionDomain} qualified by the given
     * {@code CodeSource}, permissions, {@code ClassLoader} and array
     * of principals. If permissions is not {@code null}, then
     * {@code setReadOnly()} will be called on the passed in permissions.
     * <p>
     * The permissions granted to this domain include both the permissions
     * passed to this constructor, and any permissions granted to this domain
     * by the current policy at the time a permission is checked.
     * <p>
     * This constructor is typically used by
     * {@link SecureClassLoader ClassLoaders}
     * and {@link DomainCombiner DomainCombiners} which delegate to the
     * {@code Policy} object to actively associate the permissions granted to
     * this domain. This constructor affords the
     * policy provider the opportunity to augment the supplied
     * {@code PermissionCollection} to reflect policy changes.
     *
     * @param codesource the {@code CodeSource} associated with this domain
     * @param permissions the permissions granted to this domain
     * @param classloader the {@code ClassLoader} associated with this domain
     * @param principals the array of {@code Principal} objects associated
     * with this domain. The contents of the array are copied to protect against
     * subsequent modification.
     * @see Policy#refresh
     * @see Policy#getPermissions(ProtectionDomain)
     * @since 1.4
     */
    @SuppressWarnings("unchecked")
    public ProtectionDomain(CodeSource codesource,
                            PermissionCollection<? extends Permission> permissions,
                            ClassLoader classloader,
                            Principal[] principals) {
        this.codesource = codesource;
        this.uriCS = codesource!= null ? new UriCodeSource(codesource) : null;
        boolean hasAllPerm = false;
        if (permissions != null) permissions.setReadOnly();
        this.permissions = (PermissionCollection<Permission>) permissions;
        if (permissions instanceof Permissions &&
            ((Permissions)permissions).allPermission()) {
            hasAllPerm = true;
        }
        this.hasAllPerm = hasAllPerm;
        this.classloader = classloader;
        this.principals = (principals != null ? principals.clone():
                           new Principal[0]);
        int hash = 7;
        hash = 83 * hash + Objects.hashCode(this.uriCS);
        hash = 83 * hash + Objects.hashCode(this.classloader);
        hash = 83 * hash + this.principals.length > 0 ? 
                Arrays.deepHashCode(this.principals) : this.principals.hashCode();
        hashcode = hash;
        staticPermissions = false;
    }

    /**
     * Returns the {@code CodeSource} of this domain.
     * @return the {@code CodeSource} of this domain which may be {@code null}.
     * @since 1.2
     */
    public final CodeSource getCodeSource() {
        return this.codesource;
    }


    /**
     * Returns the {@code ClassLoader} of this domain.
     * @return the {@code ClassLoader} of this domain which may be {@code null}.
     *
     * @since 1.4
     */
    public final ClassLoader getClassLoader() {
        return this.classloader;
    }


    /**
     * Returns an array of principals for this domain.
     * @return a non-null array of principals for this domain.
     * Returns a new array each time this method is called.
     *
     * @since 1.4
     */
    public final Principal[] getPrincipals() {
        return this.principals.clone();
    }

    /**
     * Returns the static permissions granted to this domain.
     *
     * @return the static set of permissions for this domain which may be
     * {@code null}.
     * @see Policy#refresh
     * @see Policy#getPermissions(ProtectionDomain)
     */
    public final PermissionCollection<Permission> getPermissions() {
        return permissions;
    }

    /**
     * Returns {@code true} if this domain contains only static permissions.
     * 
     * For performance reasons, Policy performs static permission checks
     * using thread confined PermissionCollection's, adding
     * any additional permissions determined by policy for CodeSource,
     * however Subject Principal's aren't injected into PermissionCollection's
     * constructed using the two argument ProtectionDomain constructor.
     *
     * @return {@code false} if four argument constructor was called and {@code true}
     * if two argument constructor was called to construct this domain.
     *
     * @since 9
     */
    public final boolean staticPermissionsOnly() {
        return staticPermissions;
    }
    
    /* Optimization for AccessController */
    final boolean hasAllPerm(){
        return hasAllPerm;
    }

    /**
     * Check and see if this {@code ProtectionDomain} implies the permissions
     * expressed in the {@code Permission} object.
     * <p>
     * The permission will be checked against the combination
     * of the {@code PermissionCollection} supplied at construction and
     * the current policy binding.
     *
     * @param perm the {code Permission} object to check.
     *
     * @return {@code true} if {@code perm} is implied by this
     * {@code ProtectionDomain}.
     */
    @SuppressWarnings("removal")
    public boolean implies(Permission perm) {

        if (hasAllPerm) {
            // internal permission collection already has AllPermission -
            // no need to go to policy
            return true;
        }
        if (Policy.getPolicyNoCheck().implies(this, perm)) return true;
        // Supports AccessController methods with Permission parameter argument.
        if (staticPermissions && codesource == null && permissions != null){
            return permissions.implies(perm);
        }
        return false;
    }

    /**
     * This method has almost the same logic flow as {@link #implies} but
     * it ensures some level of FilePermission compatibility after JDK-8164705.
     *
     * This method is called by {@link AccessControlContext#checkPermission}
     * and not intended to be called by an application.
     */
    boolean impliesWithAltFilePerm(Permission perm) {

        // If FilePermCompat.compat is set (default value), FilePermission
        // checking compatibility should be considered.

        // If filePermCompatInPD is set, this method checks for alternative
        // FilePermission to keep compatibility for any Policy implementation.
        // When set to false (default value), implies() is called since
        // the PolicyFile implementation already supports compatibility.

        // If this is a subclass of ProtectionDomain, call implies()
        // because most likely user has overridden it.

        if (!filePermCompatInPD || !FilePermCompat.compat ||
                getClass() != ProtectionDomain.class) {
            return implies(perm);
        }

        if (hasAllPerm) {
            // internal permission collection already has AllPermission -
            // no need to go to policy
            return true;
        }

        Permission p2 = null;
        boolean p2Calculated = false;
        
        @SuppressWarnings("removal")
        Policy policy = Policy.getPolicyNoCheck();
        // Reminder: Policy cannot check static permissions when a domain has
        // a null codesource.
        if (policy instanceof PolicyFile) {
            // The PolicyFile implementation supports compatibility
            // inside, and it also covers the static permissions,
            // but it cannot check static permissions with a null
            // codesource.
            if (policy.implies(this, perm)) return true;
        } else {
            if (policy.implies(this, perm)) {
                return true;
            }
            p2 = FilePermCompat.newPermUsingAltPath(perm);
            p2Calculated = true;
            if (p2 != null && policy.implies(this, p2)) {
                return true;
            }
        }
        // Warning: poor scalability, this supports
        // AccessController methods with a Permission parameter argument.
        if (staticPermissions && codesource == null && permissions != null) {
            if (permissions.implies(perm)) {
                return true;
            } else {
                if (!p2Calculated) {
                    p2 = FilePermCompat.newPermUsingAltPath(perm);
                }
                if (p2 != null) {
                    return permissions.implies(p2);
                }
            }
        }
        return false;
    }

    @Override
    public int hashCode() {
        return hashcode;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        final ProtectionDomain other = (ProtectionDomain) obj;
        if (hashcode != other.hashcode) return false;
        if (!Objects.equals(this.uriCS, other.uriCS)) return false;
        if (staticPermissions){
            if (this.codesource == null && other.codesource == null){ // permissions become part of identity.
                if (permissions != null && other.permissions != null){
                    SortedSet<Permission> thisPermSet = permissionsToSet(permissions);
                    SortedSet<Permission> thatPermSet = permissionsToSet(other.permissions);
                    return Objects.equals(thisPermSet, thatPermSet);
                } else if (permissions == null || other.permissions == null){
                    return false;
                }
            } else if (this.codesource == null || other.codesource == null){
                return false;
            }
            return false;
        }
        if (!Objects.equals(this.classloader, other.classloader)) return false;
        return Arrays.equals(this.principals, other.principals);
    }
    
    /**
     * Generates unique hash codes for Permissions without calling their
     * hashcode method.
     * 
     * @param perms the PermissionCollection
     * @return hash code.
     */
    static int permissionsHashCode(PermissionCollection<Permission> perms){
        if (perms == null) return 0;
        int hashCode = 13;
        Enumeration<Permission> e = perms.elements();
        while (e.hasMoreElements()){
            hashCode ^= permissionHashCode(e.nextElement());
        }
        return hashCode;
    }

    /**
     * Generates unique hash codes for Permission without calling their
     * hashcode method.
     * 
     * @param perm the Permission
     * @return hash code.
     */
    static int permissionHashCode(Permission perm){
        if (perm == null) return 0;
        int hashCode = 7;
        hashCode = (hashCode << 5) - hashCode + perm.getClass().hashCode();
        hashCode = (hashCode << 5) - hashCode + perm.getName().hashCode();
        hashCode = (hashCode << 5) - hashCode + perm.getActions().hashCode();
        if (perm instanceof javax.security.auth.PrivateCredentialPermission pcp){
            hashCode = (hashCode << 5) - hashCode + Arrays.deepHashCode(pcp.getPrincipals());
            String credClass = pcp.getCredentialClass();
            if (credClass != null) hashCode = (hashCode << 5) - hashCode + credClass.hashCode();
        }
        return hashCode;   
    }
    
    /**
     * A SortedSet doesn't call hashCode on elements, this is important to
     * avoid DNS calls or File system access that occurs with some Permission
     * implementations like SocketPermission or FilePermission.
     * 
     * @param p
     * @return a SortedSet
     */
    static SortedSet<Permission> permissionsToSet(PermissionCollection<Permission> p){
        SortedSet<Permission> result = new TreeSet<>(PERM_COMPARE);
        Enumeration<Permission> e = p.elements();
        while (e.hasMoreElements()){
            result.add(e.nextElement());
        }
        return result;
    }
    
    private static Comparator<Permission> PERM_COMPARE = new PermissionComparator();

    

    /**
     * Convert a {@code ProtectionDomain} to a {@code String}.
     */
    @Override public String toString() {
        String pals = "<no principals>";
        if (principals != null && principals.length > 0) {
            StringBuilder palBuf = new StringBuilder("(principals ");

            for (int i = 0; i < principals.length; i++) {
                palBuf.append(principals[i].getClass().getName() +
                            " \"" + principals[i].getName() +
                            "\"");
                if (i < principals.length-1)
                    palBuf.append(",\n");
                else
                    palBuf.append(")\n");
            }
            pals = palBuf.toString();
        }

        // Check if policy is set; we don't want to load
        // the policy prematurely here
        @SuppressWarnings("removal")
        PermissionCollection<Permission> pc = Policy.isSet() && seeAllp() ?
                                      mergePermissions():
                                      getPermissions();

        return "ProtectionDomain "+
            " "+codesource+"\n"+
            " "+classloader+"\n"+
            " "+pals+"\n"+
            " "+pc+"\n";
    }

    /*
     * holder class for the static field "debug" to delay its initialization
     */
    private static class DebugHolder {
        private static final Debug debug = Debug.getInstance("domain");
    }

    /**
     * Return {@code true} (merge policy permissions) in the following cases:
     *
     * . SecurityManager is {@code null}
     *
     * . SecurityManager is not {@code null},
     *          debug is not {@code null},
     *          SecurityManager implementation is in bootclasspath,
     *          Policy implementation is in bootclasspath
     *          (the bootclasspath restrictions avoid recursion)
     *
     * . SecurityManager is not {@code null},
     *          debug is {@code null},
     *          caller has Policy.getPolicy permission
     */
    @SuppressWarnings("removal")
    private static boolean seeAllp() {
        SecurityManager sm = System.getSecurityManager();

        if (sm == null) {
            return true;
        } else {
            if (DebugHolder.debug != null) {
                return sm.getClass().getClassLoader() == null &&
                        Policy.getPolicyNoCheck().getClass().getClassLoader()
                                == null;
            } else {
                try {
                    sm.checkPermission(SecurityConstants.GET_POLICY_PERMISSION);
                    return true;
                } catch (SecurityException se) {
                    return false;
                }
            }
        }
    }

    @SuppressWarnings("removal")
    private PermissionCollection<Permission> mergePermissions() {
        // The use of lambda's could cause problems at bootstrap time?
        PermissionCollection<Permission> perms =
            java.security.AccessController.doPrivileged
            ((PrivilegedAction<PermissionCollection<Permission>>) () ->
                Policy.getPolicyNoCheck().getPermissions(ProtectionDomain.this));
        //Policy has responsiblity of merging permissions.
        if (perms != null && perms != Policy.UNSUPPORTED_EMPTY_COLLECTION){
            return perms;
        }
        return permissions;
    }

    /**
     * Used for storing ProtectionDomains as keys in a Map.
     */
    static final class Key {}
    
    /**
     * To avoid CodeSource equals and hashCode methods.
     * 
     * Shamelessly stolen from RFC3986URLClassLoader
     * 
     * CodeSource uses DNS lookup calls to check location IP addresses are 
     * equal.
     * 
     * This class must not be serialized.
     * @author Peter Firmstone.
     */
    @SuppressWarnings("serial")
    private static class UriCodeSource extends CodeSource{
        private final Uri uri;
        private final int hashCode;
        
        UriCodeSource(CodeSource cs){
            this(cs.getLocation(), cs.getCertificates());
        }
        
        private UriCodeSource(URL url, java.security.cert.Certificate [] certs){
            super(url, certs);
            Uri uRi = null;
            if (url != null){
                try {
                    uRi = Uri.urlToUri(url);
                } catch (URISyntaxException ex) { }//Ignore
            }
            this.uri = uRi;
            int hash = 7;
            hash = 23 * hash + (this.uri != null ? this.uri.hashCode() : 0);
            hash = 23 * hash + (certs != null ? Arrays.hashCode(certs) : 0);
            hashCode = hash;
        }

        @Override
        public int hashCode() {
            return hashCode;
        }
        
        @Override
        public boolean equals(Object o){
            if (!(o instanceof UriCodeSource)) return false;
            if (uri == null) return super.equals(o); // In case of URISyntaxException
            UriCodeSource that = (UriCodeSource) o; 
            if ( !uri.equals(that.uri)) return false;
            java.security.cert.Certificate [] mine = getCertificates();
            java.security.cert.Certificate [] theirs = that.getCertificates();
            return Arrays.equals(mine, theirs);
        }
       
    }

}

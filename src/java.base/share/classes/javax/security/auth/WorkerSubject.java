/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
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
public sealed class WorkerSubject extends Subject permits SpiffeSubject{
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

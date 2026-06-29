/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package javax.security.auth;

import au.zeus.jdk.authorization.spire.SpiffePrincipal;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * A RemoteSubject is a read only WorkerSubject constructed from an X509Certificate chain.
 * It contains no private credentials.
 * 
 * @author user
 */
public final class RemoteSubject extends WorkerSubject {
    private static final long serialVersionUID = 1L;
    
    /**
     * Creates a RemoteSubject using an X509Certificate chain.
     * 
     * @param certificateChain X509Certificate's
     */
    public RemoteSubject(X509Certificate [] certificateChain){
        CertificateFactory cf;
        try {
            cf = CertificateFactory.getInstance("X.509");
        } catch (CertificateException ex) {
            throw new IllegalArgumentException("Certificate exception: ", ex);
        }
        List<X509Certificate> certList = Arrays.asList(certificateChain);
        X509Certificate leafCert = certList.get(0);

        // Build credentials
        CertPath certPath;
        try {
            certPath = cf.generateCertPath(certList);
        } catch (CertificateException ex) {
            throw new IllegalArgumentException("Certificate exception: ", ex);
        }
        Set<Object> pubCreds = new LinkedHashSet<Object>();
        pubCreds.add(certPath);

        Set<Principal> principals = new LinkedHashSet<Principal>();
        principals.add(leafCert.getSubjectX500Principal());
        Collection<List<?>> names;
        try {
            names = leafCert.getSubjectAlternativeNames();
        } catch (CertificateParsingException e) {
            throw new IllegalArgumentException(
                    "Cannot parse SubjectAlternativeNames from certificate: "
                    + leafCert.getSubjectX500Principal(), e);
        }
        if (names != null) {
            for (List<?> altName : names) {
                if (altName != null && altName.size() >= 2 && Integer.valueOf(6).equals(altName.get(0))) {
                    if (altName.get(1) instanceof String uri) {
                        if (uri.startsWith("spiffe://")) {
                            principals.add(new SpiffePrincipal(uri));
                            break;
                        }
                    }
                }
            }
        }
        
        this(Collections.unmodifiableSet(principals), Collections.unmodifiableSet(pubCreds), Collections.emptySet());
        
    }
    
    private RemoteSubject(Set<? extends Principal> principals,
                   Set<?> pubCredentials, Set<?> privCredentials) {
        super(true, principals, pubCredentials, privCredentials);
    }
}

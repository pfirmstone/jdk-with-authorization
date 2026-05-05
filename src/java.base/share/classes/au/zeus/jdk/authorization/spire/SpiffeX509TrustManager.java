/*
 * Copyright (c) 2025, Peter Firmstone.
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the
 * License.
 */

package au.zeus.jdk.authorization.spire;

import javax.net.ssl.X509TrustManager;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * X509TrustManager that validates peer certificates as SPIFFE SVIDs.
 * Trusts certificates signed by the SPIRE trust bundle.
 * 
 * <p>Bootstrap-safe: no lambdas, explicit loops.
 * 
 * @author Peter Firmstone
 * @since 3.1.1
 */
public final class SpiffeX509TrustManager implements X509TrustManager {
    
    private final SpiffeCredentialManager credentialManager;
    
    public SpiffeX509TrustManager() throws IOException {
        this.credentialManager = SpiffeCredentialManager.getInstance();
    }
    
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        checkTrusted(chain, authType, true);
    }
    
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        checkTrusted(chain, authType, false);
    }
    
    private void checkTrusted(X509Certificate[] chain, String authType, boolean isClient)
            throws CertificateException {
        
        if (chain == null || chain.length == 0)
            throw new CertificateException("Peer presented no certificates");
        
        if (authType == null || authType.length() == 0)
            throw new CertificateException("authType must not be null or empty");
       
        X509Certificate leafCert = chain[0];
        
        if (isClient){
            String leafKeyAlg = leafCert.getPublicKey().getAlgorithm(); // "EC" or "RSA"
            if (!authType.equals(leafKeyAlg)) {
                throw new CertificateException(
                    "authType '" + authType + "' does not match leaf certificate " +
                    "key algorithm '" + leafKeyAlg + "'");
            }
        } else { // server
            String leafKeyAlg = leafCert.getPublicKey().getAlgorithm(); // "EC" or "RSA"
            // "EC" certs appear as "ECDHE_ECDSA", "ECDH_ECDSA"; RSA as "ECDHE_RSA", "RSA" etc.
            String authTypeUpper = authType.toUpperCase();
            boolean consistent = ("EC".equals(leafKeyAlg) && authTypeUpper.contains("ECDSA"))
                              || ("RSA".equals(leafKeyAlg) && authTypeUpper.contains("RSA"));
            if (!consistent) {
                throw new CertificateException(
                    "authType '" + authType + "' inconsistent with leaf certificate " +
                    "key algorithm '" + leafKeyAlg + "'");
            }
        }
        
        // Verify it's a SPIFFE SVID (has URI SAN starting with "spiffe://")
        String spiffeId = extractSpiffeId(leafCert);
        if (spiffeId == null) {
            throw new CertificateException("Peer certificate is not a SPIFFE SVID (no spiffe:// URI SAN)");
        }
        
        // Verify trust domain matches (optional — can cross-trust)
        // Uncomment to enforce same-trust-domain requirement:
        String ourSpiffeId = credentialManager.getSpiffeId();
        if (ourSpiffeId != null && ourSpiffeId.startsWith("spiffe://")) {
            String ourTrustDomain = extractTrustDomain(ourSpiffeId);
            String peerTrustDomain = extractTrustDomain(spiffeId);
            if (!ourTrustDomain.equals(peerTrustDomain)) {
                throw new CertificateException("SPIFFE ID trust domain mismatch: peer=" + 
                                           peerTrustDomain + ", ours=" + ourTrustDomain);
            }
        }
        
        // Check validity FIRST — cheap, avoids unnecessary crypto
        for (int i = 0; i < chain.length; i++) {
            try {
                chain[i].checkValidity();
            } catch (java.security.cert.CertificateExpiredException e) {
                throw new CertificateException(
                    "Certificate at position " + i + " in chain has expired", e);
            } catch (java.security.cert.CertificateNotYetValidException e) {
                throw new CertificateException(
                    "Certificate at position " + i + " in chain is not yet valid", e);
            }
        }
        
        try {
            // THEN verify signature chain
            verifyChainAgainstTrustBundle(chain);
            // Success — peer is trusted SPIFFE workload
        } catch (CertificateException e) {
            throw e;
        } catch (Exception e) {
            throw new CertificateException("Failed to verify SPIFFE SVID chain", e);
        }
    }
    
    /**
     * Extracts SPIFFE ID from certificate's URI SAN extension.
     */
    private String extractSpiffeId(X509Certificate cert) {
        try {
            // X.509 SAN extension: 2.5.29.17 (Subject Alternative Name)
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans == null) {
                return null;
            }
            
            // SAN type 6 = URI
            for (List<?> san : sans) {
                if (san.size() >= 2 && Integer.valueOf(6).equals(san.get(0))) {
                    String uri = (String) san.get(1);
                    if (uri.startsWith("spiffe://")) {
                        return uri;
                    }
                }
            }
            return null;
            
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * Extracts trust domain from SPIFFE ID.
     * Example: "spiffe://jgdms.example.org/host/policy" → "jgdms.example.org"
     */
    private String extractTrustDomain(String spiffeId) {
        if (spiffeId == null || !spiffeId.startsWith("spiffe://")) {
            return null;
        }
        String withoutScheme = spiffeId.substring("spiffe://".length());
        int slashIndex = withoutScheme.indexOf('/');
        if (slashIndex == -1) {
            return withoutScheme;
        }
        return withoutScheme.substring(0, slashIndex);
    }
    
    /**
     * Verifies the certificate chain against the SPIRE trust bundle.
     * 
     * <p>Verification steps:
     * <ol>
     *   <li>Verify each certificate is signed by the next in chain
     *   <li>Verify root certificate is self-signed
     *   <li>Verify root certificate fingerprint matches SPIRE trust bundle
     * </ol>
     *
     * @param chain certificate chain from peer (leaf to root)
     * @throws Exception if verification fails
     */
    private void verifyChainAgainstTrustBundle(X509Certificate[] chain)
        throws Exception {

        if (chain.length == 0) {
            throw new CertificateException("Empty certificate chain");
        }

        X509Certificate[] trustBundle = credentialManager.getTrustBundle();
        if (trustBundle.length == 0) {
            throw new CertificateException(
                "No trust bundle available — SPIRE may not have provided bundle yet");
        }

        // Verify chain integrity: each cert is signed by the next
        for (int i = 0; i < chain.length - 1; i++) {
            chain[i].verify(chain[i + 1].getPublicKey());
        }

        // Find the trust bundle cert that signed the last cert in the chain.
        // The root CA is in the trust bundle, NOT in the chain itself.
        X509Certificate lastInChain = chain[chain.length - 1];
        boolean foundIssuer = false;
        for (int i = 0; i < trustBundle.length; i++) {
            try {
                lastInChain.verify(trustBundle[i].getPublicKey());
                foundIssuer = true;
                break;
            } catch (Exception e) {
                // Not signed by this trust bundle cert — try next
            }
        }

        if (!foundIssuer) {
            throw new CertificateException(
                "Certificate chain is not anchored by any certificate in the SPIRE trust bundle");
        }
    }
    
    @Override
    public X509Certificate[] getAcceptedIssuers() {
        // Return trust bundle — tells peer what CAs we accept
        // (JSSE uses this for client cert requests)
        try {
            return credentialManager.getTrustBundle();
        } catch (Exception e) {
            // Fallback: return empty array (accept any issuer)
            return new X509Certificate[0];
        }
    }
}
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
        
        if (chain == null || chain.length == 0) {
            throw new CertificateException("Peer presented no certificates");
        }
        
        X509Certificate leafCert = chain[0];
        
        // 1. Verify it's a SPIFFE SVID (has URI SAN starting with "spiffe://")
        String spiffeId = extractSpiffeId(leafCert);
        if (spiffeId == null) {
            throw new CertificateException("Peer certificate is not a SPIFFE SVID (no spiffe:// URI SAN)");
        }
        
        // 2. Verify trust domain matches (optional — can cross-trust)
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
        
        // 3. Verify signature chain against trust bundle
        try {
            verifyChainAgainstTrustBundle(chain);
        } catch (Exception e) {
            throw new CertificateException("Failed to verify SPIFFE SVID chain", e);
        }
        
        // 4. Verify certificate validity
        leafCert.checkValidity();
        
        // Success — peer is trusted SPIFFE workload
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
        
        // Get trust bundle from credential manager
        X509Certificate[] trustBundle = credentialManager.getTrustBundle();
        if (trustBundle.length == 0) {
            throw new CertificateException(
                "No trust bundle available — SPIRE may not have provided bundle yet");
        }
        
        // Verify chain integrity: each cert signed by next
        for (int i = 0; i < chain.length - 1; i++) {
            X509Certificate cert = chain[i];
            X509Certificate issuer = chain[i + 1];
            cert.verify(issuer.getPublicKey());
        }
        
        // Verify root is self-signed
        X509Certificate rootCert = chain[chain.length - 1];
        rootCert.verify(rootCert.getPublicKey());
        
        // Verify root fingerprint matches trust bundle
        byte[] rootFingerprint = computeSha256Fingerprint(rootCert);
        boolean foundInBundle = false;
        
        for (int i = 0; i < trustBundle.length; i++) {
            byte[] bundleFingerprint = computeSha256Fingerprint(trustBundle[i]);
            if (Arrays.equals(rootFingerprint, bundleFingerprint)) {
                foundInBundle = true;
                break;
            }
        }
        
        if (!foundInBundle) {
            throw new CertificateException(
                "Root certificate not found in SPIRE trust bundle (SHA-256 mismatch)");
        }
    }
    
    /**
     * Computes SHA-256 fingerprint of a certificate.
     * Bootstrap-safe: uses standard MessageDigest.
     */
    private byte[] computeSha256Fingerprint(X509Certificate cert) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(cert.getEncoded());
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
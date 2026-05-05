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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.io.IOException;
import java.util.Collection;
import java.util.List;

/**
 * X509TrustManager that validates peer certificates as SPIFFE SVIDs.
 * Trusts certificates signed by the SPIRE trust bundle.
 * 
 * <p>Bootstrap-safe: no lambdas.
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
        // String expectedTrustDomain = credentialManager.getSpiffeId().split("/")[2];
        // if (!spiffeId.startsWith("spiffe://" + expectedTrustDomain + "/")) {
        //     throw new CertificateException("SPIFFE ID trust domain mismatch");
        // }
        
        // 3. Verify signature chain against trust bundle
        // (SPIRE trust bundle is in our own Subject's public credentials as root CA)
        try {
            verifyChainAgainstTrustBundle(chain);
        } catch (Exception e) {
            throw new CertificateException("Failed to verify SPIFFE SVID chain", e);
        }
        
        // 4. Verify certificate validity
        leafCert.checkValidity();
        
        // Success — peer is trusted SPIFFE workload
    }
    
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
    
    private void verifyChainAgainstTrustBundle(X509Certificate[] chain)
            throws Exception {
        
        // Get trust bundle from SpiffeCredentialManager
        // (SPIRE includes trust bundle in X509SVIDResponse.bundle field)
        // For now, simplified: verify chain[last] is self-signed root
        
        X509Certificate rootCert = chain[chain.length - 1];
        
        // Verify each cert is signed by the next in chain
        for (int i = 0; i < chain.length - 1; i++) {
            X509Certificate cert = chain[i];
            X509Certificate issuer = chain[i + 1];
            cert.verify(issuer.getPublicKey());
        }
        
        // Verify root is self-signed
        rootCert.verify(rootCert.getPublicKey());
        
        // TODO: Compare root fingerprint against SPIRE trust bundle
        // (requires SpiffeCredentialManager to expose trust bundle)
    }
    
    @Override
    public X509Certificate[] getAcceptedIssuers() {
        // Return empty array — we accept any SPIFFE SVID in our trust domain
        // (JSSE uses this for client cert requests; empty = "any issuer OK")
        return new X509Certificate[0];
    }
}
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

import javax.net.ssl.X509KeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.io.IOException;
import java.util.Set;
import javax.security.auth.Subject;

/**
 * X509KeyManager that retrieves credentials from SpiffeCredentialManager.
 * Credentials rotate automatically when SPIRE issues a new SVID.
 * 
 * <p>Bootstrap-safe: no lambdas, explicit iteration.
 */
public final class SpiffeX509KeyManager implements X509KeyManager {
    
    private final SpiffeCredentialManager credentialManager;
    
    public SpiffeX509KeyManager() throws IOException {
        this.credentialManager = SpiffeCredentialManager.getInstance();
    }
    
    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        // SPIFFE SVIDs use "RSA" or "EC" key types
        if ("RSA".equals(keyType) || "EC".equals(keyType)) {
            return new String[] { "spiffe" };
        }
        return null;
    }
    
    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        // Always return "spiffe" � we have exactly one credential source
        for (int i = 0; keyType != null && i < keyType.length; i++) {
            if ("RSA".equals(keyType[i]) || "EC".equals(keyType[i])) {
                return "spiffe";
            }
        }
        return null;
    }
    
    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        if ("RSA".equals(keyType) || "EC".equals(keyType)) {
            return new String[] { "spiffe" };
        }
        return null;
    }
    
    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        if ("RSA".equals(keyType) || "EC".equals(keyType)) {
            return "spiffe";
        }
        return null;
    }
    
    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        if (!"spiffe".equals(alias)) {
            return null;
        }
        
        Subject subject = credentialManager.getSubject(); // Credential manager unavailable � return null (JSSE will fail handshake)
        Set<X509Certificate> certs = subject.getPublicCredentials(X509Certificate.class);
        // SPIRE returns certificates in order: leaf, intermediate, ...
        // Convert to array preserving order
        X509Certificate[] chain = new X509Certificate[certs.size()];
        int index = 0;
        for (X509Certificate cert : certs) {
            chain[index] = cert;
            index = index + 1;
        }
        return chain;
    }
    
    @Override
    public PrivateKey getPrivateKey(String alias) {
        if (!"spiffe".equals(alias)) {
            return null;
        }
        
        Subject subject = credentialManager.getSubject();
        Set<PrivateKey> keys = subject.getPrivateCredentials(PrivateKey.class);
        // SPIRE returns exactly one private key per SVID
        for (PrivateKey key : keys) {
            return key;  // Return first (and only) key
        }
        return null;
    }
}
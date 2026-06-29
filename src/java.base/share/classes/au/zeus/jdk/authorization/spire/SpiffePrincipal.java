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

import au.zeus.jdk.net.Uri;
import java.net.URISyntaxException;
import java.security.Principal;

/**
 * A {@link Principal} representing a SPIFFE workload identity, identified by a
 * SPIFFE ID URI of the form {@code spiffe://<trust-domain>/<path>}.
 *
 * <p>
 * SPIFFE IDs are carried as URI SubjectAlternativeNames (type 6) in the leaf
 * certificate of an X.509 SVID (SPIFFE Verifiable Identity Document). 
 *
 * <h2>SPIFFE ID format</h2>
 * <p>
 * A SPIFFE ID is a URI in the form {@code spiffe://<trust-domain>/<path>} where
 * {@code <trust-domain>} is a DNS name identifying the trust domain and
 * {@code <path>} is a workload-specific path segment. Example:
 * <pre>
 *   spiffe://test.jgdms.local/svc/reggie
 *   spiffe://jgdms.example.org/host/lookup
 * </pre>
 *
 */
public final class SpiffePrincipal implements Principal {

    /**
     * The SPIFFE ID URI, e.g. {@code spiffe://example.org/svc/name}.
     */
    private final String spiffeId;

    /**
     * Creates a {@code SpiffePrincipal} for the given SPIFFE ID.
     *
     * @param spiffeId the SPIFFE ID URI; must start with {@code spiffe://}
     * @throws NullPointerException if {@code spiffeId} is null
     * @throws IllegalArgumentException if {@code spiffeId} does not start with
     * {@code spiffe://}
     */
    public SpiffePrincipal(String spiffeId) {
        this(toUri(spiffeId));
    }
    
    private SpiffePrincipal(Uri spiffeId){
        this.spiffeId = spiffeId.toString();
    }
    
    private static Uri toUri(String spiffeId){
        if (spiffeId == null) {
            throw new NullPointerException("spiffeId must not be null");
        }
        if (!spiffeId.startsWith("spiffe://")
                || spiffeId.length() <= "spiffe://".length()) {
            throw new IllegalArgumentException(
                    "SPIFFE ID must start with 'spiffe://' and have a "
                    + "non-empty trust domain: " + spiffeId);
        }
        try {
            return new Uri(spiffeId);
        } catch (URISyntaxException ex) {
            throw new IllegalArgumentException("URI Syntax Exception ", ex);
        }
    }

    /**
     * Returns the SPIFFE ID URI.
     *
     * @return the SPIFFE ID; never {@code null}
     */
    @Override
    public String getName() {
        return spiffeId;
    }

    /**
     * Returns {@code true} if {@code obj} is a {@code SpiffePrincipal} with the
     * same SPIFFE ID URI.
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SpiffePrincipal)) {
            return false;
        }
        return spiffeId.equals(((SpiffePrincipal) obj).spiffeId);
    }

    @Override
    public int hashCode() {
        return spiffeId.hashCode();
    }

    /**
     * Returns a string of the form {@code SpiffePrincipal(spiffe://...)}.
     */
    @Override
    public String toString() {
        return "SpiffePrincipal(" + spiffeId + ")";
    }

}

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

package au.zeus.jdk.authorization.policy;

import javax.security.auth.Subject;
import java.net.URL;

/**
 * Bootstrap policy layer that fetches grants from an HTTPS server using
 * a SPIFFE X.509 SVID for TLS client authentication.
 *
 * <p>Extends {@link ConcurrentPolicyFile}, supplying an
 * {@link HttpsClientAuthPolicyParser} as the parser and a fixed HTTPS URL
 * as the sole policy location. All grant management, {@code implies()},
 * {@code getPermissions()}, {@code getPermissionGrants()}, and
 * {@code refresh()} are inherited unchanged.
 *
 * <p>{@code refresh()} re-fetches from the same HTTPS URL using the same
 * Subject, making SVID rotation transparent — the caller
 * ({@code SpiffeCredentialManager}) simply calls {@code refresh()} when a
 * new SVID is provisioned and the grant set is atomically replaced.
 *
 * <p>Fail-secure by construction: if the HTTPS server is unreachable,
 * returns a non-200 response, or the policy cannot be parsed,
 * {@link PolicyInitializationException} is thrown during superclass
 * construction and the node does not start.
 *
 * <p>{@link PermissionComparator} is always used — it is well-tested,
 * reliable, and correct for all policy grant comparisons in this stack.
 *
 * <p>Bootstrap constraints: this class is instantiated during early JVM
 * bootstrap as part of the DirtyChai OpenJDK fork. No lambdas, method
 * references, or string switch statements may be used — these rely on
 * invokedynamic / metafactory infrastructure not yet initialised at
 * bootstrap time.
 *
 * @see HttpsClientAuthPolicyParser
 * @see ConcurrentPolicyFile
 * @see PermissionComparator
 * @author Peter Firmstone
 * @since 3.1.1
 */
public class SpiffePolicyFile extends ConcurrentPolicyFile {

    /**
     * Fetches the bootstrap policy from {@code policyUrl} over HTTPS,
     * authenticating as {@code spiffeSubject}.
     *
     * <p>Construction blocks until the policy is successfully fetched and
     * parsed. If the server is unreachable or returns an error,
     * {@link PolicyInitializationException} is thrown — the node must not
     * start without a valid bootstrap policy.
     *
     * <p>The {@code spiffeSubject} must be read-only before being passed
     * here (caller must invoke {@link Subject#setReadOnly()}) to prevent
     * credential substitution between construction and any subsequent
     * {@code refresh()} call.
     *
     * @param spiffeSubject the SPIFFE Subject carrying SVID credentials;
     *                      must not be {@code null} and must be read-only
     * @param policyUrl     the https URL of the bootstrap policy file;
     *                      must not be {@code null}
     * @throws PolicyInitializationException if the policy cannot be fetched
     *         or parsed
     * @throws NullPointerException if either argument is {@code null}
     */
    public SpiffePolicyFile(Subject spiffeSubject, URL policyUrl)
            throws PolicyInitializationException {
        super(new HttpsClientAuthPolicyParser(spiffeSubject),
              new PermissionComparator(),
              new URL[]{policyUrl});
    }
}

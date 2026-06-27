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

import org.apache.river.api.security.PermissionGrant;

import javax.net.ssl.HttpsURLConnection;
import javax.security.auth.Subject;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URL;
import java.security.KeyStore;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import javax.security.auth.WorkerSubject;

/**
 * A {@link PolicyParser} that fetches a policy file over HTTPS using a
 * SPIFFE X.509 SVID for TLS client authentication.
 *
 * <p>The SPIFFE {@link Subject} — carrying the SVID certificate chain as a
 * public credential and the private key as a private credential — is supplied
 * at construction time. The URL is opened inside a
 * {@link Subject#doAs(Subject, PrivilegedExceptionAction)} call so that the
 * JSSE stack can locate the Subject's credentials during the TLS handshake. 
 * This Subject is not an instance of WorkerSubject.
 *
 * <p>The supplied Subject should be read-only (caller must invoke
 * {@link Subject#setReadOnly()} before construction) to prevent credential
 * substitution between construction time and the {@code doAs} call.
 *
 * <p>All grant scanning and resolution logic is inherited from
 * {@link DefaultPolicyParser}. This class is responsible only for opening
 * the HTTPS connection correctly.
 *
 * <p>This class is called only during early JVM bootstrap, where only trusted
 * {@code java.base} classes are present. Consequently:
 * <ul>
 *   <li>No lambdas or method references may be used (invokedynamic /
 *       metafactory not yet initialised at bootstrap time).
 *   <li>No string switch statements (invokedynamic-based in javac output).
 *   <li>{@link HttpsURLConnection} is used in preference to
 *       {@code java.net.http.HttpClient}, which is in an unprivileged module
 *       outside the trusted codebase.
 * </ul>
 *
 * <p>Fail-secure: any non-200 HTTP response or I/O error propagates as an
 * exception, preventing the node from starting without a valid bootstrap
 * policy.
 *
 * @see DefaultPolicyParser
 * @see PolicyParser
 * @see SpiffePolicyFile
 * @author Peter Firmstone
 * @since 3.1.1
 */
public class HttpsClientAuthPolicyParser extends DefaultPolicyParser {

    private final Subject spiffeSubject;

    /**
     * Constructs a parser that will authenticate to the policy HTTPS server
     * using the credentials held in {@code spiffeSubject}.
     *
     * @param spiffeSubject the SPIFFE Subject carrying the SVID credentials;
     *                      must not be {@code null} and should be read-only
     * @throws NullPointerException if {@code spiffeSubject} is {@code null}
     */
    public HttpsClientAuthPolicyParser(Subject spiffeSubject) {
        this(spiffeSubject, check(spiffeSubject));
    }
    
    private HttpsClientAuthPolicyParser(Subject spiffeSubject, boolean check) {
        super();
        this.spiffeSubject = spiffeSubject;
    }
    
    private static final boolean check(Subject spiffeSubject){
        if (spiffeSubject == null) throw new NullPointerException("spiffeSubject");
        if (spiffeSubject instanceof WorkerSubject) throw new IllegalArgumentException("WorkerSubject not allowed here.");
        return true;
    }

    /**
     * Fetches the policy at {@code location} over HTTPS, authenticating as
     * the SPIFFE Subject, then scans and resolves the grants.
     *
     * <p>The connection is opened inside a
     * {@link Subject#doAs(Subject, PrivilegedExceptionAction)} call so that
     * JSSE can locate the Subject's X.509 credentials during the TLS
     * handshake. No {@code SSLSocketFactory} is set explicitly — doing so
     * would bypass the Subject-based credential lookup.
     *
     * @param location an https URL of the bootstrap policy file
     * @param system   system properties used for property expansion
     * @return a collection of resolved {@link PermissionGrant} objects,
     *         may be empty but never {@code null}
     * @throws IllegalArgumentException if {@code location} is not an
     *         {@code https} URL
     * @throws IOException if the server returns a non-200 status or on any
     *         I/O error
     * @throws Exception on policy file syntax errors or grant resolution
     *         failures
     */
    @Override
    public Collection<PermissionGrant> parse(final URL location,
            final Properties system) throws Exception {
        if (!"https".equalsIgnoreCase(location.getProtocol())) {
            throw new IllegalArgumentException(
                    "HttpsClientAuthPolicyParser requires an https URL, got: "
                    + location);
        }

        try {
            return Subject.doAs(spiffeSubject,
                    new PrivilegedExceptionAction<Collection<PermissionGrant>>() {
                        @Override
                        public Collection<PermissionGrant> run() throws Exception {
                            return fetchAndParse(location, system);
                        }
                    });
        } catch (PrivilegedActionException e) {
            // Unwrap — callers expect Exception, not PrivilegedActionException
            throw e.getException();
        }
    }

    /**
     * Opens the HTTPS connection, scans the policy stream, and resolves
     * grants. Called from within the {@code Subject.doAs} action in
     * {@link #parse(URL, Properties)}.
     *
     * <p>No lambda or method reference may be used in this method or any
     * method it calls — see class-level documentation.
     */
    private Collection<PermissionGrant> fetchAndParse(URL location,
            Properties system) throws Exception {
        HttpsURLConnection conn =
                (HttpsURLConnection) location.openConnection();
        conn.setRequestMethod("GET");
        conn.connect();

        int status = conn.getResponseCode();
        if (status != 200) {
            conn.disconnect();
            throw new IOException(
                    "Bootstrap policy server returned HTTP " + status
                    + " for: " + location);
        }

        boolean resolve = PolicyUtils.canExpandProperties();
        Reader r = new BufferedReader(
                new InputStreamReader(conn.getInputStream(), "UTF-8"));

        Collection<DefaultPolicyScanner.GrantEntry> grantEntries =
                new HashSet<DefaultPolicyScanner.GrantEntry>();
        List<DefaultPolicyScanner.KeystoreEntry> keystores =
                new ArrayList<DefaultPolicyScanner.KeystoreEntry>();

        try {
            scanner.scanStream(r, grantEntries, keystores);
        } finally {
            r.close();
            conn.disconnect();
        }

        KeyStore ks = initKeyStore(keystores, location, system, resolve);

        Collection<PermissionGrant> result =
                new HashSet<PermissionGrant>();
        for (DefaultPolicyScanner.GrantEntry ge : grantEntries) {
            try {
                PermissionGrant pe = resolveGrant(ge, ks, system, resolve);
                if (!pe.isVoid()) result.add(pe);
            } catch (Exception e) {
                if (e instanceof SecurityException) throw (SecurityException) e;
                log("security.1A9", new Object[]{ge}, e);
            }
        }
        return result;
    }
}

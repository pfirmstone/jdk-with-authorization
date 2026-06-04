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
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.security.auth.Subject;
import javax.security.auth.UserSubject;
import javax.security.auth.WorkerSubject;
import javax.security.auth.x500.X500PrivateCredential;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URL;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletionException;

/**
 * A {@link PolicyParser} that fetches a policy file over HTTPS, optionally
 * authenticating with a client {@link Subject} for TLS client auth.
 *
 * <p>The behaviour of {@link #parse(URL, Properties)} depends on the type of
 * the {@link Subject} supplied at construction time:
 * <ul>
 *   <li><strong>{@link WorkerSubject} (SPIFFE)</strong> — the Subject's
 *       {@link X500PrivateCredential} and {@link CertPath} are extracted and
 *       used to build an {@link SSLContext} that is set explicitly on the
 *       connection. {@code Subject.doAs()} is <em>not</em> used because
 *       {@code WorkerSubject} identity is ambient: the process principals are
 *       embedded in every {@code ProtectionDomain} at class-load time by
 *       {@code SecureClassLoader} and must not be re-installed via
 *       {@code doAs}.</li>
 *   <li><strong>{@link UserSubject}</strong> — the Subject is installed as the
 *       current scoped identity via {@link Subject#callAs} for the duration of
 *       the fetch. The JVM-default {@code SSLSocketFactory} is used; the caller
 *       is responsible for any additional credential configuration.</li>
 *   <li><strong>Plain {@code Subject} (legacy)</strong> — the Subject is
 *       installed via {@link Subject#doAs} so that JSSE can locate client
 *       credentials through the {@code SubjectDomainCombiner}.</li>
 * </ul>
 *
 * <p>The supplied Subject should be read-only (caller must invoke
 * {@link Subject#setReadOnly()} before construction) to prevent credential
 * substitution between construction time and the connection setup.
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
        super();
        if (spiffeSubject == null) throw new NullPointerException("spiffeSubject");
        this.spiffeSubject = spiffeSubject;
    }

    /**
     * Fetches the policy at {@code location} over HTTPS and resolves the
     * grants.
     *
     * <p>The Subject supplied at construction time controls how the HTTPS
     * connection is authenticated:
     * <ul>
     *   <li>A {@link WorkerSubject} causes an {@link SSLContext} to be built
     *       from the Subject's embedded X.509 credentials and set explicitly
     *       on the connection.
     *   <li>A {@link UserSubject} causes the connection to be opened inside a
     *       {@link Subject#callAs} scope.
     *   <li>A plain {@link Subject} causes the connection to be opened inside a
     *       {@link Subject#doAs} scope for legacy JSSE credential lookup via
     *       {@code SubjectDomainCombiner}.
     * </ul>
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

        if (spiffeSubject instanceof WorkerSubject) {
            // WorkerSubject (SPIFFE) identity is ambient — principals are
            // embedded in every ProtectionDomain at class-load time.
            // Subject.doAs() rejects WorkerSubject; configure the SSLContext
            // explicitly from the Subject's X.509 credentials instead.
            SSLSocketFactory factory = buildSslSocketFactory();
            return fetchAndParse(location, system, factory);
        } else if (spiffeSubject instanceof UserSubject) {
            // UserSubject must use Subject.callAs(), not Subject.doAs().
            try {
                return Subject.callAs(spiffeSubject,
                        new Callable<Collection<PermissionGrant>>() {
                            @Override
                            public Collection<PermissionGrant> call()
                                    throws Exception {
                                return fetchAndParse(location, system, null);
                            }
                        });
            } catch (CompletionException ce) {
                Throwable cause = ce.getCause();
                if (cause instanceof Exception) throw (Exception) cause;
                throw ce;
            }
        } else {
            // Legacy plain Subject: use doAs so that JSSE can locate
            // client credentials via the SubjectDomainCombiner.
            try {
                return Subject.doAs(spiffeSubject,
                        new PrivilegedExceptionAction<Collection<PermissionGrant>>() {
                            @Override
                            public Collection<PermissionGrant> run()
                                    throws Exception {
                                return fetchAndParse(location, system, null);
                            }
                        });
            } catch (PrivilegedActionException e) {
                // Unwrap — callers expect Exception, not PrivilegedActionException
                throw e.getException();
            }
        }
    }

    /**
     * Extracts X.509 credentials from a {@link WorkerSubject} and builds an
     * {@link SSLSocketFactory} configured to present them during TLS client
     * authentication.
     *
     * <p>The subject must contain an {@link X500PrivateCredential} in its
     * private credential set. If a {@link CertPath} is present in the public
     * credential set its full chain is used; otherwise only the leaf
     * certificate from the private credential is presented.
     *
     * <p>No lambda or method reference may be used in this method — see
     * class-level documentation.
     *
     * @return an {@link SSLSocketFactory} configured for SPIFFE client auth
     * @throws Exception if credential extraction or SSLContext initialisation
     *         fails
     */
    private SSLSocketFactory buildSslSocketFactory() throws Exception {
        Iterator<X500PrivateCredential> privIt =
                spiffeSubject.getPrivateCredentials(X500PrivateCredential.class)
                        .iterator();
        if (!privIt.hasNext()) {
            throw new IllegalStateException(
                    "WorkerSubject has no X500PrivateCredential");
        }
        X500PrivateCredential privCred = privIt.next();
        PrivateKey privateKey = privCred.getPrivateKey();

        Certificate[] certChain;
        Iterator<CertPath> pubIt =
                spiffeSubject.getPublicCredentials(CertPath.class).iterator();
        if (pubIt.hasNext()) {
            List<? extends Certificate> certs = pubIt.next().getCertificates();
            certChain = certs.toArray(new Certificate[certs.size()]);
        } else {
            certChain = new Certificate[]{ privCred.getCertificate() };
        }

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("spiffe", privateKey, new char[0], certChain);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);

        SSLContext sslCtx = SSLContext.getInstance("TLS");
        sslCtx.init(kmf.getKeyManagers(), null, null);
        return sslCtx.getSocketFactory();
    }

    /**
     * Opens the HTTPS connection, optionally installing an
     * {@link SSLSocketFactory}, scans the policy stream, and resolves grants.
     *
     * <p>When {@code factory} is non-null it is set on the connection before
     * the request is sent (used for the {@link WorkerSubject}/SPIFFE path).
     * For the {@link UserSubject} and legacy {@link Subject} paths
     * {@code factory} is {@code null} and the JVM-default socket factory
     * is used.
     *
     * <p>No lambda or method reference may be used in this method or any
     * method it calls — see class-level documentation.
     */
    private Collection<PermissionGrant> fetchAndParse(URL location,
            Properties system, SSLSocketFactory factory) throws Exception {
        HttpsURLConnection conn =
                (HttpsURLConnection) location.openConnection();
        if (factory != null) {
            conn.setSSLSocketFactory(factory);
        }
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

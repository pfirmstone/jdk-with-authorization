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

import au.zeus.jdk.authorization.policy.PolicyInitializationException;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Singleton manager for SPIFFE credentials obtained from the SPIRE Workload API.
 * Maintains the current X.509 SVID as a read-only {@link Subject} and watches
 * for SVID rotation in the background.
 *
 * <p>When a new SVID is received, all registered listeners are notified so they
 * can refresh their policy grants. This enables automatic policy refresh on
 * SVID rotation without polling.
 *
 * <p>Bootstrap-safe: no lambdas, method references, string switches, or
 * invokedynamic constructs. Can be used during early JVM initialization.
 *
 * <p>Configuration via system properties:
 * <ul>
 *   <li>{@code spiffe.workload.socket} — path to SPIRE agent socket
 *       (default: {@code /run/spire/sockets/agent.sock})
 *   <li>{@code spiffe.policy.url} — bootstrap policy URL (overrides derivation
 *       from SPIFFE ID)
 * </ul>
 *
 * @author Peter Firmstone
 * @since 3.1.1
 */
public final class SpiffeCredentialManager {

  private static final String DEFAULT_SOCKET_PATH = "/run/spire/sockets/agent.sock";
  private static final String SOCKET_PROPERTY = "spiffe.workload.socket";
  private static final String POLICY_URL_PROPERTY = "spiffe.policy.url";

  private static final SpiffeCredentialManager INSTANCE;
  
  static {
      SpiffeCredentialManager scm = null;
      try {
          scm = new SpiffeCredentialManager();
      } catch (IOException ex) {
          System.getLogger(SpiffeCredentialManager.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
      }
      INSTANCE = scm;
  }

  private final SpireWorkloadApiClient client;
  private volatile Subject currentSubject;
  private volatile String currentSpiffeId;
  private final List<SvidRotationListener> listeners;
  private final Object listenerLock = new Object();

  /**
   * Private constructor for singleton. Connects to SPIRE agent and performs
   * initial SVID fetch.
   *
   * @throws PolicyInitializationException if SPIRE connection or initial
   *         fetch fails
   */
  private SpiffeCredentialManager() throws IOException {
    this.listeners = new ArrayList<SvidRotationListener>();

    String socketPath = System.getProperty(SOCKET_PROPERTY, DEFAULT_SOCKET_PATH);
    Path path = Path.of(socketPath);

    try {
      this.client = new SpireWorkloadApiClient(path);
      // Initial fetch
      SpireProtobuf.X509SVIDResponse response = client.fetchSVID();
      updateSubject(response);

      // Start watching for updates
      client.startWatching(new SpireWorkloadApiClient.SvidUpdateCallback() {
        @Override
        public void onUpdate(SpireProtobuf.X509SVIDResponse response) {
          try {
            updateSubject(response);
            notifyListeners();
          } catch (IOException e) {
            // Log but don't crash — current SVID remains valid
            System.err.println("Failed to update SVID: " + e.getMessage());
          }
        }

        @Override
        public void onError(SpiffeConnectionException error) {
          System.err.println("SVID watcher error: " + error.getMessage());
          // TODO: Implement reconnection logic with exponential backoff
        }
      });

    } catch (SpiffeConnectionException e) {
      throw new IOException(
          "Failed to connect to SPIRE agent at " + socketPath, e);
    }
  }

  /**
   * Returns the singleton instance.
   *
   * @return the credential manager instance
   * @throws PolicyInitializationException if initialization failed
   */
  public static SpiffeCredentialManager getInstance() throws IOException {
      if (INSTANCE == null) throw new IOException(
              "Instance doesn't exist, refer to logs.");
      return INSTANCE;
  }

  /**
   * Returns the current SPIFFE Subject containing X.509 SVID credentials.
   * The Subject is read-only and contains:
   * <ul>
   *   <li>Public credentials: {@link X509Certificate} chain (leaf + intermediates)
   *   <li>Private credentials: {@link PrivateKey} for the leaf certificate
   *   <li>Principal: {@link X500Principal} from the leaf certificate
   * </ul>
   *
   * <p>The returned Subject is safe to pass to
   * {@link au.zeus.jdk.authorization.policy.HttpsClientAuthPolicyParser} —
   * it is already read-only.
   *
   * @return current SPIFFE Subject, never {@code null}
   */
  public Subject getSubject() {
    return currentSubject;
  }

  /**
   * Returns the SPIFFE ID URI of the current SVID.
   *
   * @return SPIFFE ID (e.g., "spiffe://jgdms.example.org/host/policy")
   */
  public String getSpiffeId() {
    return currentSpiffeId;
  }

  /**
   * Returns the bootstrap policy URL. Derivation order:
   * <ol>
   *   <li>System property {@code spiffe.policy.url} (if set)
   *   <li>Derived from SPIFFE ID trust domain (if property not set)
   * </ol>
   *
   * <p>Derivation example:
   * <pre>
   * SPIFFE ID:   spiffe://jgdms.example.org/host/policy
   * Derived URL: https://policy.jgdms.example.org/bootstrap/policy
   * </pre>
   *
   * @return bootstrap policy URL
   * @throws MalformedURLException if the URL cannot be constructed
   */
  public URL getPolicyUrl() throws MalformedURLException {
    // Option 1: explicit system property
    String explicitUrl = System.getProperty(POLICY_URL_PROPERTY);
    if (explicitUrl != null) {
      return new URL(explicitUrl);
    }

    // Option 2: derive from SPIFFE ID
    // spiffe://jgdms.example.org/host/policy
    // → https://policy.jgdms.example.org/bootstrap/policy
    String spiffeId = currentSpiffeId;
    if (spiffeId == null || !spiffeId.startsWith("spiffe://")) {
      throw new MalformedURLException("Invalid SPIFFE ID: " + spiffeId);
    }

    String withoutScheme = spiffeId.substring("spiffe://".length());
    int slashIndex = withoutScheme.indexOf('/');
    String trustDomain;
    if (slashIndex == -1) {
      trustDomain = withoutScheme;
    } else {
      trustDomain = withoutScheme.substring(0, slashIndex);
    }

    // Construct: https://policy.<trust-domain>/bootstrap/policy
    return new URL("https://policy." + trustDomain + "/bootstrap/policy");
  }

  /**
   * Registers a listener to be notified when the SVID rotates.
   * Listeners are notified on the background watcher thread.
   *
   * <p>Weak references are NOT used — callers must explicitly call
   * {@link #removeListener(SvidRotationListener)} to prevent leaks.
   *
   * @param listener listener to register
   */
  public void addListener(SvidRotationListener listener) {
    if (listener == null) throw new NullPointerException("listener");
    synchronized (listenerLock) {
      if (!listeners.contains(listener)) {
        listeners.add(listener);
      }
    }
  }

  /**
   * Removes a previously registered listener.
   *
   * @param listener listener to remove
   */
  public void removeListener(SvidRotationListener listener) {
    if (listener == null) return;
    synchronized (listenerLock) {
      listeners.remove(listener);
    }
  }

  /**
   * Updates the current Subject from a SPIRE SVID response.
   *
   * @param response SVID response from SPIRE
   * @throws PolicyInitializationException if certificate or key parsing fails
   */
  private void updateSubject(SpireProtobuf.X509SVIDResponse response)
      throws IOException {
    if (response == null || response.svids.isEmpty()) {
      throw new IOException(
          "SPIRE returned empty SVID list — workload may not be registered");
    }

    // Use the first SVID (typically only one is returned)
    SpireProtobuf.X509SVID svid = response.svids.get(0);

    try {
      // Parse certificate chain
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      ByteArrayInputStream certStream = new ByteArrayInputStream(svid.certChain);
      List<X509Certificate> certList = new ArrayList<X509Certificate>();
      while (certStream.available() > 0) {
        X509Certificate cert = (X509Certificate) cf.generateCertificate(certStream);
        certList.add(cert);
      }

      if (certList.isEmpty()) {
        throw new IOException("SVID contains no certificates");
      }

      X509Certificate leafCert = certList.get(0);

      // Parse private key (PKCS#8 format)
      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(svid.privateKey);
      KeyFactory keyFactory = KeyFactory.getInstance(leafCert.getPublicKey().getAlgorithm());
      PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

      // Build Subject
      Set<Object> publicCreds = new HashSet<Object>();
      for (int i = 0; i < certList.size(); i++) {
        publicCreds.add(certList.get(i));
      }

      Set<Object> privateCreds = new HashSet<Object>();
      privateCreds.add(privateKey);

      Set<X500Principal> principals = new HashSet<X500Principal>();
      principals.add(leafCert.getSubjectX500Principal());

      Subject subject = new Subject(
          true, // read-only
          Collections.unmodifiableSet(principals),
          Collections.unmodifiableSet(publicCreds),
          Collections.unmodifiableSet(privateCreds)
      );

      this.currentSubject = subject;
      this.currentSpiffeId = svid.spiffeId;

    } catch (CertificateException e) {
      throw new IOException("Failed to parse SVID certificates", e);
    } catch (NoSuchAlgorithmException e) {
      throw new IOException("Unsupported key algorithm", e);
    } catch (InvalidKeySpecException e) {
      throw new IOException("Failed to parse SVID private key", e);
    }
  }

  /**
   * Notifies all registered listeners that the SVID has rotated.
   * Called on the background watcher thread.
   */
  private void notifyListeners() {
    List<SvidRotationListener> listenersCopy;
    synchronized (listenerLock) {
      listenersCopy = new ArrayList<SvidRotationListener>(listeners);
    }

    for (int i = 0; i < listenersCopy.size(); i++) {
      SvidRotationListener listener = listenersCopy.get(i);
      try {
        listener.onSvidRotation();
      } catch (Exception e) {
        // Prevent one listener from breaking others
        System.err.println("Listener " + listener + " threw exception: " + e.getMessage());
      }
    }
  }

  /**
   * Callback interface for SVID rotation notifications.
   * Bootstrap-safe: no default methods, no functional interface annotation.
   */
  public interface SvidRotationListener {
    /**
     * Invoked when a new SVID is received from SPIRE. Implementations
     * should refresh policy grants or other SVID-dependent state.
     *
     * <p>This method is called on a background thread. It should return
     * quickly and not block.
     */
    void onSvidRotation();
  }
}
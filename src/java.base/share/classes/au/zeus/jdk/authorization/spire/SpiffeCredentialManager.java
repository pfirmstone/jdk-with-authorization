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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

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
 *   <li>{@code spiffe.reconnect.max.attempts} — maximum reconnection attempts
 *       (default: 10, set to 0 to disable reconnection)
 *   <li>{@code spiffe.reconnect.initial.backoff.ms} — initial backoff delay
 *       (default: 1000 ms)
 *   <li>{@code spiffe.reconnect.max.backoff.ms} — maximum backoff delay
 *       (default: 300000 ms = 5 minutes)
 * </ul>
 *
 * @author Peter Firmstone
 * @since 3.1.1
 */
public final class SpiffeCredentialManager {

  private static final String DEFAULT_SOCKET_PATH = "/run/spire/sockets/agent.sock";
  private static final String SOCKET_PROPERTY = "spiffe.workload.socket";
  private static final String POLICY_URL_PROPERTY = "spiffe.policy.url";
  private static final String RECONNECT_MAX_ATTEMPTS_PROPERTY = "spiffe.reconnect.max.attempts";
  private static final String RECONNECT_INITIAL_BACKOFF_PROPERTY = "spiffe.reconnect.initial.backoff.ms";
  private static final String RECONNECT_MAX_BACKOFF_PROPERTY = "spiffe.reconnect.max.backoff.ms";

  private static final int DEFAULT_MAX_RECONNECT_ATTEMPTS = 10;
  private static final long DEFAULT_INITIAL_BACKOFF_MS = 1000;
  private static final long DEFAULT_MAX_BACKOFF_MS = 300000; // 5 minutes

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
  AtomicReference<R> subjectBundle = new AtomicReference<R>();
  
  private final List<SvidRotationListener> listeners;
  private final Object listenerLock = new Object();
  
  // Reconnection state
  private volatile boolean watcherRunning = false;
  private final AtomicInteger reconnectAttempts = new AtomicInteger();
  private final int maxReconnectAttempts;
  private final long initialBackoffMs;
  private final long maxBackoffMs;
  
  private static final class R {

        private final Subject currentSubject;
        private final String currentSpiffeId;
        private final X509Certificate[] trustBundle;
        
      R(Subject s, String id, X509Certificate [] certs){
          this.currentSubject = s;
          this.currentSpiffeId = id;
          this. trustBundle = certs;
      }
  }

  /**
   * Private constructor for singleton. Connects to SPIRE agent and performs
   * initial SVID fetch.
   *
   * @throws IOException if SPIRE connection or initial fetch fails
   */
  private SpiffeCredentialManager() throws IOException {
    this.listeners = new ArrayList<SvidRotationListener>();
    
    // Load reconnection configuration
    int mra = getIntProperty(
        RECONNECT_MAX_ATTEMPTS_PROPERTY, DEFAULT_MAX_RECONNECT_ATTEMPTS);
    if (mra > 62) mra = 62; // max allowed before bitshift overflow occurs.
    this.maxReconnectAttempts = mra;
    this.initialBackoffMs = getLongProperty(
        RECONNECT_INITIAL_BACKOFF_PROPERTY, DEFAULT_INITIAL_BACKOFF_MS);
    this.maxBackoffMs = getLongProperty(
        RECONNECT_MAX_BACKOFF_PROPERTY, DEFAULT_MAX_BACKOFF_MS);

    String socketPath = System.getProperty(SOCKET_PROPERTY, DEFAULT_SOCKET_PATH);
    Path path = Path.of(socketPath);

    try {
      this.client = new SpireWorkloadApiClient(path);
      // Initial fetch
      SpireProtobuf.X509SVIDResponse response = client.fetchSVID();
      updateSubject(response);

      // Start watching for updates
      this.watcherRunning = true;
      client.startWatching(createCallback());

    } catch (SpiffeConnectionException e) {
      throw new IOException(
          "Failed to connect to SPIRE agent at " + socketPath, e);
    }
  }

  /**
   * Returns the singleton instance.
   *
   * @return the credential manager instance
   * @throws IOException if initialization failed
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
    return subjectBundle.get().currentSubject;
  }

  /**
   * Returns the SPIFFE ID URI of the current SVID.
   *
   * @return SPIFFE ID (e.g., "spiffe://jgdms.example.org/host/policy")
   */
  public String getSpiffeId() {
    return subjectBundle.get().currentSpiffeId;
  }

  /**
   * Returns the SPIRE trust bundle (root CA certificates). The returned array
   * is a defensive copy — modifications will not affect the internal state.
   *
   * <p>The trust bundle is used to validate peer SPIFFE SVIDs. It rotates
   * independently of the workload's SVID and contains the root CA certificates
   * for the trust domain.
   *
   * @return defensive copy of trust bundle, never {@code null} but may be empty
   */
  public X509Certificate[] getTrustBundle() {
    X509Certificate[] bundle = subjectBundle.get().trustBundle; // Read volatile once
    if (bundle == null) {
      return new X509Certificate[0];
    }
    // Defensive copy
    X509Certificate[] copy = new X509Certificate[bundle.length];
    System.arraycopy(bundle, 0, copy, 0, bundle.length);
    return copy;
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
    String spiffeId = subjectBundle.get().currentSpiffeId;
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
   * Updates the current Subject and trust bundle from a SPIRE SVID response.
   *
   * @param response SVID response from SPIRE
   * @throws IOException if certificate or key parsing fails
   */
  private void updateSubject(SpireProtobuf.X509SVIDResponse response)
      throws IOException {
    if (response == null || response.svids.isEmpty()) {
        subjectBundle.set(new R(new Subject(), null, new X509Certificate[0]));
      throw new IOException(
          "SPIRE returned empty SVID list — workload may not be registered");
    }

    // Use the first SVID (typically only one is returned)
    SpireProtobuf.X509SVID svid = response.svids.get(0);

    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      
      // Parse certificate chain
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
      Set<Object> publicCreds = new LinkedHashSet<Object>();
      for (int i = 0; i < certList.size(); i++) {
        publicCreds.add(certList.get(i));
      }

      Set<Object> privateCreds = new LinkedHashSet<Object>();
      privateCreds.add(privateKey);

      Set<X500Principal> principals = new LinkedHashSet<X500Principal>();
      principals.add(leafCert.getSubjectX500Principal());

      Subject subject = new Subject(
          true, // read-only
          Collections.unmodifiableSet(principals),
          Collections.unmodifiableSet(publicCreds),
          Collections.unmodifiableSet(privateCreds)
      );

      // Parse trust bundle from X509SVID.bundle field
      // (SPIRE includes the trust bundle for this SVID's trust domain)
      X509Certificate[] bundle = null;
      if (svid.bundle != null && svid.bundle.length > 0) {
        ByteArrayInputStream bundleStream = new ByteArrayInputStream(svid.bundle);
        List<X509Certificate> bundleList = new ArrayList<X509Certificate>();
        while (bundleStream.available() > 0) {
          X509Certificate cert = (X509Certificate) cf.generateCertificate(bundleStream);
          bundleList.add(cert);
        }
        bundle = bundleList.toArray(new X509Certificate[bundleList.size()]);
      } else {
        bundle = new X509Certificate[0];
      }

      // Atomic update
      subjectBundle.set(new R(subject, svid.spiffeId, bundle));

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
        System.getLogger(SpiffeCredentialManager.class.getName()).log(System.Logger.Level.DEBUG, "Listener " + listener + " threw exception: ", e);
      }
    }
  }

  /**
   * Schedules a reconnection attempt after the specified delay.
   * Bootstrap-safe: uses raw Thread + Thread.sleep, not ScheduledExecutorService.
   *
   * @param delayMs delay in milliseconds before attempting reconnection
   */
  private void scheduleReconnect(final long delayMs) {
    Thread reconnector = new Thread(new Runnable() {
      @Override
      public void run() {
        try {
          Thread.sleep(delayMs);
          if (!watcherRunning) {
            reconnectWatcher();
          }
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          System.getLogger(SpiffeCredentialManager.class.getName()).log(System.Logger.Level.DEBUG, "Reconnection attempt interrupted", e);
        }
      }
    });
    reconnector.setDaemon(true);
    reconnector.setName("SPIRE-Watcher-Reconnect-" + reconnectAttempts);
    reconnector.start();
  }
  
  private SpireWorkloadApiClient.SvidUpdateCallback createCallback(){
      return new SpireWorkloadApiClient.SvidUpdateCallback(){
        @Override
        public void onUpdate(SpireProtobuf.X509SVIDResponse response) {
          try {
            updateSubject(response);
            reconnectAttempts.set(0); // Reset on successful update
            notifyListeners();
          } catch (IOException e) {
            System.getLogger(SpiffeCredentialManager.class.getName()).log(
                    System.Logger.Level.DEBUG, "Failed to update SVID: ", e);
          }
        }

        @Override
        public void onError(SpiffeConnectionException error) {
            System.getLogger(SpiffeCredentialManager.class.getName()).log(
                    System.Logger.Level.ERROR, "SVID watcher error: ", error);
          watcherRunning = false;
          
          if (maxReconnectAttempts <= 0) {
            System.getLogger(SpiffeCredentialManager.class.getName()).log(
                    System.Logger.Level.DEBUG, "Reconnection disabled. SVID will expire without renewal.");
            return;
          }
          
          long backoffMs = Math.min(
              initialBackoffMs * (1L << reconnectAttempts.get()),
              maxBackoffMs
          );
          
          if (reconnectAttempts.incrementAndGet() < maxReconnectAttempts) {
            StringBuilder sb = new StringBuilder();
            sb.append("Scheduling reconnect attempt ").append(reconnectAttempts)
                    .append(" of ").append(maxReconnectAttempts).append(" in ")
                    .append(backoffMs).append("ms");
            System.getLogger(SpiffeCredentialManager.class.getName()).log(
                    System.Logger.Level.DEBUG, sb.toString());
            scheduleReconnect(backoffMs);
          } else {
              System.getLogger(SpiffeCredentialManager.class.getName()).log(
                    System.Logger.Level.DEBUG, "Max reconnect attempts reached. SVID will expire without renewal.");
          }
        }
      };
  }

  /**
   * Attempts to reconnect to the SPIRE agent and restart the watcher.
   */
  private void reconnectWatcher() {
    try {
      client.stopWatching(); // Clean up old connection
      SpireProtobuf.X509SVIDResponse response = client.fetchSVID();
      updateSubject(response);
      
      watcherRunning = true;
      client.startWatching(createCallback());
      
      reconnectAttempts.set(0); // Reset on successful reconnection
      System.getLogger(SpiffeCredentialManager.class.getName()).log(
                    System.Logger.Level.DEBUG, "SPIRE watcher reconnected successfully");
      
    } catch (SpiffeConnectionException e) {
      // Reconnection failed — onError will be called automatically
      System.getLogger(SpiffeCredentialManager.class.getName()).log(
                    System.Logger.Level.DEBUG, "Reconnection attempt failed: ", e);
    } catch (IOException e) {
      System.getLogger(SpiffeCredentialManager.class.getName()).log(
                    System.Logger.Level.DEBUG, "Failed to update SVID after reconnection: ", e);
    }
  }

  /**
   * Reads an integer system property with a default value.
   * Bootstrap-safe: no parsing exceptions propagate.
   */
  private static int getIntProperty(String name, int defaultValue) {
    String value = System.getProperty(name);
    if (value == null) {
      return defaultValue;
    }
    try {
      return Integer.parseInt(value);
    } catch (NumberFormatException e) {
      StringBuilder sb = new StringBuilder();
            sb.append("Invalid integer property ").append(name)
                    .append("=").append(value).append(", using default ")
                    .append(defaultValue);
            System.getLogger(SpiffeCredentialManager.class.getName()).log(
                    System.Logger.Level.DEBUG, sb.toString(), e);
      return defaultValue;
    }
  }

  /**
   * Reads a long system property with a default value.
   * Bootstrap-safe: no parsing exceptions propagate.
   */
  private static long getLongProperty(String name, long defaultValue) {
    String value = System.getProperty(name);
    if (value == null) {
      return defaultValue;
    }
    try {
      return Long.parseLong(value);
    } catch (NumberFormatException e) {
      StringBuilder sb = new StringBuilder();
            sb.append("Invalid long property ").append(name)
                    .append("=").append(value).append(", using default ")
                    .append(defaultValue);
            System.getLogger(SpiffeCredentialManager.class.getName()).log(
                    System.Logger.Level.DEBUG, sb.toString(), e);
      return defaultValue;
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
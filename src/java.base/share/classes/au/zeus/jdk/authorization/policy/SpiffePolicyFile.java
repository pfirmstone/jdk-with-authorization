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

import au.zeus.jdk.authorization.spire.SpiffeCredentialManager;
import java.io.IOException;

import javax.security.auth.Subject;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;

/**
 * Bootstrap policy layer that fetches grants from an HTTPS server using
 * a SPIFFE X.509 SVID for TLS client authentication.
 *
 * <p>Extends {@link ConcurrentPolicyFile}, supplying a
 * {@link RefreshingParserDecorator} that automatically uses fresh SPIFFE
 * credentials on every policy fetch, even after SVID rotation.
 *
 * <p>When {@link #refresh()} is called (either manually or via SVID rotation
 * notification), the decorator obtains the current credential Subject from
 * {@link SpiffeCredentialManager} before fetching, ensuring the policy is
 * always retrieved with valid credentials.  Note that credential Subject is
 * a plain Subject, not an instance of WorkerSubject.
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
 * @see RefreshingParserDecorator
 * @see ConcurrentPolicyFile
 * @see SpiffeCredentialManager
 * @see PermissionComparator
 * @author Peter Firmstone
 * @since 3.1.1
 */
public class SpiffePolicyFile extends ConcurrentPolicyFile
    implements SpiffeCredentialManager.SvidRotationListener {

  private final SpiffeCredentialManager credentialManager;

  /**
   * Fetches the bootstrap policy from the SPIRE-derived policy URL,
   * authenticating with the workload's SPIFFE SVID.
   *
   * <p>The policy URL and SVID are obtained from
   * {@link SpiffeCredentialManager#getInstance()}, which connects to the
   * SPIRE Workload API on the local Unix domain socket.
   *
   * <p>Construction blocks until the policy is successfully fetched and
   * parsed. If the SPIRE agent is unreachable, the policy server returns
   * an error, or parsing fails, {@link PolicyInitializationException} is
   * thrown — the node must not start without a valid bootstrap policy.
   *
   * <p>After construction, this instance registers as a listener for SVID
   * rotation. When the SVID rotates, {@link #refresh()} is called
   * automatically to re-fetch the policy with fresh credentials.
   *
   * @throws PolicyInitializationException if SPIRE connection, initial SVID
   *         fetch, or policy fetch/parsing fails
   */
  public SpiffePolicyFile() throws PolicyInitializationException, IOException {
    this(SpiffeCredentialManager.getInstance());
  }

  /**
   * Package-private constructor for testing. Allows injection of a mock
   * {@link SpiffeCredentialManager} without going through the singleton.
   *
   * @param credentialManager the credential manager to use
   * @throws PolicyInitializationException if policy fetch/parsing fails
   */
  SpiffePolicyFile(SpiffeCredentialManager credentialManager)
      throws PolicyInitializationException {
    super(new RefreshingParserDecorator(credentialManager),
          new PermissionComparator(),
          getPolicyUrlArray(credentialManager));
    this.credentialManager = credentialManager;

    // Register for SVID rotation notifications
    credentialManager.addListener(this);
  }

  /**
   * Fetches the bootstrap policy from {@code policyUrl} over HTTPS,
   * authenticating as {@code spiffeSubject}.
   *
   * <p>This constructor is provided for direct use when the Subject and URL
   * are already known. The {@link #SpiffePolicyFile()} no-arg constructor
   * is preferred for bootstrap scenarios.
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
   * <p><strong>Important:</strong> This constructor does NOT register for
   * SVID rotation notifications and does NOT refresh credentials on
   * {@code refresh()}. If using this constructor directly, the caller is
   * responsible for managing credential rotation.
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
    this.credentialManager = null; // No auto-refresh when constructed directly
  }

  /**
   * Invoked by {@link SpiffeCredentialManager} when the SPIFFE SVID rotates.
   * Triggers a policy refresh. The {@link RefreshingParserDecorator} will
   * automatically use the new credentials when re-fetching the policy.
   *
   * <p>This method is called on a background thread. The refresh is
   * synchronous but should complete quickly (single HTTPS request).
   */
  @Override
  public void onSvidRotation() {
    try {
      refresh();
    } catch (Exception e) {
      // Log but don't crash — the node can continue with the previous policy
      System.err.println("Failed to refresh policy after SVID rotation: " + e.getMessage());
    }
  }

  /**
   * Helper to convert credential manager's policy URL to a single-element array.
   */
  private static URL[] getPolicyUrlArray(SpiffeCredentialManager cm)
      throws PolicyInitializationException {
    try {
      return new URL[]{cm.getPolicyUrl()};
    } catch (MalformedURLException e) {
      throw new PolicyInitializationException(
          "Failed to derive bootstrap policy URL from SPIFFE ID", e);
    } catch (URISyntaxException e) {
          throw new PolicyInitializationException(
          "Failed to derive bootstrap policy URL from SPIFFE ID", e);
      }
  }
}
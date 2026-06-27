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
import java.lang.System.Logger;
import org.apache.river.api.security.PermissionGrant;

import javax.security.auth.Subject;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import sun.security.util.Debug;

/**
 * Decorator for {@link PolicyParser} that obtains a fresh {@link Subject}
 * from {@link SpiffeCredentialManager} on every parse operation, ensuring
 * that policy fetches always use current SPIFFE credentials even after
 * SVID rotation.
 *
 * <p>This decorator eliminates the need to modify {@link ConcurrentPolicyFile}
 * or make its {@code parser} field mutable. The wrapped parser is recreated
 * on each call with fresh credentials.
 *
 * <p>Bootstrap-safe: no lambdas, method references, or invokedynamic constructs.
 *
 * @author Peter Firmstone
 * @since 3.1.1
 */
final class RefreshingParserDecorator implements PolicyParser {

  private final SpiffeCredentialManager credentialManager;
  
  private final ConcurrentMap<String, Collection<PermissionGrant>> cached = new ConcurrentHashMap<>();

  /**
   * Constructs a decorator that delegates to a fresh
   * {@link HttpsClientAuthPolicyParser} on each parse, using the current
   * Subject from the given credential manager.
   *
   * @param credentialManager source of current SPIFFE credentials
   * @throws NullPointerException if {@code credentialManager} is {@code null}
   */
  RefreshingParserDecorator(SpiffeCredentialManager credentialManager) {
    if (credentialManager == null) {
      throw new NullPointerException("credentialManager");
    }
    this.credentialManager = credentialManager;
  }

  /**
   * Parses the policy at the given location using a fresh Subject from
   * {@link SpiffeCredentialManager}. If the SVID has rotated since the
   * previous parse, the new credentials are used automatically.
   *
   * @param location policy file URL
   * @param system system properties for property expansion
   * @return collection of parsed permission grants
   * @throws Exception if parsing or fetching fails
   */
  @Override
  public Collection<PermissionGrant> parse(URL location, Properties system)
      throws Exception {
    Collection<PermissionGrant> result = null;
    try{
        // Obtain fresh Subject (may have rotated since last parse)
        Subject currentSubject = credentialManager.getCredentialSubject();
        if (currentSubject == null){
            DefaultPolicyParser.log("Spiffe Subject is null");
            result = cached.get(location.toExternalForm());
            if (result != null) return result;
            throw new NullPointerException("SpiffeSubject was null");
        }

        // Create a fresh parser with current credentials
        HttpsClientAuthPolicyParser freshParser =
            new HttpsClientAuthPolicyParser(currentSubject);

        // Delegate to the fresh parser
        result = freshParser.parse(location, system);
        cached.replace(location.toExternalForm(), result);
    } catch (IOException | GeneralSecurityException e){
        result = cached.get(location.toExternalForm());
        DefaultPolicyParser.log("Unable to refresh policy, url: {0}", new Object[]{location.toExternalForm()}, e);
        if (result == null) throw e;
    }
    return result;
  }
}
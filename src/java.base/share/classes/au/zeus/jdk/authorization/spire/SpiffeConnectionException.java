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

import java.io.IOException;

/**
 * Thrown when communication with the SPIRE Workload API fails.
 * This may indicate:
 * <ul>
 *   <li>The SPIRE agent is not running
 *   <li>The Unix domain socket path is incorrect
 *   <li>The workload is not authorized by SPIRE (no registration entry)
 *   <li>Network or protocol errors
 * </ul>
 *
 * <p>Typically wrapped in {@link au.zeus.jdk.authorization.policy.PolicyInitializationException}
 * during bootstrap policy initialization.
 *
 * @author Peter Firmstone
 * @since 3.1.1
 */
public class SpiffeConnectionException extends IOException {
  private static final long serialVersionUID = 1L;

  /**
   * Constructs a new exception with the specified detail message.
   *
   * @param message the detail message
   */
  public SpiffeConnectionException(String message) {
    super(message);
  }

  /**
   * Constructs a new exception with the specified detail message and cause.
   *
   * @param message the detail message
   * @param cause the cause
   */
  public SpiffeConnectionException(String message, Throwable cause) {
    super(message, cause);
  }
}
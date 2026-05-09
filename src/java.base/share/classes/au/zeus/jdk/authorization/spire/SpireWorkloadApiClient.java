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
import java.nio.file.Path;

/**
 * High-level client for the SPIRE Workload API. Wraps {@link SpireConnection}
 * and provides methods for fetching and watching X.509 SVIDs.
 *
 * <p>Bootstrap-safe: no lambdas, method references, or invokedynamic constructs.
 * Uses {@code sun.security.util.Debug} for diagnostic output rather than
 * {@code System.getLogger()} which is not available during bootstrap.
 *
 * <p>This class is non-final to permit {@code SpiffeCredentialManager.UnavailableClient}
 * to extend it as a null-object stand-in when the SPIRE agent is unreachable at
 * startup.  The {@code skipConnect} constructor parameter is provided for this
 * purpose — it skips the {@link SpireConnection} construction entirely.
 * No other subclassing is intended or supported.
 *
 * @author Peter Firmstone
 * @since 3.1.1
 */
class SpireWorkloadApiClient implements AutoCloseable {

  // Bootstrap-safe debug channel — controlled by -Djava.security.debug=spiffe
  private static final sun.security.util.Debug debug =
      sun.security.util.Debug.getInstance("spiffe", "SPIFFE/SPIRE Workload API Client");

  // Null when constructed via the skipConnect path (UnavailableClient).
  private final SpireConnection conn;

  private volatile SvidWatcher watcher;

  /**
   * Creates a client connected to the given SPIRE agent socket.
   *
   * @param socketPath path to the SPIRE Workload API Unix domain socket
   * @throws SpiffeConnectionException if connection fails
   */
  SpireWorkloadApiClient(Path socketPath) throws SpiffeConnectionException {
    this.conn = new SpireConnection(socketPath);
    if (debug != null) debug.println("Connected to SPIRE agent socket: " + socketPath);
  }

  /**
   * Skip-connect constructor for use by null-object subclasses only.
   * No {@link SpireConnection} is created — {@code conn} is {@code null}.
   * Subclasses must override all methods that would dereference {@code conn}.
   *
   * @param socketPath  retained for diagnostic messages
   * @param skipConnect must be {@code true}; documents intent at call site
   */
  SpireWorkloadApiClient(Path socketPath, boolean skipConnect) {
    if (!skipConnect) throw new IllegalArgumentException(
        "Use SpireWorkloadApiClient(Path) for normal construction");
    this.conn = null;
    if (debug != null) debug.println(
        "UnavailableClient created for socket: " + socketPath +
        " — no connection established");
  }

  /**
   * Fetches the current X.509 SVID. This is a one-shot call — the
   * connection remains open but the stream is closed after the response.
   *
   * @return current SVID response
   * @throws SpiffeConnectionException if the fetch fails
   */
  SpireProtobuf.X509SVIDResponse fetchSVID() throws SpiffeConnectionException {
    if (debug != null) debug.println("Fetching X.509 SVID");
    return conn.fetchX509SVID();
  }

  /**
   * Starts watching for SVID updates in the background. The callback is
   * invoked on a background thread whenever a new SVID is received.
   *
   * <p>Only one watcher can be active at a time. Calling this method
   * again stops the previous watcher.
   *
   * @param callback invoked when a new SVID is received or on error;
   *                 must not be {@code null}
   */
  void startWatching(SvidUpdateCallback callback) {
    stopWatching(); // stop any existing watcher first

    try {
      int streamId = conn.startFetchX509SVIDStream();
      SvidWatcher newWatcher = new SvidWatcher(conn, streamId, callback);
      this.watcher = newWatcher;
      Thread watcherThread = new Thread(newWatcher, "SPIRE-SVID-Watcher");
      watcherThread.setDaemon(true);
      watcherThread.start();
      if (debug != null) debug.println("SVID watcher started on stream " + streamId);
    } catch (IOException e) {
      if (debug != null) debug.println("Failed to start SVID watcher: " + e);
      callback.onError(new SpiffeConnectionException(
          "Failed to start SVID watcher", e));
    }
  }

  /**
   * Stops the background SVID watcher if one is running.
   */
  void stopWatching() {
    SvidWatcher w = this.watcher;
    if (w != null) {
      w.stop();
      this.watcher = null;
      if (debug != null) debug.println("SVID watcher stopped");
    }
  }

  /**
   * Closes the connection and stops any active watcher.
   */
  @Override
  public void close() {
    stopWatching();
    if (conn != null) {
            conn.close();
      if (debug != null) debug.println("SPIRE connection closed");
    }
  }

  /**
   * Callback interface for SVID updates.
   * Bootstrap-safe: no default methods, no {@code @FunctionalInterface}.
   */
  interface SvidUpdateCallback {
    /**
     * Invoked when a new SVID is received from the SPIRE agent.
     *
     * @param response the updated SVID response
     */
    void onUpdate(SpireProtobuf.X509SVIDResponse response);

    /**
     * Invoked when the watcher encounters an error. The watcher stops
     * after this callback is invoked.
     *
     * @param error the error that occurred
     */
    void onError(SpiffeConnectionException error);
  }

  /**
   * Background thread that watches for SVID updates on a streaming gRPC call.
   * Reads responses in a loop until {@link #stop()} is called or an error
   * occurs.
   */
  private static final class SvidWatcher implements Runnable {
    private final SpireConnection    conn;
    private final int                streamId;
    private final SvidUpdateCallback callback;
    private volatile boolean         running = true;

    SvidWatcher(SpireConnection conn, int streamId, SvidUpdateCallback callback) {
      this.conn     = conn;
      this.streamId = streamId;
      this.callback = callback;
    }

    @Override
    public void run() {
      try {
        while (running) {
          SpireProtobuf.X509SVIDResponse response = conn.readX509SVIDResponse(streamId);
          if (running) { // check again in case stop() was called during the read
            callback.onUpdate(response);
          }
        }
      } catch (IOException e) {
        if (running) { // only report error if not stopped intentionally
          callback.onError(new SpiffeConnectionException("SVID watcher failed", e));
        }
      }
    }

    /**
     * Signals the watcher loop to exit.  The watcher thread will stop
     * after the current {@code readX509SVIDResponse} call returns or throws.
     */
    void stop() {
      running = false;
    }
  }
}

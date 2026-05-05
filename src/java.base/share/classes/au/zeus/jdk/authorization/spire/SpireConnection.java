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
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.file.Path;

/**
 * Minimal HTTP/2 client for SPIRE Workload API over Unix domain socket.
 * Implements only the subset of HTTP/2 needed for unary and streaming
 * gRPC calls to the FetchX509SVID endpoint.
 *
 * <p>Bootstrap-safe: no lambdas, method references, string switches, or
 * invokedynamic constructs. Uses only {@code java.base} classes available
 * during early JVM initialization.
 *
 * <p>Limitations (acceptable for bootstrap SPIRE client):
 * <ul>
 *   <li>No HPACK dynamic table (static table only)
 *   <li>Simplified flow control (no WINDOW_UPDATE sent)
 *   <li>Single concurrent stream (sufficient for FetchX509SVID)
 *   <li>No server push support
 * </ul>
 *
 * @author Peter Firmstone
 * @since 3.1.1
 */
final class SpireConnection {

  private static final byte[] HTTP2_PREFACE =
      "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes();

  // HTTP/2 frame types
  private static final int FRAME_TYPE_DATA = 0x00;
  private static final int FRAME_TYPE_HEADERS = 0x01;
  private static final int FRAME_TYPE_RST_STREAM = 0x03;
  private static final int FRAME_TYPE_SETTINGS = 0x04;
  private static final int FRAME_TYPE_PING = 0x06;
  private static final int FRAME_TYPE_GOAWAY = 0x07;

  // HTTP/2 flags
  private static final int FLAG_END_STREAM = 0x01;
  private static final int FLAG_END_HEADERS = 0x04;
  private static final int FLAG_ACK = 0x01; // for SETTINGS/PING

  private final SocketChannel channel;
  private int nextStreamId = 1; // Client stream IDs are odd
  private volatile boolean closed = false;

  /**
   * Opens a connection to the SPIRE agent socket and completes the
   * HTTP/2 handshake.
   *
   * @param socketPath path to the SPIRE Workload API Unix domain socket
   * @throws SpiffeConnectionException if connection or handshake fails
   */
  SpireConnection(Path socketPath) throws SpiffeConnectionException {
    try {
      UnixDomainSocketAddress addr = UnixDomainSocketAddress.of(socketPath);
      this.channel = SocketChannel.open(addr);

      // Send HTTP/2 connection preface
      writeBytes(HTTP2_PREFACE);

      // Send empty SETTINGS frame
      writeFrame(FRAME_TYPE_SETTINGS, 0, 0, new byte[0]);

      // Read server's SETTINGS frame and ACK it
      Http2Frame serverSettings = readFrame();
      if (serverSettings.type != FRAME_TYPE_SETTINGS) {
        throw new SpiffeConnectionException(
            "Expected SETTINGS frame from server, got type: " + serverSettings.type);
      }

      // Send SETTINGS ACK
      writeFrame(FRAME_TYPE_SETTINGS, FLAG_ACK, 0, new byte[0]);

    } catch (IOException e) {
      throw new SpiffeConnectionException(
          "Failed to connect to SPIRE agent at " + socketPath, e);
    }
  }

  /**
   * Makes a streaming gRPC call to FetchX509SVID. Returns immediately with
   * the first response. For long-lived watching, use {@link #startFetchX509SVIDStream}.
   *
   * @return the first X509SVID response
   * @throws SpiffeConnectionException if the call fails
   */
  SpireProtobuf.X509SVIDResponse fetchX509SVID() throws SpiffeConnectionException {
    try {
      int streamId = startFetchX509SVIDStream();
      return readX509SVIDResponse(streamId);
    } catch (IOException e) {
      throw new SpiffeConnectionException("Failed to fetch X509 SVID", e);
    }
  }

  /**
   * Starts a streaming call to FetchX509SVID and returns the stream ID.
   * The stream remains open for watching SVID updates.
   *
   * @return HTTP/2 stream ID for this call
   * @throws IOException if the request cannot be sent
   */
  int startFetchX509SVIDStream() throws IOException {
    int streamId = nextStreamId;
    nextStreamId += 2;

    // Build HEADERS frame for gRPC request
    byte[] headers = encodeGrpcHeaders("/SpiffeWorkloadAPI/FetchX509SVID");
    writeFrame(FRAME_TYPE_HEADERS, FLAG_END_HEADERS, streamId, headers);

    // Build DATA frame with empty protobuf request (FetchX509SVID has no fields)
    byte[] request = SpireProtobuf.encodeX509SVIDRequest();
    byte[] grpcMessage = encodeGrpcMessage(request);
    writeFrame(FRAME_TYPE_DATA, FLAG_END_STREAM, streamId, grpcMessage);

    return streamId;
  }

  /**
   * Reads one X509SVID response from the given stream. Blocks until a
   * response is available.
   *
   * @param streamId HTTP/2 stream ID
   * @return decoded X509SVID response
   * @throws IOException if reading fails or the response is malformed
   */
  SpireProtobuf.X509SVIDResponse readX509SVIDResponse(int streamId) throws IOException {
    // Read response HEADERS frame (contains gRPC status metadata)
    Http2Frame frame = readFrameForStream(streamId);
    if (frame.type != FRAME_TYPE_HEADERS) {
      throw new IOException("Expected HEADERS frame, got type: " + frame.type);
    }

    // Read response DATA frame (contains protobuf message)
    frame = readFrameForStream(streamId);
    if (frame.type != FRAME_TYPE_DATA) {
      throw new IOException("Expected DATA frame, got type: " + frame.type);
    }

    // Check for END_STREAM flag (stream closed after this message)
    boolean endStream = (frame.flags & FLAG_END_STREAM) != 0;

    // Decode gRPC message (skip 5-byte prefix: 1 compression + 4 length)
    if (frame.payload.length < 5) {
      throw new IOException("Invalid gRPC message: too short (" +
                            frame.payload.length + " bytes)");
    }

    int messageLength = ((frame.payload[1] & 0xFF) << 24)
                      | ((frame.payload[2] & 0xFF) << 16)
                      | ((frame.payload[3] & 0xFF) << 8)
                      | (frame.payload[4] & 0xFF);

    if (frame.payload.length != 5 + messageLength) {
      throw new IOException("gRPC message length mismatch: prefix says " +
                            messageLength + ", frame has " +
                            (frame.payload.length - 5));
    }

    byte[] protobufData = new byte[messageLength];
    System.arraycopy(frame.payload, 5, protobufData, 0, messageLength);

    SpireProtobuf.X509SVIDResponse response =
        SpireProtobuf.decodeX509SVIDResponse(protobufData);

    // If stream ended, read trailing HEADERS (gRPC status)
    if (endStream) {
      frame = readFrameForStream(streamId);
      if (frame.type == FRAME_TYPE_HEADERS) {
        // TODO: decode grpc-status and grpc-message if needed
      }
    }

    return response;
  }

  /**
   * Reads frames from the connection until one for the given stream is found.
   * Handles interleaved frames (SETTINGS, PING) automatically.
   *
   * @param expectedStreamId stream ID to read for
   * @return frame for the expected stream
   * @throws IOException if connection fails or an error frame is received
   */
  private Http2Frame readFrameForStream(int expectedStreamId) throws IOException {
    while (true) {
      Http2Frame frame = readFrame();

      // Handle connection-level frames
      if (frame.streamId == 0) {
        if (frame.type == FRAME_TYPE_SETTINGS && (frame.flags & FLAG_ACK) == 0) {
          // Server sent new SETTINGS, ACK it
          writeFrame(FRAME_TYPE_SETTINGS, FLAG_ACK, 0, new byte[0]);
          continue;
        }
        if (frame.type == FRAME_TYPE_PING && (frame.flags & FLAG_ACK) == 0) {
          // Server sent PING, respond with ACK
          writeFrame(FRAME_TYPE_PING, FLAG_ACK, 0, frame.payload);
          continue;
        }
        if (frame.type == FRAME_TYPE_GOAWAY) {
          throw new IOException("Server sent GOAWAY");
        }
        // Ignore other connection-level frames
        continue;
      }

      // Handle stream-level frames
      if (frame.streamId == expectedStreamId) {
        if (frame.type == FRAME_TYPE_RST_STREAM) {
          throw new IOException("Stream " + expectedStreamId + " reset by server");
        }
        return frame;
      }

      // Frame for a different stream — should not happen with single-stream usage
      throw new IOException("Unexpected frame for stream " + frame.streamId +
                            " (expected " + expectedStreamId + ")");
    }
  }

  /**
   * Encodes gRPC headers for the given method path using HPACK.
   *
   * @param path gRPC method path (e.g., "/SpiffeWorkloadAPI/FetchX509SVID")
   * @return HPACK-encoded header block
   */
  private byte[] encodeGrpcHeaders(String path) {
    ByteBuffer buf = ByteBuffer.allocate(512);

    // Simplified literal encoding (no HPACK dynamic table for bootstrap)
    // :method: POST
    buf.put((byte) 0x00);
    encodeString(buf, ":method");
    encodeString(buf, "POST");

    // :scheme: http
    buf.put((byte) 0x00);
    encodeString(buf, ":scheme");
    encodeString(buf, "http");

    // :path: <path>
    buf.put((byte) 0x00);
    encodeString(buf, ":path");
    encodeString(buf, path);

    // :authority: localhost
    buf.put((byte) 0x00);
    encodeString(buf, ":authority");
    encodeString(buf, "localhost");

    // content-type: application/grpc
    buf.put((byte) 0x00);
    encodeString(buf, "content-type");
    encodeString(buf, "application/grpc");

    // te: trailers
    buf.put((byte) 0x00);
    encodeString(buf, "te");
    encodeString(buf, "trailers");

    byte[] result = new byte[buf.position()];
    buf.flip();
    buf.get(result);
    return result;
  }

  /**
   * Encodes a string as length-prefixed bytes (HPACK string literal).
   * No Huffman encoding (bit 7 = 0).
   */
  private void encodeString(ByteBuffer buf, String s) {
    byte[] bytes = s.getBytes();
    buf.put((byte) bytes.length);
    buf.put(bytes);
  }

  /**
   * Encodes a gRPC message with length prefix.
   * Format: [1 byte compression flag][4 bytes big-endian length][message]
   */
  private byte[] encodeGrpcMessage(byte[] protobufData) {
    byte[] result = new byte[5 + protobufData.length];
    result[0] = 0; // No compression
    result[1] = (byte) (protobufData.length >>> 24);
    result[2] = (byte) (protobufData.length >>> 16);
    result[3] = (byte) (protobufData.length >>> 8);
    result[4] = (byte) protobufData.length;
    System.arraycopy(protobufData, 0, result, 5, protobufData.length);
    return result;
  }

  /**
   * Writes an HTTP/2 frame to the connection.
   */
  private void writeFrame(int type, int flags, int streamId, byte[] payload)
      throws IOException {
    if (closed) throw new IOException("Connection closed");

    ByteBuffer buffer = ByteBuffer.allocate(9 + payload.length);

    // Frame header (9 bytes)
    buffer.put((byte) (payload.length >>> 16));
    buffer.put((byte) (payload.length >>> 8));
    buffer.put((byte) payload.length);
    buffer.put((byte) type);
    buffer.put((byte) flags);
    buffer.putInt(streamId & 0x7FFFFFFF);

    // Payload
    buffer.put(payload);

    buffer.flip();
    writeBuffer(buffer);
  }

  /**
   * Reads an HTTP/2 frame from the connection.
   */
  private Http2Frame readFrame() throws IOException {
    if (closed) throw new IOException("Connection closed");

    // Read 9-byte frame header
    ByteBuffer header = ByteBuffer.allocate(9);
    readBuffer(header);
    header.flip();

    int length = ((header.get() & 0xFF) << 16)
               | ((header.get() & 0xFF) << 8)
               | (header.get() & 0xFF);
    int type = header.get() & 0xFF;
    int flags = header.get() & 0xFF;
    int streamId = header.getInt() & 0x7FFFFFFF;

    // Read payload
    byte[] payload = new byte[length];
    if (length > 0) {
      ByteBuffer payloadBuf = ByteBuffer.wrap(payload);
      readBuffer(payloadBuf);
    }

    return new Http2Frame(type, flags, streamId, payload);
  }

  private void writeBytes(byte[] data) throws IOException {
    ByteBuffer buf = ByteBuffer.wrap(data);
    writeBuffer(buf);
  }

  private void writeBuffer(ByteBuffer buf) throws IOException {
    while (buf.hasRemaining()) {
      int written = channel.write(buf);
      if (written == 0) {
        throw new IOException("Socket write returned 0");
      }
    }
  }

  private void readBuffer(ByteBuffer buf) throws IOException {
    while (buf.hasRemaining()) {
      int read = channel.read(buf);
      if (read == -1) {
        throw new IOException("Unexpected end of stream (connection closed by server)");
      }
      if (read == 0) {
        throw new IOException("Socket read returned 0");
      }
    }
  }

  /**
   * Closes the connection gracefully. Sends GOAWAY frame if not already closed.
   */
  void close() {
    if (closed) return;
    closed = true;
    try {
      ByteBuffer payload = ByteBuffer.allocate(8);
      payload.putInt(0); // Last stream ID
      payload.putInt(0); // Error code NO_ERROR
      writeFrame(FRAME_TYPE_GOAWAY, 0, 0, payload.array());
    } catch (IOException e) {
      // Best effort
    }
    try {
      channel.close();
    } catch (IOException e) {
      // Ignore
    }
  }

  /**
   * Holds an HTTP/2 frame.
   */
  static final class Http2Frame {
    final int type;
    final int flags;
    final int streamId;
    final byte[] payload;

    Http2Frame(int type, int flags, int streamId, byte[] payload) {
      this.type = type;
      this.flags = flags;
      this.streamId = streamId;
      this.payload = payload;
    }
  }
}
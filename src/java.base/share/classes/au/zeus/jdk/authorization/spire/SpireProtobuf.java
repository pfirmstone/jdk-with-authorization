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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Minimal protobuf encoder/decoder for SPIRE Workload API messages.
 * Supports only the X509SVID message types required for bootstrap.
 *
 * <p>Bootstrap-safe: no lambdas, method references, string switches, or
 * invokedynamic constructs. Uses only {@code java.base} classes available
 * during early JVM initialization.
 *
 * <p>Wire format: tag (varint) + [length (varint)] + data
 * <ul>
 *   <li>Tag = (field_number &lt;&lt; 3) | wire_type
 *   <li>Wire types: 0 = varint, 2 = length-delimited
 * </ul>
 *
 * @author Peter Firmstone
 * @since 3.1.1
 */
final class SpireProtobuf {

  // Wire types
  private static final int WIRE_TYPE_VARINT = 0;
  private static final int WIRE_TYPE_LENGTH_DELIMITED = 2;

  // X509SVID field numbers (from spire/proto/spire/api/agent/agent.proto)
  private static final int FIELD_X509_SVID_CERT = 1;
  private static final int FIELD_X509_SVID_KEY = 2;
  private static final int FIELD_X509_SVID_BUNDLE = 3;
  private static final int FIELD_X509_SVID_SPIFFE_ID = 4;

  // X509SVIDResponse field numbers
  private static final int FIELD_RESPONSE_SVIDS = 1;

  private SpireProtobuf() {} // static only

  /**
   * Encodes an empty X509SVIDRequest. The SPIRE Workload API request
   * message is empty (no fields).
   *
   * @return zero-length byte array
   */
  static byte[] encodeX509SVIDRequest() {
    return new byte[0];
  }

  /**
   * Decodes an X509SVIDResponse from a protobuf byte array.
   *
   * @param data protobuf-encoded X509SVIDResponse
   * @return decoded response containing zero or more SVIDs
   * @throws IOException if the protobuf data is malformed
   */
  static X509SVIDResponse decodeX509SVIDResponse(byte[] data) throws IOException {
    if (data == null) throw new NullPointerException("data");
    
    ByteArrayInputStream in = new ByteArrayInputStream(data);
    List<X509SVID> svids = new ArrayList<X509SVID>();

    while (in.available() > 0) {
      int tag = readVarint(in);
      int fieldNumber = tag >>> 3;
      int wireType = tag & 0x07;

      if (fieldNumber == FIELD_RESPONSE_SVIDS && wireType == WIRE_TYPE_LENGTH_DELIMITED) {
        int length = readVarint(in);
        byte[] svidBytes = readBytes(in, length);
        svids.add(decodeX509SVID(svidBytes));
      } else {
        skipField(in, wireType);
      }
    }

    return new X509SVIDResponse(Collections.unmodifiableList(svids));
  }

  /**
   * Decodes a single X509SVID message.
   *
   * @param data protobuf-encoded X509SVID
   * @return decoded SVID
   * @throws IOException if required fields are missing or data is malformed
   */
  private static X509SVID decodeX509SVID(byte[] data) throws IOException {
    ByteArrayInputStream in = new ByteArrayInputStream(data);
    byte[] certChain = null;
    byte[] privateKey = null;
    byte[] bundle = null;
    String spiffeId = null;

    while (in.available() > 0) {
      int tag = readVarint(in);
      int fieldNumber = tag >>> 3;
      int wireType = tag & 0x07;

      if (wireType != WIRE_TYPE_LENGTH_DELIMITED) {
        skipField(in, wireType);
        continue;
      }

      int length = readVarint(in);
      byte[] value = readBytes(in, length);

      if (fieldNumber == FIELD_X509_SVID_CERT) {
        certChain = value;
      } else if (fieldNumber == FIELD_X509_SVID_KEY) {
        privateKey = value;
      } else if (fieldNumber == FIELD_X509_SVID_BUNDLE) {
        bundle = value;
      } else if (fieldNumber == FIELD_X509_SVID_SPIFFE_ID) {
        spiffeId = new String(value, java.nio.charset.StandardCharsets.UTF_8);
      }
    }

    if (certChain == null || privateKey == null) {
      throw new IOException("Invalid X509SVID: missing required fields " +
                            "(certChain=" + (certChain != null) +
                            ", privateKey=" + (privateKey != null) + ")");
    }

    return new X509SVID(certChain, privateKey, bundle, spiffeId);
  }

  /**
   * Reads a protobuf varint from the stream. Varints encode integers
   * using 7 bits per byte, with the MSB indicating continuation.
   *
   * <p>A 32-bit varint occupies at most 5 bytes. The 5th byte contributes
   * bits 28–31; any continuation bit set on the 5th byte indicates the value
   * exceeds 32 bits and is rejected.
   *
   * @param in input stream
   * @return decoded integer
   * @throws IOException if stream ends unexpectedly or varint exceeds 32 bits
   */
  private static int readVarint(ByteArrayInputStream in) throws IOException {
    int result = 0;
    int shift = 0;
    while (true) {
      int b = in.read();
      if (b == -1) throw new IOException("Truncated varint");
      result |= (b & 0x7F) << shift;
      if ((b & 0x80) == 0) return result;
      shift += 7;
      if (shift >= 35) throw new IOException("Varint too large (exceeds 32 bits)");
    }
  }

  /**
   * Reads exactly {@code length} bytes from the stream.
   *
   * @param in input stream
   * @param length number of bytes to read
   * @return byte array of exactly {@code length} bytes
   * @throws IOException if fewer bytes are available
   */
  private static byte[] readBytes(ByteArrayInputStream in, int length) throws IOException {
    if (length < 0) throw new IOException("Negative length: " + length);
    byte[] result = new byte[length];
    int read = 0;
    while (read < length) {
      int n = in.read(result, read, length - read);
      if (n == -1) throw new IOException("Truncated message: expected " +
                                         length + " bytes, got " + read);
      read += n;
    }
    return result;
  }

  /**
   * Skips a field based on its wire type.
   *
   * @param in input stream
   * @param wireType protobuf wire type
   * @throws IOException if wire type is unsupported or data is malformed
   */
  private static void skipField(ByteArrayInputStream in, int wireType) throws IOException {
    if (wireType == WIRE_TYPE_VARINT) {
      readVarint(in);
    } else if (wireType == WIRE_TYPE_LENGTH_DELIMITED) {
      int length = readVarint(in);
      long skipped = in.skip(length);
      if (skipped != length) {
        throw new IOException("Failed to skip " + length + " bytes (skipped " + skipped + ")");
      }
    } else {
      throw new IOException("Unsupported wire type: " + wireType);
    }
  }

  /**
   * Holds a single X.509 SVID returned by the SPIRE Workload API.
   */
  static final class X509SVID {
    /**
     * DER-encoded X.509 certificate chain. The first certificate is the
     * leaf (workload identity), followed by zero or more intermediates.
     */
    final byte[] certChain;

    /**
     * PKCS#8-encoded private key corresponding to the leaf certificate.
     */
    final byte[] privateKey;

    /**
     * PEM-encoded trust bundle (CA certificates). May be {@code null}
     * if no bundle was provided.
     */
    final byte[] bundle;

    /**
     * SPIFFE ID URI (e.g., "spiffe://trust.domain/workload/path").
     */
    final String spiffeId;

    X509SVID(byte[] certChain, byte[] privateKey, byte[] bundle, String spiffeId) {
      this.certChain = certChain;
      this.privateKey = privateKey;
      this.bundle = bundle;
      this.spiffeId = spiffeId;
    }
  }

  /**
   * Holds the response from a FetchX509SVID call, containing one or more
   * SVIDs. Typically only one SVID is returned for a given workload.
   */
  static final class X509SVIDResponse {
    /**
     * Unmodifiable list of SVIDs. Never {@code null}, but may be empty
     * if the SPIRE agent has no SVIDs provisioned for this workload.
     */
    final List<X509SVID> svids;

    X509SVIDResponse(List<X509SVID> svids) {
      if (svids == null) throw new NullPointerException("svids");
      this.svids = svids;
    }
  }
}
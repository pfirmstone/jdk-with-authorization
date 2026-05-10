/*
 * Copyright (c) 2025, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.net.URL;
import java.security.CodeSource;
import java.security.DigestCodeSource;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

/**
 * @test
 * @summary Tests for DigestCodeSource: equals, hashCode, implies,
 *          serialization round-trip, and DOS-limit enforcement.
 * @modules java.base/sun.security.tools.keytool
 *          java.base/sun.security.x509
 * @run main DigestCodeSourceTest
 */
public class DigestCodeSourceTest {

    // -----------------------------------------------------------------------
    // Fake Certificate for equality tests only (no serialization).
    // getEncoded() returns arbitrary bytes that are NOT valid DER, so
    // this cert must never pass through writeExternal/readExternal.
    // -----------------------------------------------------------------------
    private static final byte[] CERT_BYTES_A = new byte[]{1, 2, 3, 4};
    private static final byte[] CERT_BYTES_B = new byte[]{5, 6, 7, 8};

    private static Certificate fakeCert(byte[] encoded) {
        return new Certificate("FAKE") {
            @Override public byte[]    getEncoded()  { return encoded.clone(); }
            @Override public void      verify(PublicKey k) {}
            @Override public void      verify(PublicKey k, String p) {}
            @Override public String    toString()    { return Arrays.toString(encoded); }
            @Override public PublicKey getPublicKey(){ return null; }
        };
    }

    private static final Certificate CERT_A = fakeCert(CERT_BYTES_A);
    private static final Certificate CERT_B = fakeCert(CERT_BYTES_B);

    // Real self-signed X.509 certificate used for serialization round-trip tests.
    private static X509Certificate REAL_CERT;

    private static final byte[] SHA256_A = new byte[32];       // all-zero digest
    private static final byte[] SHA256_B = new byte[32];
    static { SHA256_B[0] = 1; }

    private static final String ALG = "SHA-256";

    // -----------------------------------------------------------------------
    // Test runner
    // -----------------------------------------------------------------------
    public static void main(String[] args) throws Exception {
        REAL_CERT = generateSelfSignedCert();

        testNullsAllowed();
        testGetDigestReturnsCopy();
        testEqualsReflexive();
        testEqualsSameContent();
        testEqualsDifferentDigest();
        testEqualsDifferentAlgorithm();
        testEqualsDifferentUrl();
        testEqualsDifferentCerts();
        testHashCodeConsistentWithEquals();
        testSerializationRoundTrip();
        testSerializationRoundTripNulls();
        testSerializationRoundTripWithCert();
        testDosLimitCertCount();
        testDosLimitCertBytes();
        testDosLimitDigestBytes();
        testDosLimitNegativeCertCount();
        testToString();
        System.out.println("All DigestCodeSourceTest assertions passed.");
    }

    // -----------------------------------------------------------------------
    // Null tolerance
    // -----------------------------------------------------------------------
    static void testNullsAllowed() throws Exception {
        DigestCodeSource dcs = new DigestCodeSource(
                (URL) null, (Certificate[]) null, null, null);
        if (dcs.getLocation() != null)
            fail("testNullsAllowed: expected null location");
        if (dcs.getCertificates() != null)
            fail("testNullsAllowed: expected null certs");
        if (dcs.getDigestAlgorithm() != null)
            fail("testNullsAllowed: expected null algorithm");
        if (dcs.getDigest() != null)
            fail("testNullsAllowed: expected null digest");
    }

    // -----------------------------------------------------------------------
    // getDigest() must return a defensive copy
    // -----------------------------------------------------------------------
    static void testGetDigestReturnsCopy() throws Exception {
        byte[] original = {10, 20, 30};
        DigestCodeSource dcs = new DigestCodeSource(
                (URL) null, (Certificate[]) null, ALG, original);
        byte[] copy1 = dcs.getDigest();
        copy1[0] = 99;
        byte[] copy2 = dcs.getDigest();
        if (copy2[0] == 99)
            fail("testGetDigestReturnsCopy: getDigest() returned aliased array");
    }

    // -----------------------------------------------------------------------
    // equals: reflexive
    // -----------------------------------------------------------------------
    static void testEqualsReflexive() throws Exception {
        DigestCodeSource dcs = make("http://example.com/a.jar", ALG, SHA256_A);
        if (!dcs.equals(dcs))
            fail("testEqualsReflexive");
    }

    // -----------------------------------------------------------------------
    // equals: same content must be equal
    // -----------------------------------------------------------------------
    static void testEqualsSameContent() throws Exception {
        DigestCodeSource a = make("http://example.com/a.jar", ALG, SHA256_A);
        DigestCodeSource b = make("http://example.com/a.jar", ALG, SHA256_A);
        if (!a.equals(b) || !b.equals(a))
            fail("testEqualsSameContent");
        if (a.hashCode() != b.hashCode())
            fail("testEqualsSameContent: hashCodes differ for equal objects");
    }

    // -----------------------------------------------------------------------
    // equals: different digest must not be equal
    // -----------------------------------------------------------------------
    static void testEqualsDifferentDigest() throws Exception {
        DigestCodeSource a = make("http://example.com/a.jar", ALG, SHA256_A);
        DigestCodeSource b = make("http://example.com/a.jar", ALG, SHA256_B);
        if (a.equals(b))
            fail("testEqualsDifferentDigest: different digests compared equal");
    }

    // -----------------------------------------------------------------------
    // equals: different algorithm must not be equal
    // -----------------------------------------------------------------------
    static void testEqualsDifferentAlgorithm() throws Exception {
        DigestCodeSource a = make("http://example.com/a.jar", "SHA-256", SHA256_A);
        DigestCodeSource b = make("http://example.com/a.jar", "SHA-512", SHA256_A);
        if (a.equals(b))
            fail("testEqualsDifferentAlgorithm: different algorithms compared equal");
    }

    // -----------------------------------------------------------------------
    // equals: different URL must not be equal
    // -----------------------------------------------------------------------
    static void testEqualsDifferentUrl() throws Exception {
        DigestCodeSource a = make("http://example.com/a.jar", ALG, SHA256_A);
        DigestCodeSource b = make("http://example.com/b.jar", ALG, SHA256_A);
        if (a.equals(b))
            fail("testEqualsDifferentUrl: different URLs compared equal");
    }

    // -----------------------------------------------------------------------
    // equals: different certs must not be equal (uses fake certs — no serialization)
    // -----------------------------------------------------------------------
    static void testEqualsDifferentCerts() throws Exception {
        URL url = new URL("http://example.com/a.jar");
        DigestCodeSource a = new DigestCodeSource(
                url, new Certificate[]{CERT_A}, ALG, SHA256_A);
        DigestCodeSource b = new DigestCodeSource(
                url, new Certificate[]{CERT_B}, ALG, SHA256_A);
        if (a.equals(b))
            fail("testEqualsDifferentCerts: different certs compared equal");
    }

    // -----------------------------------------------------------------------
    // hashCode consistency
    // -----------------------------------------------------------------------
    static void testHashCodeConsistentWithEquals() throws Exception {
        DigestCodeSource a = make("http://example.com/a.jar", ALG, SHA256_A);
        DigestCodeSource b = make("http://example.com/a.jar", ALG, SHA256_A);
        if (a.hashCode() != b.hashCode())
            fail("testHashCodeConsistentWithEquals");
    }

    // -----------------------------------------------------------------------
    // implies: same algorithm + same digest → true
    // -----------------------------------------------------------------------
    static void testImpliesSameDigest() throws Exception {
        DigestCodeSource policy = make("http://example.com/a.jar", ALG, SHA256_A);
        DigestCodeSource code   = make("http://example.com/a.jar", ALG, SHA256_A);
        if (!policy.implies(code))
            fail("testImpliesSameDigest: same digest should be implied");
    }

    // -----------------------------------------------------------------------
    // implies: different digest → false (fail-secure)
    // -----------------------------------------------------------------------
    static void testImpliesDifferentDigest() throws Exception {
        DigestCodeSource policy = make("http://example.com/a.jar", ALG, SHA256_A);
        DigestCodeSource code   = make("http://example.com/a.jar", ALG, SHA256_B);
        if (policy.implies(code))
            fail("testImpliesDifferentDigest: different digest must NOT be implied");
    }

    // -----------------------------------------------------------------------
    // implies: DigestCodeSource vs plain CodeSource delegates to super
    // -----------------------------------------------------------------------
    static void testImpliesPlainCodeSourceDelegatesToSuper() throws Exception {
        DigestCodeSource policy = make("http://example.com/a.jar", ALG, SHA256_A);
        CodeSource plain = new CodeSource(null, (Certificate[]) null);
        if (!policy.implies(plain))
            fail("testImpliesPlainCodeSourceDelegatesToSuper");
    }

    // -----------------------------------------------------------------------
    // Serialization round-trip (non-null URL + digest, no certs)
    // -----------------------------------------------------------------------
    static void testSerializationRoundTrip() throws Exception {
        URL url = new URL("http://example.com/a.jar");
        DigestCodeSource original = new DigestCodeSource(
                url, (Certificate[]) null, ALG, SHA256_A);
        DigestCodeSource restored = roundTrip(original);

        if (!original.equals(restored))
            fail("testSerializationRoundTrip: equals failed after round-trip");
        if (original.hashCode() != restored.hashCode())
            fail("testSerializationRoundTrip: hashCode changed after round-trip");
        if (!url.toExternalForm().equals(restored.getLocation().toExternalForm()))
            fail("testSerializationRoundTrip: URL not preserved");
        if (!ALG.equals(restored.getDigestAlgorithm()))
            fail("testSerializationRoundTrip: algorithm not preserved");
        if (!Arrays.equals(SHA256_A, restored.getDigest()))
            fail("testSerializationRoundTrip: digest not preserved");
    }

    // -----------------------------------------------------------------------
    // Serialization round-trip (all-null fields)
    // -----------------------------------------------------------------------
    static void testSerializationRoundTripNulls() throws Exception {
        DigestCodeSource original = new DigestCodeSource(
                (URL) null, (Certificate[]) null, null, null);
        DigestCodeSource restored = roundTrip(original);

        if (!original.equals(restored))
            fail("testSerializationRoundTripNulls: equals failed");
        if (restored.getLocation() != null)
            fail("testSerializationRoundTripNulls: location should be null");
        if (restored.getDigest() != null)
            fail("testSerializationRoundTripNulls: digest should be null");
    }

    // -----------------------------------------------------------------------
    // Serialization round-trip with a real X.509 certificate
    // -----------------------------------------------------------------------
    static void testSerializationRoundTripWithCert() throws Exception {
        URL url = new URL("http://example.com/b.jar");
        DigestCodeSource original = new DigestCodeSource(
                url, new Certificate[]{REAL_CERT}, ALG, SHA256_A);
        DigestCodeSource restored = roundTrip(original);

        if (!original.equals(restored))
            fail("testSerializationRoundTripWithCert: equals failed");
        Certificate[] rc = restored.getCertificates();
        if (rc == null || rc.length != 1)
            fail("testSerializationRoundTripWithCert: certificate count wrong");
        if (!Arrays.equals(REAL_CERT.getEncoded(), rc[0].getEncoded()))
            fail("testSerializationRoundTripWithCert: certificate bytes differ");
    }

    // -----------------------------------------------------------------------
    // DOS limit: cert count too large
    // -----------------------------------------------------------------------
    static void testDosLimitCertCount() throws Exception {
        byte[] malformed = buildStream(b -> {
            b.writeByte(1);
            b.writeUTF("http://example.com/a.jar");
            b.writeByte(1);
            b.writeInt(Integer.MAX_VALUE);
        });
        expectReadExternalFails(malformed, "Certificate count out of range");
    }

    // -----------------------------------------------------------------------
    // DOS limit: negative cert count
    // -----------------------------------------------------------------------
    static void testDosLimitNegativeCertCount() throws Exception {
        byte[] malformed = buildStream(b -> {
            b.writeByte(1);
            b.writeUTF("http://example.com/a.jar");
            b.writeByte(1);
            b.writeInt(-1);
        });
        expectReadExternalFails(malformed, "Certificate count out of range");
    }

    // -----------------------------------------------------------------------
    // DOS limit: single cert encoding too large
    // -----------------------------------------------------------------------
    static void testDosLimitCertBytes() throws Exception {
        byte[] malformed = buildStream(b -> {
            b.writeByte(1);
            b.writeUTF("http://example.com/a.jar");
            b.writeByte(1);
            b.writeInt(1);
            b.writeInt(Integer.MAX_VALUE);
        });
        expectReadExternalFails(malformed, "Certificate encoding length out of range");
    }

    // -----------------------------------------------------------------------
    // DOS limit: digest length too large
    // -----------------------------------------------------------------------
    static void testDosLimitDigestBytes() throws Exception {
        byte[] malformed = buildStream(b -> {
            b.writeByte(0);
            b.writeByte(0);
            b.writeByte(0);
            b.writeByte(1);
            b.writeInt(Integer.MAX_VALUE);
        });
        expectReadExternalFails(malformed, "Digest length out of range");
    }

    // -----------------------------------------------------------------------
    // toString
    // -----------------------------------------------------------------------
    static void testToString() throws Exception {
        byte[] d = {(byte) 0xab, (byte) 0xcd};
        DigestCodeSource dcs = new DigestCodeSource(
                new URL("http://example.com/a.jar"),
                (Certificate[]) null, "SHA-256", d);
        String s = dcs.toString();
        if (!s.startsWith("(")) fail("testToString: missing opening paren — got: " + s);
        if (!s.endsWith(")"))   fail("testToString: missing closing paren— got: " + s);
        if (!s.contains("SHA-256:abcd"))
            fail("testToString: missing algorithm:digest — got: " + s);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static DigestCodeSource make(String url, String alg, byte[] digest)
            throws Exception {
        return new DigestCodeSource(new URL(url), (Certificate[]) null, alg, digest);
    }

    private static DigestCodeSource roundTrip(DigestCodeSource src)
            throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutput out = new ObjectOutputStream(baos)) {
            src.writeExternal(out);
        }
        DigestCodeSource dst = new DigestCodeSource();
        try (ObjectInput in = new ObjectInputStream(
                new ByteArrayInputStream(baos.toByteArray()))) {
            dst.readExternal(in);
        }
        return dst;
    }

    @FunctionalInterface
    interface StreamWriter {
        void write(ObjectOutput b) throws IOException;  // ObjectOutput, not DataOutputStream
    }

    private static byte[] buildStream(StreamWriter w) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            w.write(oos);
        }
        return baos.toByteArray();
    }

    private static void expectReadExternalFails(byte[] stream, String msgFragment)
            throws Exception {
        DigestCodeSource dst = new DigestCodeSource();
        try (ObjectInput in = new ObjectInputStream(
                new ByteArrayInputStream(stream))) {
            dst.readExternal(in);
            fail("Expected IOException containing '" + msgFragment
                 + "' but no exception thrown");
        } catch (IOException expected) {
            if (!expected.getMessage().contains(msgFragment)) {
                fail("Expected message containing '" + msgFragment
                     + "' but got: " + expected.getMessage());
            }
        }
    }

    /**
     * Generates a minimal self-signed RSA/SHA-256 X.509 certificate valid
     * for one year using {@code sun.security.tools.keytool.CertAndKeyGen},
     * which is the standard JDK-internal helper for test certificate creation.
     */
    private static X509Certificate generateSelfSignedCert() throws Exception {
        CertAndKeyGen gen = new CertAndKeyGen("RSA", "SHA256withRSA");
        gen.generate(2048);
        return gen.getSelfCertificate(
                new X500Name("CN=DigestCodeSourceTest"),
                365 * 24 * 3600L);      // validity in seconds
    }

    private static void fail(String msg) {
        throw new AssertionError(msg);
    }
}
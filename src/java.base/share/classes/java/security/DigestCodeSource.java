/*
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
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package java.security;

import au.zeus.jdk.net.Uri;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.Externalizable;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import sun.net.util.URLUtil;

/**
 * Non Standard API.
 * 
 * A {@link CodeSource} that additionally identifies a code artifact by its
 * content digest, enabling DNS-free, content-addressed equality checks.
 *
 * <p>Equality and hashing use the RFC 3986 URI form of the location (avoiding
 * DNS lookups), the certificates, the digest algorithm name, and the digest
 * bytes.  {@link #getDigest()} always returns a defensive copy.
 *
 * <p>Serialization uses {@link Externalizable} with a stable binary layout
 * containing only primitives, {@code String}s, and byte arrays, compatible
 * with {@code @AtomicSerial} in JGDMS.  Standard Java {@code Serializable}
 * object graphs are never written to the stream.
 *
 * @author Peter Firmstone
 */
public final class DigestCodeSource extends CodeSource implements Externalizable {

    @java.io.Serial
    private static final long serialVersionUID = 1L;

    /** Written before every nullable field to signal presence or absence. */
    private static final byte FIELD_NULL    = 0;
    private static final byte FIELD_PRESENT = 1;

    // DOS-defence limits applied during readExternal and computeDigest.

    /** Maximum number of certificates in a single DigestCodeSource stream. */
    private static final int MAX_CERT_COUNT = 100;

    /**
     * Maximum encoded size of a single certificate (DER bytes).
     * X.509 end-entity certificates are typically 1–4 KiB; 64 KiB is generous.
     */
    private static final int MAX_CERT_BYTES = 64 * 1024;

    /**
     * Maximum digest length in bytes.
     * SHA-512 produces 64 bytes; 512 bytes is a very conservative ceiling
     * that accommodates any foreseeable algorithm.
     */
    private static final int MAX_DIGEST_BYTES = 512;

    /**
     * Maximum bytes consumed when computing a digest from a URL stream.
     * Protects against infinite / very large HTTP responses.
     * Default: 512 MiB.  Callers that need a different limit should
     * compute the digest themselves and use the pre-computed-digest constructor.
     */
    static final long MAX_STREAM_BYTES = 512L * 1024 * 1024;

    // Instance fields — all transient; the full stream is owned by
    // writeExternal / readExternal.
    private transient String digestAlgorithm;
    private transient byte[] digest;
    private transient Uri    uri;           // RFC 3986 form; avoids DNS in equals/hashCode
    private transient int    cachedHashCode;


    /**
     * No-arg constructor required by {@link Externalizable}.
     * All fields are populated by {@link #readExternal}.
     */
    public DigestCodeSource() {
        super(null, (Certificate[]) null);
    }

    /**
     * Creates a {@code DigestCodeSource} from a URL string, downloading the
     * artifact and computing its digest.
     *
     * @param url             the code location as a string (may be {@code null})
     * @param certs           the certificates (may be {@code null})
     * @param digestAlgorithm the hash algorithm, e.g. {@code "SHA-256"}
     * @throws URISyntaxException       if {@code url} is not a valid URI
     * @throws MalformedURLException    if the URI cannot be converted to a URL
     * @throws IOException              if the artifact cannot be read
     * @throws NoSuchAlgorithmException if the algorithm is unavailable
     */
    public DigestCodeSource(String url, Certificate[] certs, String digestAlgorithm)
            throws URISyntaxException, MalformedURLException,
                   IOException, NoSuchAlgorithmException {
        this(parseUri(url), certs, digestAlgorithm);
    }

    /**
     * Creates a {@code DigestCodeSource} from a URL string, downloading the
     * artifact and computing its digest.
     *
     * @param url             the code location as a string (may be {@code null})
     * @param signers         the code signers (may be {@code null})
     * @param digestAlgorithm the hash algorithm, e.g. {@code "SHA-256"}
     * @throws URISyntaxException       if {@code url} is not a valid URI
     * @throws MalformedURLException    if the URI cannot be converted to a URL
     * @throws IOException              if the artifact cannot be read
     * @throws NoSuchAlgorithmException if the algorithm is unavailable
     */
    public DigestCodeSource(String url, CodeSigner[] signers, String digestAlgorithm)
            throws URISyntaxException, MalformedURLException,
                   IOException, NoSuchAlgorithmException {
        this(parseUri(url), signers, digestAlgorithm);
    }

    /**
     * Creates a {@code DigestCodeSource} with a pre-computed digest.
     *
     * @param url             the code location (may be {@code null})
     * @param certs           the certificates (may be {@code null})
     * @param digestAlgorithm the hash algorithm name (may be {@code null})
     * @param digest          the raw digest bytes (defensively copied; may be {@code null})
     */
    public DigestCodeSource(URL url, Certificate[] certs,
                            String digestAlgorithm, byte[] digest) {
        super(url, certs);
        this.digestAlgorithm = digestAlgorithm;
        this.digest = digest != null ? digest.clone() : null;
        this.uri = uriFromUrl(url);
        this.cachedHashCode = computeHashCode();
    }

    /**
     * Creates a {@code DigestCodeSource} with a pre-computed digest.
     *
     * @param url             the code location (may be {@code null})
     * @param signers         the code signers (may be {@code null})
     * @param digestAlgorithm the hash algorithm name (may be {@code null})
     * @param digest          the raw digest bytes (defensively copied; may be {@code null})
     */
    public DigestCodeSource(URL url, CodeSigner[] signers,
                            String digestAlgorithm, byte[] digest) {
        super(url, signers);
        this.digestAlgorithm = digestAlgorithm;
        this.digest = digest != null ? digest.clone() : null;
        this.uri = uriFromUrl(url);
        this.cachedHashCode = computeHashCode();
    }

    /**
     * Promotes a plain {@link CodeSource} to a {@code DigestCodeSource},
     * attaching a pre-computed digest.  Used by SecureClassLoader
     *
     * @param cs              the source to promote (must not be {@code null})
     * @param digestAlgorithm the hash algorithm name (may be {@code null})
     * @throws IOException if a connection cannot be established.
     * @throws NoSuchAlgorithmException if the provider isn't available.
     */
    public DigestCodeSource(CodeSource cs,
                            String digestAlgorithm ) throws IOException, NoSuchAlgorithmException {
        this(cs.getLocation(), cs.getCertificates(), digestAlgorithm, computeDigest(cs.getLocation(), digestAlgorithm));
    }
    
    /**
     * Promotes a plain {@link CodeSource} to a {@code DigestCodeSource},
     * attaching a pre-computed digest. Here for testing.
     *
     * @param cs              the source to promote (must not be {@code null})
     * @param digestAlgorithm the hash algorithm name (may be {@code null})
     * @param digest          the raw digest bytes (defensively copied; may be {@code null})
     * @throws IOException if a connection cannot be established.
     * @throws NoSuchAlgorithmException if the provider isn't available.
     */
    public DigestCodeSource(CodeSource cs,
                            String digestAlgorithm, byte [] digest ) throws IOException, NoSuchAlgorithmException {
        this(cs.getLocation(), cs.getCertificates(), digestAlgorithm, digest);
    }

    // Package-private auto-compute helpers used in Phase 2 of SecureClassLoader.

    DigestCodeSource(Uri uri, Certificate[] certs, String digestAlgorithm)
            throws MalformedURLException, IOException, NoSuchAlgorithmException {
        this(uri, certs, digestAlgorithm, computeDigest(uriToUrl(uri), digestAlgorithm));
    }

    DigestCodeSource(Uri uri, CodeSigner[] signers, String digestAlgorithm)
            throws MalformedURLException, IOException, NoSuchAlgorithmException {
        this(uri, signers, digestAlgorithm, computeDigest(uriToUrl(uri), digestAlgorithm));
    }

    private DigestCodeSource(Uri uri, Certificate[] certs,
                             String digestAlgorithm, byte[] digest)
            throws MalformedURLException {
        super(uriToUrl(uri), certs);
        this.digestAlgorithm = digestAlgorithm;
        this.digest = digest;   // already a fresh array from computeDigest
        this.uri = uri;
        this.cachedHashCode = computeHashCode();
    }

    private DigestCodeSource(Uri uri, CodeSigner[] signers,
                             String digestAlgorithm, byte[] digest)
            throws MalformedURLException {
        super(uriToUrl(uri), signers);
        this.digestAlgorithm = digestAlgorithm;
        this.digest = digest;
        this.uri = uri;
        this.cachedHashCode = computeHashCode();
    }
    
    /**
     * Performs a clone for defensive copying following unmarshaling.
     * 
     * @return clone of this DigestCodeSource.
     */
    @Override
    public DigestCodeSource clone(){
        DigestCodeSource result = null;
        try {
            result = (DigestCodeSource) super.clone();
            result.digest = digest == null ? null : digest.clone();
        } catch (CloneNotSupportedException ex) {} // ignore.
        return result;
    }

    /** 
     * Returns the digest algorithm name, e.g. {@code "SHA-256"}, or {@code null}. 
     * 
     * @return the digest algorithm name, e.g. {@code "SHA-256"}, or {@code null}.
     */
    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * Returns a defensive copy of the content digest, or {@code null} if none
     * was provided.
     * 
     * @return a defensive copy of the content digest, or {@code null} if none
     * was provided.
     */
    public byte[] getDigest() {
        return digest != null ? digest.clone() : null;
    }

    @Override
    public int hashCode() {
        return cachedHashCode;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DigestCodeSource that)) return false;
        // Compare location via RFC 3986 URI to avoid DNS resolution.
        if (uri != null && that.uri != null) {
            if (!uri.equals(that.uri)) return false;
        } else if (uri == null ^ that.uri == null) {
            // One null, one non-null: URI conversion failed on one side;
            // fall back to super which handles null URL equality safely.
            return super.equals(o);
        }
        // Both URIs null or both equal: continue with cert + digest checks.
        if (!Arrays.equals(getCertificates(), that.getCertificates())) return false;
        if (!stringsEqual(digestAlgorithm, that.digestAlgorithm)) return false;
        return Arrays.equals(digest, that.digest);
    }
    
        /**
     * Returns a string describing this {@code DigestCodeSource}, including
     * its URL, certificates, digest algorithm, and digest value.
     * <p>
     * Format: {@code (url [cert ...] algorithm:hexDigest)}
     *
     * @return a human-readable description of this {@code DigestCodeSource}.
     */
    @Override
    public String toString() {
        // Start from CodeSource's representation, which ends with ')'.
        String base = super.toString();
        if (digestAlgorithm == null && digest == null) {
            return base;
        }
        // Strip the trailing ')' so we can append digest info.
        StringBuilder sb = new StringBuilder(base.length() + 72);
        sb.append(base);
        sb.append(' ');
        sb.append(digestAlgorithm != null ? digestAlgorithm : "<null-algorithm>");
        sb.append(':');
        if (digest != null) {
            sb.append(hexEncode(digest));
        } else {
            sb.append("<null-digest>");
        }
        sb.append(')');
        return sb.toString();
    }

    /** Encodes a byte array as a lowercase hex string. */
    private static String hexEncode(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >>> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    // Externalizable

    /**
     * Binary stream layout — each nullable field is preceded by a presence byte:
     * <pre>
     *   byte  urlPresent        (FIELD_NULL | FIELD_PRESENT)
     *   if present: UTF  url.toExternalForm()
     *
     *   byte  certsPresent      (FIELD_NULL | FIELD_PRESENT)
     *   if present:
     *     int  certCount                          (≤ MAX_CERT_COUNT)
     *     for each cert:
     *       int    encodedLength                  (≤ MAX_CERT_BYTES)
     *       byte[] encoded          (DER)
     *       UTF    cert.getType()
     *
     *   byte  algorithmPresent  (FIELD_NULL | FIELD_PRESENT)
     *   if present: UTF  digestAlgorithm
     *
     *   byte  digestPresent     (FIELD_NULL | FIELD_PRESENT)
     *   if present:
     *     int    digestLength                     (≤ MAX_DIGEST_BYTES)
     *     byte[] digest
     * </pre>
     */
    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        // --- URL ---
        URL loc = getLocation();
        if (loc != null) {
            out.writeByte(FIELD_PRESENT);
            out.writeUTF(loc.toExternalForm());
        } else {
            out.writeByte(FIELD_NULL);
        }

        // --- Certificates ---
        Certificate[] certArr = getCertificates();
        if (certArr != null && certArr.length > 0) {
            out.writeByte(FIELD_PRESENT);
            out.writeInt(certArr.length);
            for (Certificate cert : certArr) {
                try {
                    byte[] enc = cert.getEncoded();
                    out.writeInt(enc.length);
                    out.write(enc);
                    out.writeUTF(cert.getType());
                } catch (CertificateEncodingException e) {
                    throw new IOException("Cannot encode certificate: " + e.getMessage(), e);
                }
            }
        } else {
            out.writeByte(FIELD_NULL);
        }

        // --- Digest algorithm ---
        if (digestAlgorithm != null) {
            out.writeByte(FIELD_PRESENT);
            out.writeUTF(digestAlgorithm);
        } else {
            out.writeByte(FIELD_NULL);
        }

        // --- Digest bytes ---
        if (digest != null) {
            out.writeByte(FIELD_PRESENT);
            out.writeInt(digest.length);
            out.write(digest);
        } else {
            out.writeByte(FIELD_NULL);
        }
    }

    /**
     * Restores all fields from the stream written by {@link #writeExternal}.
     *
     * <p>DOS defence: array lengths read from the stream are validated against
     * hard ceilings ({@link #MAX_CERT_COUNT}, {@link #MAX_CERT_BYTES},
     * {@link #MAX_DIGEST_BYTES}) before any allocation is performed.
     */
    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        // --- URL ---
        URL loc = null;
        if (in.readByte() == FIELD_PRESENT) {
            try {
                loc = Uri.parseAndCreate(in.readUTF()).toURL();
            } catch (MalformedURLException e) {
                throw new IOException("Malformed URL in DigestCodeSource stream", e);
            } catch (URISyntaxException e) {
                throw new IOException("URI Syntax error in DigestCodeSource stream", e);
            }
        }

        // --- Certificates ---
        Certificate[] restoredCerts = null;
        if (in.readByte() == FIELD_PRESENT) {
            int count = in.readInt();
            if (count < 0 || count > MAX_CERT_COUNT) {
                throw new IOException(
                        "Certificate count out of range in DigestCodeSource stream: " + count
                        + " (max " + MAX_CERT_COUNT + ")");
            }
            restoredCerts = new Certificate[count];
            for (int i = 0; i < count; i++) {
                int len = in.readInt();
                if (len < 0 || len > MAX_CERT_BYTES) {
                    throw new IOException(
                            "Certificate encoding length out of range: " + len
                            + " (max " + MAX_CERT_BYTES + ")");
                }
                byte[] enc = new byte[len];
                in.readFully(enc);
                String type = in.readUTF();
                if (type.length() > 64)// no legitimate cert type is longer than this
                    throw new IOException("Certificate type string too long: " + type.length());
                if (!"X.509".equals(type)) throw new IOException("Unknown Certificate Type: " + type);
                try {
                    CertificateFactory cf = CertificateFactory.getInstance(type);
                    restoredCerts[i] = cf.generateCertificate(
                            new ByteArrayInputStream(enc));
                } catch (CertificateException e) {
                    throw new IOException(
                            "Cannot reconstruct certificate of type "
                            + type + ": " + e.getMessage(), e);
                }
            }
        }

        // Restore inherited CodeSource fields directly — all are package-private.
        location = loc;
        certs = restoredCerts;
        locationNoFragString = loc != null ? URLUtil.urlNoFragString(loc) : null;

        // --- Digest algorithm ---
        digestAlgorithm = null;
        if (in.readByte() == FIELD_PRESENT) {
            digestAlgorithm = in.readUTF();
        }

        // --- Digest bytes ---
        digest = null;
        if (in.readByte() == FIELD_PRESENT) {
            int len = in.readInt();
            if (len < 0 || len > MAX_DIGEST_BYTES) {
                throw new IOException(
                        "Digest length out of range in DigestCodeSource stream: " + len
                        + " (max " + MAX_DIGEST_BYTES + ")");
            }
            digest = new byte[len];
            in.readFully(digest);
        }

        uri = uriFromUrl(loc);
        cachedHashCode = computeHashCode();
    }

    // Static helpers

    /**
     * Computes the content digest of the artifact at the given URL.
     *
     * <p>DOS defence: throws {@link IOException} if the stream exceeds
     * {@link #MAX_STREAM_BYTES} (default 512 MiB).
     *
     * @param url       the data location (must not be {@code null})
     * @param algorithm the digest algorithm (e.g. {@code "SHA-256"})
     * @return the raw digest bytes
     * @throws IOException              if the URL cannot be read or the
     *                                  stream exceeds {@code MAX_STREAM_BYTES}
     * @throws NoSuchAlgorithmException if the algorithm is unavailable
     */
    public static byte[] computeDigest(URL url, String algorithm)
            throws IOException, NoSuchAlgorithmException {
        try (InputStream raw = url.openStream()) {
            InputStream in = raw instanceof BufferedInputStream
                    ? raw : new BufferedInputStream(raw, 8192);
            return computeDigest(in, algorithm);
        }
    }

    /**
     * Computes the digest from an already-open stream (stream is not closed).
     *
     * <p>DOS defence: aborts with {@link IOException} after
     * {@link #MAX_STREAM_BYTES} have been read.
     */
    static byte[] computeDigest(InputStream in, String algorithm)
            throws IOException, NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        byte[] buf = new byte[8192];
        long totalRead = 0;
        int n;
        while ((n = in.read(buf)) >= 0) {
            totalRead += n;
            if (totalRead > MAX_STREAM_BYTES) {
                throw new IOException(
                        "Digest computation aborted: stream exceeds "
                        + MAX_STREAM_BYTES + " bytes");
            }
            md.update(buf, 0, n);
        }
        return md.digest();
    }

    // Private helpers

    private static Uri parseUri(String url) throws URISyntaxException {
        return url == null ? null : Uri.parseAndCreate(url);
    }

    private static URL uriToUrl(Uri uri) throws MalformedURLException {
        return uri == null ? null : uri.toURL();
    }

    private static Uri uriFromUrl(URL url) {
        if (url == null) return null;
        try {
            return Uri.urlToUri(url);
        } catch (URISyntaxException e) {
            return null;    // equals/implies fall back to super when uri == null
        }
    }

    private int computeHashCode() {
        int h = 7;
        h = 31 * h + (uri != null ? uri.hashCode() : 0);
        h = 31 * h + Arrays.hashCode(getCertificates());
        h = 31 * h + (digestAlgorithm != null ? digestAlgorithm.hashCode() : 0);
        h = 31 * h + Arrays.hashCode(digest);
        return h;
    }

    private static boolean stringsEqual(String a, String b) {
        return a == b || (a != null && a.equals(b));
    }
}

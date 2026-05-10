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
import java.io.Externalizable;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.io.Serial;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.cert.Certificate;

/**
 *
 * @author Peter Firmstone
 */
final class DigestCodeSource extends CodeSource implements Externalizable, Cloneable {
    private static final long serialVersionUID = 1L;
    
    private transient String digestAlgorithm;
    private transient byte [] digest;
    private transient Uri uri;
    
    @Override
    public DigestCodeSource clone(){
        DigestCodeSource result = null;
        try {
            result = (DigestCodeSource) super.clone();
            result.digest = digest == null ? null : digest.clone();
        } catch (CloneNotSupportedException ex) {} // ignore.
        return result;
    }
    
    public DigestCodeSource(){
        super(null, (Certificate []) null);
        digestAlgorithm = null;
        digest = null;
        uri = null;
    }

    DigestCodeSource(String url, Certificate[] certs, String digestAlgorithm ) throws MalformedURLException, URISyntaxException, IOException, NoSuchAlgorithmException {
        this(toUri(url), certs, digestAlgorithm );
    }

    DigestCodeSource(String url, CodeSigner[] signers, String digestAlgorithm ) throws MalformedURLException, URISyntaxException, IOException, NoSuchAlgorithmException {
        this(toUri(url), signers, digestAlgorithm );
    }
    
    private DigestCodeSource(Uri uri, Certificate[] certs, String digestAlgorithm ) throws MalformedURLException, URISyntaxException, IOException, NoSuchAlgorithmException {
        this(uri, certs, digestAlgorithm, computeDigest(toURL(uri), digestAlgorithm));
    }
    
    private DigestCodeSource(Uri uri, CodeSigner[] signers, String digestAlgorithm ) throws MalformedURLException, URISyntaxException, IOException, NoSuchAlgorithmException {
        this(uri, signers, digestAlgorithm, computeDigest(toURL(uri), digestAlgorithm));
    }
    
    private DigestCodeSource(Uri uri, Certificate[] certs, String digestAlgorithm, byte [] digest ) throws MalformedURLException {
        super(toURL(uri), certs); // Won't throw MalformedURLException here, previous constructor throws it first.
        this.digestAlgorithm = digestAlgorithm;
        this.digest = digest;
        this.uri = uri;
    }
    
    private DigestCodeSource(Uri uri, CodeSigner[] signers, String digestAlgorithm, byte [] digest ) throws MalformedURLException {
        super(uri.toURL(), signers); // Won't throw MalformedURLException here, previous constructor throws it first.
        this.digestAlgorithm = digestAlgorithm;
        this.digest = digest;
        this.uri = uri;
    }
    
    private static Uri toUri(String url) throws URISyntaxException{
        return url == null ? null : Uri.parseAndCreate(url);
    }
    
    private static URL toURL(Uri uri) throws MalformedURLException{
        return uri == null ? null : uri.toURL();
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        
    }
    
    /**
     * Computes the message digest of data specified by a URL.
     *
     * @param url the URL of the data
     * @param algorithm the message digest algorithm to use
     * @return the message digest, as a <code>String</code> in hexadecimal
     *	       format
     * @throws IOException if an I/O exception occurs while reading data from
     *	       the URL
     * @throws NoSuchAlgorithmException if no provider is found for the message
     *	       digest algorithm
     * @throws NullPointerException if either argument is <code>null</code>
     */
    private static byte [] computeDigest(URL url, String algorithm)
	throws IOException, NoSuchAlgorithmException
    {
	return computeDigest(url.openStream(), algorithm);
    }

    /** Computes the message digest for an input stream. */
    private static byte [] computeDigest(InputStream in, String algorithm)
	throws IOException, NoSuchAlgorithmException
    {
	try {
	    if (!(in instanceof BufferedInputStream)) {
		in = new BufferedInputStream(in, 2048);
	    }
	    MessageDigest md = MessageDigest.getInstance(algorithm);
	    byte[] buf = new byte[2048];
	    while (true) {
		int n = in.read(buf);
		if (n < 0) {
		    break;
		}
		md.update(buf, 0, n);
	    }
	    return md.digest();
	} finally {
	    try {
		in.close();
	    } catch (IOException e) {
	    }
	}
    }
    
}

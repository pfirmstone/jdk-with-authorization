/*
 * Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
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

package sun.security.ssl;

import java.nio.ByteBuffer;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

/**
 *
 * @author Peter Firmstone
 */
public class QuicTLSEngineFacadeImpl extends SSLEngine {

    private final QuicTLSEngineImpl qtlse;
    
    QuicTLSEngineFacadeImpl(QuicTLSEngineImpl qtlse){
        this.qtlse = qtlse;
        
    }

    @Override
    public SSLSession getHandshakeSession() {
        return qtlse.getHandshakeSession();
    }

    @Override
    public SSLParameters getSSLParameters() {
        return qtlse.getSSLParameters();
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst) throws SSLException {
        throw new UnsupportedOperationException("Not supported.");
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length) throws SSLException {
        throw new UnsupportedOperationException("Not supported.");
    }

    @Override
    public Runnable getDelegatedTask() {
        return qtlse.getDelegatedTask();
    }

    @Override
    public void closeInbound() throws SSLException {
        throw new UnsupportedOperationException("Not supported.");
    }

    @Override
    public boolean isInboundDone() {
        throw new UnsupportedOperationException("Not supported.");
    }

    @Override
    public void closeOutbound() {
        throw new UnsupportedOperationException("Not supported.");
    }

    @Override
    public boolean isOutboundDone() {
        throw new UnsupportedOperationException("Not supported.");
    }

    @Override
    public String[] getSupportedCipherSuites() {
        throw new UnsupportedOperationException("Not supported.");
    }

    @Override
    public String[] getEnabledCipherSuites() {
        throw new UnsupportedOperationException("Not supported.");
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        throw new UnsupportedOperationException("Not supported.");
    }

    @Override
    public String[] getSupportedProtocols() {
        throw new UnsupportedOperationException("Not supported.");
    }

    @Override
    public String[] getEnabledProtocols() {
        throw new UnsupportedOperationException("Not supported.");
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        throw new UnsupportedOperationException("Not supported.");
    }

    @Override
    public SSLSession getSession() {
        return qtlse.getSession();
    }

    @Override
    public void beginHandshake() throws SSLException {
        throw new UnsupportedOperationException("Not supported.");
    }

    @Override
    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        throw new UnsupportedOperationException("Not supported.");
    }

    @Override
    public void setUseClientMode(boolean mode) {
        throw new UnsupportedOperationException("Not supported.");
    }

    @Override
    public boolean getUseClientMode() {
        throw new UnsupportedOperationException("Not supported.");
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        throw new UnsupportedOperationException("Not supported.");
    }

    @Override
    public boolean getNeedClientAuth() {
        throw new UnsupportedOperationException("Not supported.");
    }

    @Override
    public void setWantClientAuth(boolean want) {
        throw new UnsupportedOperationException("Not supported.");
    }

    @Override
    public boolean getWantClientAuth() {
        throw new UnsupportedOperationException("Not supported.");
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        throw new UnsupportedOperationException("Not supported.");
    }

    @Override
    public boolean getEnableSessionCreation() {
        throw new UnsupportedOperationException("Not supported.");
    }
    
}

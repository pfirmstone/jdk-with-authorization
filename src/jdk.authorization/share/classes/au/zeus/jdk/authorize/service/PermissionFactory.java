/*
 * Copyright (c) 2024, Oracle and/or its affiliates. All rights reserved.
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
package au.zeus.jdk.authorize.service;

import au.zeus.jdk.authorization.spi.GuardServiceFactory;
import java.security.Guard;
import java.security.Permission;
import au.zeus.jdk.authorize.guards.SerialObjectPermission;

/**
 * Permission required to read an object from ObjectInputStream.
 * @author Peter Firmstone.
 */
public final class PermissionFactory implements GuardServiceFactory{
    
    private static final Guard NULL_GUARD = new NullGuard();
    
    public PermissionFactory(){};
    
    public Guard newInstance(String permission, String name, String actions){
        
        return NULL_GUARD;
    }
    
    public Guard newInstance(String permission, String name){
        switch (permission){
            case "au.zeus.jdk.authorization.guards.SerialObjectPermission" : return new SerialObjectPermission(name);
        }
        return NULL_GUARD;
    }
    
    public Guard newInstance(String permission){
//        switch (permission){
//            case "au.zeus.jdk.authorization.guards.LoadClassPermission" : return new LoadClassPermission();
//        }
        return NULL_GUARD;
    }
    
    private static final class NullGuard extends Permission {
        private static final long serialVersionUID = 1L;

        public NullGuard() {
            super("NULL");
        }

        @Override
        public boolean implies(Permission permission) {
            if (permission instanceof NullGuard) return true;
            return false;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj instanceof NullGuard) return true;
            return false;
        }

        @Override
        public int hashCode() {
            return 73;
        }

        @Override
        public String getActions() {
            return "";
        }
        
        @Override
        public void checkGuard(Object o) throws SecurityException {}
        
    }
}
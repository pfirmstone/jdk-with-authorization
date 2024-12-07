/*
 * Copyright (c) 1998, 2022, Oracle and/or its affiliates. All rights reserved.
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
package au.zeus.jdk.authorization.guards;

import java.net.URL;
import java.security.BasicPermission;

/**
 * When a {@link java.lang.SecurityManager} is in force, this {@link java.security.Permission}
 * is required to load classes with {@link java.security.SecureClassLoader}.   This allows
 * an administrator to prevent class loading from unsigned jar files or other
 * untrusted {@link java.net.URL}.  
 * <p>
 * It is advisable to use either signed jar's
 * or a secure hash algorithm with a message digest of the file containing
 * class files.
 * 
 * @author Peter Firmstone.
 */
public class LoadClassPermission extends BasicPermission {
    private static final long serialVersionUID = 1L;
    
    /**
     * Creates a LoadClassPermission, with the name "ALLOW".
     */
    public LoadClassPermission(){
        super("ALLOW");
    }
    
    /**
     * String name is ignored, only "ALLOW".
     */
    public LoadClassPermission(String name){
        super("ALLOW");
    }
    
}

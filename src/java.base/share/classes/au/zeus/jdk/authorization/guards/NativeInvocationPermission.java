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
package au.zeus.jdk.authorization.guards;

import java.security.BasicPermission;

/**
 * NativeInvocationPermission guards invocation of native libraries.
 * 
 * <table class="striped">
 * <caption style="display:none">permission target name,
 *  what the target allows, and associated risks</caption>
 * <thead>
 * <tr>
 * <th scope="col">Permission Target Name</th>
 * <th scope="col">What the Permission Allows</th>
 * <th scope="col">Risks of Allowing this Permission</th>
 * </tr>
 * </thead>
 * <tbody>
 *
 * <tr>
 *   <th scope="row">library name resolved by 
 * jdk.internal.loader.NativeLibraries.findLibraryNameAddress</th>
 *   <td>Allows access to resolved libraries at runtime.</td>
 *   <td>This permission guards native library resolution, for example if
 * trusted code loads a native library, an attacker could otherwise access
 * that library at runtime.
 * </td>
 * 
 * </tbody>
 * </table>
 * 
 * <p>
 * Trusted code must be careful not to delegate native invocation capability
 * to code that is not trusted to do so.
 * 
 */
public class NativeInvocationPermission extends BasicPermission<NativeInvocationPermission> {
    
    /**
     * Creates a new NativeInvocationPermission
     * 
     * @param name the name of the native library. 
     */
    public NativeInvocationPermission(String name){
        super(name);
    }
    
}

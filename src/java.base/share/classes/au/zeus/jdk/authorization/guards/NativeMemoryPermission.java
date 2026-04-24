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
 * Guards access to native memory.
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
 *   <th scope="row">global-arena</th>
 *   <td>Native memory segments from the global arena are visible to any thread.</td>
 *   <td>This is dangerous permission to grant, an attacker could perform a 
 * denial of service by preventing the release and collection of off heap global memory.
 * Off heap memory is not bounded by the JVM heap limit -Xmx
 * Exhausting native memory causes OutOfMemoryError, JVM process termination, 
 * or OS-level failure — all denial-of-service outcomes.
 * </td>
 * 
 * <tr>
 *   <th scope="row">shared-arena</th>
 *   <td>Allows allocation of cross-thread-accessible off heap native memory.</td>
 *   <td>This is dangerous permission to grant, an attacker could perform a 
 * denial of service by allocating arbitrarily large native memory regions.
 * Off heap memory is not bounded by the JVM heap limit -Xmx
 * Exhausting native memory causes OutOfMemoryError, JVM process termination, 
 * or OS-level failure — all denial-of-service outcomes.
 * </td>
 * 
 * <tr>
 *   <th scope="row">confined-arena</th>
 *   <td>Allows per thread allocation of off heap native memory.</td>
 *   <td>This is dangerous permission to grant, an attacker could perform a 
 * denial of service by allocating arbitrarily large native memory regions.
 * Off heap memory is not bounded by the JVM heap limit -Xmx
 * Exhausting native memory causes OutOfMemoryError, JVM process termination, 
 * or OS-level failure — all denial-of-service outcomes.
 * </td>
 * 
 * <tr>
 *   <th scope="row">auto-arena</th>
 *   <td>Allows allocation of garbage collection bounded off heap native memory.</td>
 *   <td>This is dangerous permission to grant, an attacker could perform a 
 * denial of service by allocating arbitrarily large native memory regions.
 * Off heap memory is not bounded by the JVM heap limit -Xmx
 * Exhausting native memory causes OutOfMemoryError, JVM process termination, 
 * or OS-level failure — all denial-of-service outcomes.
 * </td>
 * 
 * <tr>
 *   <th scope="row">native-linker</th>
 *   <td>Permits creating downcall and upcall handles.</td>
 *   <td>This is dangerous permission to grant, obtaining the native linker is 
 * the first step toward creating downcall and upcall handles.
 * </td>
 * 
 * <tr>
 *   <th scope="row">reinterpret-memory-segment</th>
 *   <td>Native memory segments can be reinterpreted and resized.</td>
 *   <td>This is dangerous permission to grant, an attacker could perform a 
 * denial of service by consuming excessive memory.
 * Off heap memory is not bounded by the JVM heap limit -Xmx
 * Exhausting native memory causes OutOfMemoryError, JVM process termination, 
 * or OS-level failure — all denial-of-service outcomes.
 * </td>
 * 
 * <tr>
 *   <th scope="row">address-memory-segment</th>
 *   <td>Creates a native segment with the global scope from a raw long address value.</td>
 *   <td>This is dangerous permission to grant, an attacker could perform a 
 * denial of service by preventing the release and collection of off heap global memory.
 * Off heap memory is not bounded by the JVM heap limit -Xmx
 * Exhausting native memory causes OutOfMemoryError, JVM process termination, 
 * or OS-level failure — all denial-of-service outcomes.
 * </td>
 * 
 * 
 * 
 * </tbody>
 * </table>
 * 
 * <p>
 * Trusted code must be careful not to delegate native invocation capability
 * to code that is not trusted to do so.
 * 
 * 
 * @author peter
 */
public class NativeMemoryPermission extends BasicPermission<NativeMemoryPermission> {
    
    /**
     * Creates a new NativeMemoryPermission
     * @param name either MemorySegment or Arena
     */
    public NativeMemoryPermission(String name){
        super(name);
    }
}

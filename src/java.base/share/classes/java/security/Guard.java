/*
 * Copyright (c) 1997, 2024, Oracle and/or its affiliates. All rights reserved.
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

package java.security;

import java.util.concurrent.Callable;

/**
 * <p> This interface represents a guard, which is an object that is used
 * to protect access to another object.
 *
 * <p>This interface contains a single method, {@code checkGuard},
 * with a single {@code object} argument. {@code checkGuard} is
 * invoked (by the GuardedObject {@code getObject} method)
 * to determine whether to allow access to the object.
 *
 * @see GuardedObject
 *
 * @author Roland Schemers
 * @author Li Gong
 * @author Peter Firmstone
 * @since 1.2
 */

public interface Guard {

    /**
     * Determines whether to allow access to the guarded object
     * {@code object}. Returns silently if access is allowed.
     * Otherwise, throws a {@code SecurityException}.
     * 
     * @param object the object being protected by the guard.
     *
     * @throws    SecurityException if access is denied.
     *
     */
    void checkGuard(Object object) throws SecurityException;
    
    /**
     * When this guard on duty, the condition parameter will be used by the guard
     * to determine if a security check shall be carried out.
     * 
     * Any Exceptions will cause a SecurityException to be thrown, 
     * with the Exception as the cause.
     * 
     * @param condition - the condition used to determine whether this guard will check.
     * 
     * @throws SecurityException if access denied, or if the condition throws an
     * Exception.
     */
    default void checkIf(Callable<Boolean> condition) throws SecurityException{
        @SuppressWarnings("removal")
        SecurityManager sm = System.getSecurityManager();
        try {
            if (sm != null && condition.call()) {
                checkGuard(null);
            }
        } catch (Exception e){
            if (e instanceof SecurityException securityException) throw securityException;
            throw new SecurityException("Exception occured in condition before checking guard: ", e);
        }
    }
    
    /**
     * When this guard on duty, the condition parameter will be used by the guard
     * to determine if a security check shall be carried out, then action1 will be called, 
     * otherwise action2 will be called if this guard is inactive.
     * 
     * Any Exceptions will cause a SecurityException to be thrown, 
     * with the Exception as the cause.
     * 
     * @param <V> the result of the action performed.
     * @param condition the condition used to determine whether this guard will 
     * perform a security check.
     * @param action1 the action to perform, or null, when this guard is on duty.
     * @param action2 the action to perform, or null, when this guard is inactive.
     * @return the result of the action, or null.
     * 
     * @throws SecurityException if access is denied, the condition throws an
     * Exception, or the action throws an exception.
     */
    default <V> V conditionActionElse(Callable<Boolean> condition, Callable<V> action1, Callable<V> action2){
        @SuppressWarnings("removal")
        SecurityManager sm = System.getSecurityManager();
        try {
            if (sm != null ){
                if (condition.call()) checkGuard(null);
                return action1 != null ? action1.call(): null;
            } else {
                return action2 != null ? action2.call(): null;
            }
        } catch (Exception e) {
            if (e instanceof SecurityException securityException) throw securityException;
            throw new SecurityException("Action threw an exception after guard check passed: ", e);
        }
    }
    
}

/*
 * Copyright (c) 2006, 2024, Oracle and/or its affiliates. All rights reserved.
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

package java.io;

import au.zeus.jdk.authorization.spi.GuardServiceFactory;
import java.security.Guard;
import java.util.Iterator;
import java.util.ServiceLoader;

/**
 * Context during upcalls from object stream to class-defined
 * readObject/writeObject methods.
 * Holds object currently being deserialized and descriptor for current class.
 * <p>
 * This context keeps track of the thread it was constructed on, and allows
 * only a single call of defaultReadObject, readFields, defaultWriteObject
 * or writeFields which must be invoked on the same thread before the class's
 * readObject/writeObject method has returned.
 * If not set to the current thread, the getObj method throws NotActiveException.
 */
final class SerialCallbackContext {
    private static final GuardServiceFactory FACTORY;
    
    static {
        GuardServiceFactory factory = null;
        ServiceLoader<GuardServiceFactory> guards = ServiceLoader.load(GuardServiceFactory.class);
        Iterator<GuardServiceFactory> it = guards.iterator();
        while (it.hasNext()){
            factory = it.next();
            if (factory != null) break;
        } 
        FACTORY = factory;
    }
    
    private final Object obj;
    private final ObjectStreamClass desc;
    /**
     * Thread this context is in use by.
     * As this only works in one thread, we do not need to worry about thread-safety.
     */
    private Thread thread;
    
    private static boolean check(Guard guard) throws SecurityException {
        guard.checkGuard(null);
        return true;
    }
    
    private static Guard getGuard(String className){
        return FACTORY.newInstance(
            "au.zeus.jdk.authorization.guards.SerialObjectPermission",
            className
        );
    }

    SerialCallbackContext(Object obj, ObjectStreamClass desc) {
        this(obj, desc, check(getGuard(desc.getName())), Thread.currentThread());
    }
    
    SerialCallbackContext(Object obj, ObjectStreamClass desc, boolean check, Thread thread){
        this.obj = obj;
        this.desc = desc;
        this.thread = thread;
    }

    Object getObj() throws NotActiveException {
        checkAndSetUsed();
        return obj;
    }

    ObjectStreamClass getDesc() {
        return desc;
    }

    void check() throws NotActiveException {
        if (thread != null && thread != Thread.currentThread()) {
            throw new NotActiveException(
                "expected thread: " + thread + ", but got: " + Thread.currentThread());
        }
    }

    void checkAndSetUsed() throws NotActiveException {
        if (thread != Thread.currentThread()) {
             throw new NotActiveException(
              "not in readObject invocation or fields already read");
        }
        thread = null;
    }

    void setUsed() {
        thread = null;
    }
}

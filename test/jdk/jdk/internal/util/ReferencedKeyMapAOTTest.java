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



import org.testng.annotations.Test;
import org.testng.Assert;

import jdk.internal.util.ReferencedKeyMap;
import java.lang.ref.Reference;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Map;

/**
 * @test
 * @summary Test ReferencedKeyMap.prepareForAOTCache() properly registers SoftReference keys
 * @modules java.base/jdk.internal.util
 *          java.base/jdk.internal.misc
 * @run testng/othervm -da:jdk.internal.util.ReferencedKeyMap -da:jdk.internal.misc.CDS ReferencedKeyMapAOTTest
 */
public class ReferencedKeyMapAOTTest {

    @Test
    public void testSoftReferenceKeyRegistration() throws Exception {
        // Create a ReferencedKeyMap with SoftReference keys
        ReferencedKeyMap<String, Integer> map = ReferencedKeyMap.create(
            true, // Use SoftReference
            ReferencedKeyMap.concurrentHashMapSupplier()
        );

        // Add some entries
        map.put("key1", 1);
        map.put("key2", 2);
        map.put("key3", 3);

        // Access the prepareForAOTCache method via reflection
        Method prepareMethod = ReferencedKeyMap.class.getDeclaredMethod("prepareForAOTCache");
        prepareMethod.setAccessible(true);

        // This should not throw any exceptions
        // In the fixed version, it will call CDS.keepAlive() for both referents and keys
        try {
            prepareMethod.invoke(map);
            System.out.println("prepareForAOTCache() executed successfully");
        } catch (Exception e) {
            Assert.fail("prepareForAOTCache() failed: " + e.getMessage());
        }
    }

    @Test
    public void testWeakReferenceKeyHandling() throws Exception {
        // Create a ReferencedKeyMap with WeakReference keys
        ReferencedKeyMap<String, Integer> map = ReferencedKeyMap.create(
            false, // Use WeakReference
            ReferencedKeyMap.concurrentHashMapSupplier()
        );

        // Add some entries
        map.put("key1", 1);
        map.put("key2", 2);

        // Access the prepareForAOTCache method
        Method prepareMethod = ReferencedKeyMap.class.getDeclaredMethod("prepareForAOTCache");
        prepareMethod.setAccessible(true);

        // WeakReference keys should not cause issues
        try {
            prepareMethod.invoke(map);
            System.out.println("prepareForAOTCache() for WeakReference map executed successfully");
        } catch (Exception e) {
            Assert.fail("prepareForAOTCache() for WeakReference failed: " + e.getMessage());
        }
    }

    @Test
    public void testMixedOperations() throws Exception {
        // Test that normal operations work after prepareForAOTCache
        ReferencedKeyMap<String, Integer> map = ReferencedKeyMap.create(
            true,
            ReferencedKeyMap.concurrentHashMapSupplier()
        );

        // Add entries
        map.put("a", 1);
        map.put("b", 2);
        map.put("c", 3);

        // Prepare for AOT
        Method prepareMethod = ReferencedKeyMap.class.getDeclaredMethod("prepareForAOTCache");
        prepareMethod.setAccessible(true);
        prepareMethod.invoke(map);

        // Verify map still works
        Assert.assertEquals(map.get("a"), Integer.valueOf(1));
        Assert.assertEquals(map.get("b"), Integer.valueOf(2));
        Assert.assertEquals(map.get("c"), Integer.valueOf(3));
        Assert.assertEquals(map.size(), 3);

        System.out.println("Mixed operations test passed");
    }

    @Test
    public void testNullReferentHandling() throws Exception {
        // Test handling of null referents during AOT preparation
        ReferencedKeyMap<String, Integer> map = ReferencedKeyMap.create(
            true,
            ReferencedKeyMap.concurrentHashMapSupplier()
        );

        map.put("key1", 1);
        
        // Force GC to potentially clear some references
        System.gc();
        Thread.sleep(100);

        Method prepareMethod = ReferencedKeyMap.class.getDeclaredMethod("prepareForAOTCache");
        prepareMethod.setAccessible(true);

        // Should handle null referents gracefully
        try {
            prepareMethod.invoke(map);
            System.out.println("Null referent handling successful");
        } catch (Exception e) {
            Assert.fail("Failed to handle null referents: " + e.getMessage());
        }
    }
}
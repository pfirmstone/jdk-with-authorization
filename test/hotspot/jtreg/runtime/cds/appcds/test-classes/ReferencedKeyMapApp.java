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

import java.lang.invoke.MethodType;

/**
 * Test application for verifying ReferencedKeyMap behavior with AOT archiving.
 * This class exercises MethodType interning which uses ReferencedKeyMap internally.
 */
public class ReferencedKeyMapApp {
    public static void main(String[] args) throws Exception {
        if (args.length > 0) {
            switch (args[0]) {
                case "verify":
                    verifyMethodTypeInterning();
                    break;
                case "access-test":
                    testMethodTypeAccess();
                    break;
                default:
                    runStandardTest();
            }
        } else {
            runStandardTest();
        }
    }

    private static void runStandardTest() {
        System.out.println("Running standard ReferencedKeyMap test...");
        
        // Create various MethodTypes to populate the intern table
        // This exercises the ReferencedKeyMap with SoftReference keys
        MethodType mt1 = MethodType.methodType(void.class);
        MethodType mt2 = MethodType.methodType(int.class, String.class);
        MethodType mt3 = MethodType.methodType(Object.class, Object.class, Object.class);
        MethodType mt4 = MethodType.methodType(String.class, int.class, boolean.class);
        MethodType mt5 = MethodType.methodType(long.class, double.class);

        // Create duplicates to test interning
        MethodType mt1_dup = MethodType.methodType(void.class);
        MethodType mt2_dup = MethodType.methodType(int.class, String.class);

        // Verify interning works
        if (mt1 != mt1_dup || mt2 != mt2_dup) {
            throw new RuntimeException("MethodType interning failed!");
        }

        // Force some MethodTypeForm creation
        mt1.returnType();
        mt2.parameterArray();
        mt3.toMethodDescriptorString();
        mt4.wrap();
        mt5.unwrap();

        System.out.println("Standard test completed successfully");
    }

    private static void verifyMethodTypeInterning() {
        System.out.println("Verifying MethodType interning with AOT archive...");

        // Create several MethodTypes
        MethodType[] types = new MethodType[10];
        for (int i = 0; i < types.length; i++) {
            switch (i % 5) {
                case 0:
                    types[i] = MethodType.methodType(void.class);
                    break;
                case 1:
                    types[i] = MethodType.methodType(int.class, String.class);
                    break;
                case 2:
                    types[i] = MethodType.methodType(Object.class, Object.class);
                    break;
                case 3:
                    types[i] = MethodType.methodType(String.class, int.class);
                    break;
                case 4:
                    types[i] = MethodType.methodType(long.class, double.class, float.class);
                    break;
            }
        }

        // Verify interning: identical types should be the same object
        if (types[0] != types[5]) {
            throw new RuntimeException("MethodType(void) not interned correctly");
        }
        if (types[1] != types[6]) {
            throw new RuntimeException("MethodType(int, String) not interned correctly");
        }

        System.out.println("MethodType interning works correctly");
    }

    private static void testMethodTypeAccess() {
        System.out.println("Testing MethodType access with AOT archive...");

        try {
            // Access various MethodType methods that use LazyConstant
            MethodType mt = MethodType.methodType(Object.class, String.class, int.class);
            
            // These operations may trigger LazyConstant computation
            Class<?>[] params = mt.parameterArray();
            String descriptor = mt.toMethodDescriptorString();
            MethodType generic = mt.generic();
            MethodType wrapped = mt.wrap();
            
            // Verify results are correct
            if (params.length != 2) {
                throw new RuntimeException("Wrong parameter count: " + params.length);
            }
            if (!descriptor.equals("(Ljava/lang/String;I)Ljava/lang/Object;")) {
                throw new RuntimeException("Wrong descriptor: " + descriptor);
            }

            // Test interning
            MethodType mt2 = MethodType.methodType(Object.class, String.class, int.class);
            if (mt != mt2) {
                throw new RuntimeException("Interning failed after AOT load");
            }

            System.out.println("MethodType access successful");
            System.out.println("Interned MethodTypes are identical");

        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("MethodType access test failed", e);
        }
    }
}
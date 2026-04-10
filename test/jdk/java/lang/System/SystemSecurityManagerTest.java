/*
 * Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import java.lang.reflect.Method;
import java.security.Permission;
import static org.junit.jupiter.api.Assertions.*;

/*
 * @test
 * 
 * @summary Test suite for System.setSecurityManager() security hardening.  
 * These tests validate the null-prevention and reflection-bypass protections
 * added to System.setSecurityManager().
 * @library /test/lib
 * @run junit/othervm SystemSecurityManagerTest
 */
public class SystemSecurityManagerTest {

    private static class TestSecurityManager extends SecurityManager {
        
        volatile boolean permissive = true;
        
        @Override
        public void checkPermission(Permission perm) {
            if (!permissive && "setSecurityManager".equals(perm.getName())) {
                throw new SecurityException("setSecurityManager denied");
            }
        }
    }

    @BeforeEach
    public void cleanup() {
        SecurityManager sm = System.getSecurityManager();
        if (sm instanceof TestSecurityManager tm) tm.permissive = true;
        
        // Note: Cannot easily reset SecurityManager without it being set
        // This test assumes running in isolated JVM or test environment
    }

    /**
     * TEST: Null SecurityManager rejection at entry point
     */
    @Test
    @DisplayName("Reject null SecurityManager with IllegalArgumentException")
    public void testNullSecurityManagerRejected() {
        Exception exception = assertThrows(
            IllegalArgumentException.class,
            () -> System.setSecurityManager(null),
            "setSecurityManager(null) should throw IllegalArgumentException"
        );

        assertTrue(exception.getMessage().contains("null"),
            "Exception message should mention null: " + exception.getMessage());
    }

    /**
     * TEST: Direct call succeeds with valid SecurityManager
     */
    @Test
    @DisplayName("Accept valid SecurityManager from direct call")
    public void testDirectCallAccepted() {
        if (System.getSecurityManager() == null) {
            System.setSecurityManager(new TestSecurityManager());
        }

        TestSecurityManager testSM = new TestSecurityManager();

        // This should succeed (no exception)
        assertDoesNotThrow(
            () -> System.setSecurityManager(testSM),
            "Direct call with valid SecurityManager should succeed"
        );

        assertEquals(testSM, System.getSecurityManager(),
            "SecurityManager should be installed");
    }

    /**
     * TEST: Reflection-based bypass prevention
     */
    @Test
    @DisplayName("Prevent reflection-based setSecurityManager calls")
    public void testReflectionBypassPrevented() {
        if (System.getSecurityManager() == null) {
            System.setSecurityManager(new TestSecurityManager());
        }

        TestSecurityManager testSM = new TestSecurityManager();

        Exception exception = assertThrows(
            RuntimeException.class,
            () -> {
                try {
                    Method method = System.class.getDeclaredMethod(
                        "setSecurityManager", 
                        SecurityManager.class
                    );
                    method.setAccessible(true);
                    method.invoke(null, testSM);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            },
            "Reflection-based setSecurityManager should throw SecurityException"
        );

        assertTrue(exception.getMessage().contains("reflect"),
            "Exception should mention reflect: " + exception.getMessage());
    }



    /**
     * TEST: Null after valid installation is prevented
     */
    @Test
    @DisplayName("Cannot set SecurityManager to null after installation")
    public void testNullAfterInstallationPrevented() {
        if (System.getSecurityManager() == null) {
            System.setSecurityManager(new TestSecurityManager());
        }

        assertThrows(
            IllegalArgumentException.class,
            () -> System.setSecurityManager(null),
            "Cannot set null after SecurityManager installation"
        );
    }

    /**
     * TEST: Thread safety - concurrent setSecurityManager calls
     */
    @Test
    @DisplayName("Thread-safe setSecurityManager under concurrency")
    public void testThreadSafety() throws InterruptedException {
        if (System.getSecurityManager() == null) {
            System.setSecurityManager(new TestSecurityManager());
        }

        TestSecurityManager testSM1 = new TestSecurityManager();
        TestSecurityManager testSM2 = new TestSecurityManager();

        Thread t1 = new Thread(() -> {
            try {
                System.setSecurityManager(testSM1);
            } catch (IllegalStateException | SecurityException e) {
                // Expected - only one can succeed
            }
        });

        Thread t2 = new Thread(() -> {
            try {
                System.setSecurityManager(testSM2);
            } catch (IllegalStateException | SecurityException e) {
                // Expected - only one can succeed
            }
        });

        t1.start();
        t2.start();
        t1.join();
        t2.join();

        SecurityManager installed = System.getSecurityManager();
        assertNotNull(installed, "A SecurityManager should be installed");
        assertTrue(
            installed == testSM1 || installed == testSM2,
            "Installed SecurityManager should be one of the attempted values"
        );
    }

    /**
     * TEST: Error messages are informative
     */
    @Test
    @DisplayName("Provide clear error messages for security violations")
    public void testClearErrorMessages() {
        if (System.getSecurityManager() == null) {
            System.setSecurityManager(new TestSecurityManager());
        }

        // Test null rejection message
        IllegalArgumentException nullException = assertThrows(
            IllegalArgumentException.class,
            () -> System.setSecurityManager(null)
        );
        assertNotNull(nullException.getMessage());
        assertTrue(
            nullException.getMessage().length() > 0,
            "Exception should have descriptive message"
        );
    }
    
    /**
     * TEST: Replacement blocked by existing SecurityManager
     */
    @Test
    @DisplayName("Existing SecurityManager blocks replacement without permission")
    public void testReplacementBlockedWithoutPermission() {
        if (System.getSecurityManager() == null) {
            System.setSecurityManager(new TestSecurityManager());
        }

        // Install restrictive SecurityManager
        TestSecurityManager restrictiveSM = new TestSecurityManager();
        restrictiveSM.permissive = false;
        System.setSecurityManager(restrictiveSM);

        try {
            TestSecurityManager testSM = new TestSecurityManager();

            // This should fail because RestrictiveSecurityManager denies setSecurityManager
            assertThrows(
                SecurityException.class,
                () -> System.setSecurityManager(testSM),
                "setSecurityManager should be denied by existing SecurityManager"
            );
        } finally {
            // Cannot reset SecurityManager in standard Java
        }
    }
}
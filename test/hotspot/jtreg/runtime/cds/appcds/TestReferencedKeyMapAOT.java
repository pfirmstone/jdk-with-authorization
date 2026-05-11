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

/**
 * @test
 * @summary Test that ReferencedKeyMap with SoftReference keys works correctly with AOT archiving
 * @requires vm.cds
 * @requires vm.cds.write.archived.java.heap
 * @library /test/lib /test/hotspot/jtreg/runtime/cds/appcds
 * @compile test-classes/ReferencedKeyMapApp.java
 * @run driver jdk.test.lib.helpers.ClassFileInstaller -jar ReferencedKeyMapApp.jar ReferencedKeyMapApp
 * @run driver TestReferencedKeyMapAOT
 */

import jdk.test.lib.cds.CDSOptions;
import jdk.test.lib.cds.CDSTestUtils;
import jdk.test.lib.process.OutputAnalyzer;

public class TestReferencedKeyMapAOT {
    private static final String APP_CLASS = "ReferencedKeyMapApp";
    private static final String APP_JAR   = "ReferencedKeyMapApp.jar";

    public static void main(String[] args) throws Exception {
        testBasicAOTArchiving();
        testNoReferenceObjectErrors();
        testDynamicArchive();
    }

    // Test 1: Create a static CDS archive (bootstrap dump, no app class needed).
    // Verifies that the dump completes without reference-object errors.
    private static void testBasicAOTArchiving() throws Exception {
        System.out.println("\n=== Test 1: Basic AOT Archiving ===");

        // createArchiveAndCheck only accepts VM-flag prefixes; it adds
        // -Xshare:dump internally.  Do NOT pass an app class name here.
        OutputAnalyzer output = CDSTestUtils.createArchiveAndCheck(
            "-Xlog:cds");

        output.shouldNotContain("Cannot archive reference object");
        output.shouldNotContain("referent is not registered with CDS.keepAlive()");
    }

    // Test 2: Dump with more verbose logging and confirm no SoftReference errors.
    private static void testNoReferenceObjectErrors() throws Exception {
        System.out.println("\n=== Test 2: No Reference Object Errors ===");

        OutputAnalyzer output = CDSTestUtils.createArchiveAndCheck(
            "-Xlog:cds=debug",
            "-Xlog:cds+class=debug");

        output.shouldNotContain("Cannot archive reference object");
        output.shouldNotContain("referent is not registered with CDS.keepAlive()");
        output.shouldNotMatch(".*SoftReference.*not.*registered.*");
    }

    // Test 3: Run ReferencedKeyMapApp with a dynamic archive so that the app's
    // classes (including ReferencedKeyMap internals) are exercised during dump.
    private static void testDynamicArchive() throws Exception {
        System.out.println("\n=== Test 3: Dynamic Archive with App Classes ===");

        String baseArchive    = "base.jsa";
        String dynamicArchive = "dynamic.jsa";

        // Step 1: create a bootstrap base archive.
        CDSTestUtils.createArchiveAndCheck(
            "-Xlog:cds",
            "-XX:SharedArchiveFile=" + baseArchive);

        // Step 2: run the app with ArchiveClassesAtExit to produce a dynamic
        // archive layered on top of the base archive.
        CDSTestUtils.run(
            APP_CLASS,
            "-Xlog:cds",
            "-XX:SharedArchiveFile=" + baseArchive,
            "-XX:ArchiveClassesAtExit=" + dynamicArchive,
            "-cp", APP_JAR)
          .assertNormalExit(out -> {
              out.shouldNotContain("Cannot archive reference object");
              out.shouldNotContain("referent is not registered with CDS.keepAlive()");
          });

        // Step 3: run again using the dynamic archive to verify correctness.
        CDSTestUtils.runWithArchive(
            "-XX:SharedArchiveFile=" + dynamicArchive,
            "-cp", APP_JAR,
            APP_CLASS)
          .shouldHaveExitValue(0)
          .shouldContain("Standard test completed successfully");
    }
}
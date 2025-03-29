/*
 * Copyright (c) 2015, 2025, Oracle and/or its affiliates. All rights reserved.
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
 *
 */

import jdk.test.lib.cds.CDSJarUtils;

    public static String build(String jarName, String ...classNames)
        throws Exception {

        return createSimpleJar(classDir, getJarFilePath(jarName), classNames);
    }

    public static String build(boolean classesInWorkDir, String jarName, String ...classNames)
        throws Exception {
        if (classesInWorkDir) {
            return createSimpleJar(".", getJarFilePath(jarName), classNames);
        } else {
            return build(jarName, classNames);
        }
    }


    public static String buildWithManifest(String jarName, String manifest,
        String jarClassesDir, String ...classNames) throws Exception {
        String jarPath = getJarFilePath(jarName);
        ArrayList<String> args = new ArrayList<String>();
        args.add("cvfm");
        args.add(jarPath);
        args.add(System.getProperty("test.src") + File.separator + "test-classes"
            + File.separator + manifest);
        addClassArgs(args, jarClassesDir, classNames);
        createJar(args);

        return jarPath;
    }


    // Execute: jar uvf $jarFile -C $dir .
    static void update(String jarFile, String dir) throws Exception {
        String jarExe = JDKToolFinder.getJDKTool("jar");

        ArrayList<String> args = new ArrayList<>();
        args.add(jarExe);
        args.add("uvf");
        args.add(jarFile);
        args.add("-C");
        args.add(dir);
        args.add(".");

        executeProcess(args.toArray(new String[1]));
    }

    // Add commonly used inner classes that are often omitted by mistake. Currently
    // we support only jdk/test/whitebox/WhiteBox$WhiteBoxPermission.
    // See JDK-8199290
    private static String[] addInnerClasses(String[] classes, int startIdx) {
        boolean seenNewWb = false;
        boolean seenNewWbInner = false;
        // This method is different than ClassFileInstaller.addInnerClasses which
        // uses "." as the package delimiter :-(
        final String newWb = "jdk/test/whitebox/WhiteBox";
        final String newWbInner = newWb + "$WhiteBoxPermission";

        ArrayList<String> list = new ArrayList<>();

        for (int i = startIdx; i < classes.length; i++) {
            String cls = classes[i];
            list.add(cls);
            switch (cls) {
            case newWb:      seenNewWb      = true; break;
            case newWbInner: seenNewWbInner = true; break;
            }
        }
        if (seenNewWb && !seenNewWbInner) {
            list.add(newWbInner);
        }
        String[] array = new String[list.size()];
        list.toArray(array);
        return array;
    }


    private static String createSimpleJar(String jarclassDir, String jarName,
        String[] classNames) throws Exception {

        ArrayList<String> args = new ArrayList<String>();
        args.add("cf");
        args.add(jarName);
        addClassArgs(args, jarclassDir, classNames);
        createJar(args);

        return jarName;
    }

    private static void addClassArgs(ArrayList<String> args, String jarclassDir,
        String[] classNames) {

        classNames = addInnerClasses(classNames, 0);

        for (String name : classNames) {
            args.add("-C");
            args.add(jarclassDir);
            args.add(name + ".class");
        }
    }

/*
 * This class is deprecated and should not be used by any new test cases. Use CDSJarUtils
 * and jdk.test.lib.cds.CDSModulePackager instead.
 */
public class JarBuilder extends CDSJarUtils {
    public static void createModularJar(String jarPath,
                                        String classesDir,
                                        String mainClass) throws Exception {
        createModularJarWithManifest(jarPath, classesDir, mainClass, null);
    }

    public static void createModularJarWithManifest(String jarPath,
                                                    String classesDir,
                                                    String mainClass,
                                                    String manifest) throws Exception {
        CDSJarUtils.buildFromDirectory(jarPath, classesDir,
                                       JarOptions.of()
                                           .setMainClass(mainClass)
                                           .setManifest(manifest));
    }
}

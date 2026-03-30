/*
<<<<<<<< HEAD:test/jdk/com/sun/net/httpserver/simpleserver/SecurityManagerTest.java
 * Copyright (c) 2021, Oracle and/or its affiliates. All rights reserved.
========
 * Copyright (c) 2021, 2025, Oracle and/or its affiliates. All rights reserved.
>>>>>>>> b685ea54081fcf54a6567dddb49b63435a6e1ea4:test/jdk/com/sun/net/httpserver/simpleserver/DocRootDirPermissionsTest.java
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

/*
 * @test
<<<<<<<< HEAD:test/jdk/com/sun/net/httpserver/simpleserver/SecurityManagerTest.java
 * @summary Tests for FileServerHandler with SecurityManager
 * @library /test/lib
 * @build jdk.test.lib.net.URIBuilder
 * @run main/othervm/java.security.policy=SecurityManagerTestRead.policy -ea SecurityManagerTest true
 * @run main/othervm/java.security.policy=SecurityManagerTestNoRead.policy -ea SecurityManagerTest false
 * @run main/othervm -ea SecurityManagerTest true
========
 * @summary Tests file permission checks during the creation of a `FileServerHandler`
 * @requires (os.family != "windows")
 * @library /test/lib
 * @build jdk.test.lib.net.URIBuilder
 * @run main/othervm -ea DocRootDirPermissionsTest true
 * @run main/othervm -ea DocRootDirPermissionsTest false
>>>>>>>> b685ea54081fcf54a6567dddb49b63435a6e1ea4:test/jdk/com/sun/net/httpserver/simpleserver/DocRootDirPermissionsTest.java
 */

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AccessControlException;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.SimpleFileServer;
import com.sun.net.httpserver.SimpleFileServer.OutputLevel;
import jdk.test.lib.net.URIBuilder;
import jdk.test.lib.util.FileUtils;
import static java.net.http.HttpClient.Builder.NO_PROXY;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.StandardOpenOption.CREATE;

/**
 * Tests the permission checks during the creation of a FileServerHandler.
 *
 * A FileServerHandler can only be created if a "read" FilePermission is
 * granted for the root directory passed. The test consists of 3 runs:
 *     1) security manager enabled and "read" FilePermission granted
 *     2) security manager enabled and "read" FilePermission NOT granted
 *     3) security manager NOT enabled
 * 2) misses the required permissions to call many of the java.nio.file methods,
 * the test works around this by reusing the test directory created in the
 * previous run.
* */
<<<<<<<< HEAD:test/jdk/com/sun/net/httpserver/simpleserver/SecurityManagerTest.java
public class SecurityManagerTest {

    static final Path CWD = Path.of(".").toAbsolutePath().normalize();
    static final Path TEST_DIR = CWD.resolve("SecurityManagerTest");
    static final InetSocketAddress LOOPBACK_ADDR =
========
public class DocRootDirPermissionsTest {

    private static final Path CWD = Path.of(".").toAbsolutePath().normalize();
    private static final Path TEST_DIR = CWD.resolve("RootDir");
    private static final InetSocketAddress LOOPBACK_ADDR =
>>>>>>>> b685ea54081fcf54a6567dddb49b63435a6e1ea4:test/jdk/com/sun/net/httpserver/simpleserver/DocRootDirPermissionsTest.java
            new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);

    private static final boolean ENABLE_LOGGING = true;
    private static final Logger LOGGER = Logger.getLogger("com.sun.net.httpserver");

    private static boolean readPermitted;
    private static String lastModifiedDir;
    private static String lastModifiedFile;

<<<<<<<< HEAD:test/jdk/com/sun/net/httpserver/simpleserver/SecurityManagerTest.java
========
    private static Set<PosixFilePermission> posixPermissions;
    private static List<AclEntry> acls;

>>>>>>>> b685ea54081fcf54a6567dddb49b63435a6e1ea4:test/jdk/com/sun/net/httpserver/simpleserver/DocRootDirPermissionsTest.java
    public static void main(String[] args) throws Exception {
        new DocRootDirPermissionsTest().run(args);
    }

    protected void run(String[] args) throws Exception{
        setupLogging();
        readPermitted = Boolean.parseBoolean(args[0]);
        if (readPermitted) {
            createTestDir();
            testDirectoryGET();
            testFileGET();
<<<<<<<< HEAD:test/jdk/com/sun/net/httpserver/simpleserver/SecurityManagerTest.java
        } else {  // no FilePermission "read" for TEST_DIR granted,
                  // assert handler cannot be created
            testCreateHandler();
========
        } else {
            revokePermissions();
            try {
                testCreateHandler();
            } finally {
                restorePermissions();
            }
        }
    }

    private void revokePermissions() throws IOException {
        if (!Files.isReadable(TEST_DIR)) {
            // good nothing to do:
            System.out.println("File is already not readable: nothing to do");
            return;
        }
        System.out.println("FileSystem: " + Files.getFileStore(TEST_DIR).type());
        if (Files.getFileStore(TEST_DIR).supportsFileAttributeView("posix")) {
            System.out.println("Revoking owner's read access in POSIX permissions for " + TEST_DIR);
            posixPermissions = Files.getPosixFilePermissions(TEST_DIR);
            Set<PosixFilePermission> newPerms = new HashSet<>(posixPermissions);
            newPerms.remove(PosixFilePermission.OWNER_READ);
            newPerms.remove(PosixFilePermission.OWNER_EXECUTE);
            Files.setPosixFilePermissions(TEST_DIR, newPerms);
        } else if (Files.getFileStore(TEST_DIR).supportsFileAttributeView("acl")) {
            System.out.println("Revoking owner's read access in ACLs for " + TEST_DIR);
            AclFileAttributeView view = Files.getFileAttributeView(TEST_DIR, AclFileAttributeView.class);
            acls = view.getAcl();
            List<AclEntry> entries = new ArrayList<>();
            UserPrincipal owner = view.getOwner();
            // Deny owner
            entries.add(AclEntry.newBuilder().setType(AclEntryType.DENY)
                    .setPrincipal(owner).setPermissions(AclEntryPermission.READ_DATA,
                            AclEntryPermission.READ_ATTRIBUTES, AclEntryPermission.READ_NAMED_ATTRS,
                            AclEntryPermission.EXECUTE)
                    .build());
            // Revoke read data and execute
            for (AclEntry entry : acls) {
                Set<AclEntryPermission> perms =
                        new HashSet<>(entry.permissions());
                if (entry.type() == AclEntryType.ALLOW) {
                    System.out.println("Revoking read access: " + entry);
                    perms.remove(AclEntryPermission.READ_DATA);
                    perms.remove(AclEntryPermission.LIST_DIRECTORY);
                    perms.remove(AclEntryPermission.READ_ATTRIBUTES);
                    perms.remove(AclEntryPermission.READ_NAMED_ATTRS);
                    perms.remove(AclEntryPermission.EXECUTE);
                    entries.add(AclEntry.newBuilder(entry).setPermissions(perms).build());
                }
            }
            view.setAcl(entries);
            System.out.println("ACLs: " + view.getAcl());
            try {
                System.out.println("File is readable: " + Files.isReadable(TEST_DIR));
                Thread.sleep(50);
            } catch (InterruptedException x) {}
            // The above does not always work, skip the test if we can't make TEST_DIR
            // read-only.
            if (Files.isReadable(TEST_DIR)) {
                throw new jtreg.SkippedException("Can't make directory read-only");
            }
        } else {
            throw new RuntimeException("Required attribute view not supported");
        }
        System.out.println("File is readable: " + Files.isReadable(TEST_DIR));
    }

    private void restorePermissions() throws IOException {
        if (Files.getFileStore(TEST_DIR).supportsFileAttributeView("posix")) {
            if (posixPermissions != null) {
                System.out.println("Restoring original POSIX permissions");
                Files.setPosixFilePermissions(TEST_DIR, posixPermissions);
            }
        } else if (Files.getFileStore(TEST_DIR).supportsFileAttributeView("acl")) {
            if (acls != null) {
                System.out.println("Restoring original ACLs");
                AclFileAttributeView view = Files.getFileAttributeView(TEST_DIR, AclFileAttributeView.class);
                view.setAcl(acls);
            }
        } else {
            throw new RuntimeException("Required attribute view not supported");
>>>>>>>> b685ea54081fcf54a6567dddb49b63435a6e1ea4:test/jdk/com/sun/net/httpserver/simpleserver/DocRootDirPermissionsTest.java
        }
    }

    private void setupLogging() {
        if (ENABLE_LOGGING) {
            ConsoleHandler ch = new ConsoleHandler();
            LOGGER.setLevel(Level.ALL);
            ch.setLevel(Level.ALL);
            LOGGER.addHandler(ch);
        }
    }

    private void createTestDir() throws IOException {
        if (Files.exists(TEST_DIR)) {
            FileUtils.deleteFileTreeWithRetry(TEST_DIR);
        }
        Files.createDirectories(TEST_DIR);
        var file = Files.writeString(TEST_DIR.resolve("aFile.txt"), "some text", CREATE);
        lastModifiedDir = getLastModified(TEST_DIR);
        lastModifiedFile = getLastModified(file);
    }

    private void testDirectoryGET() throws Exception {
        var expectedBody = openHTML + """
                <h1>Directory listing for &#x2F;</h1>
                <ul>
                <li><a href="aFile.txt">aFile.txt</a></li>
                </ul>
                """ + closeHTML;
        var expectedLength = Integer.toString(expectedBody.getBytes(UTF_8).length);
        var server = SimpleFileServer.createFileServer(LOOPBACK_ADDR, TEST_DIR, OutputLevel.VERBOSE);

        server.start();
        try {
            var client = HttpClient.newBuilder().proxy(NO_PROXY).build();
            var request = HttpRequest.newBuilder(uri(server, "")).build();
            var response = client.send(request, BodyHandlers.ofString());
            assert response.statusCode() == 200;
            assert response.body().equals(expectedBody);
            assert response.headers().firstValue("content-type").get().equals("text/html; charset=UTF-8");
            assert response.headers().firstValue("content-length").get().equals(expectedLength);
            assert response.headers().firstValue("last-modified").get().equals(lastModifiedDir);
        } finally {
            server.stop(0);
        }
    }

    private void testFileGET() throws Exception {
        var expectedBody = "some text";
        var expectedLength = Integer.toString(expectedBody.getBytes(UTF_8).length);
        var server = SimpleFileServer.createFileServer(LOOPBACK_ADDR, TEST_DIR, OutputLevel.VERBOSE);

        server.start();
        try {
            var client = HttpClient.newBuilder().proxy(NO_PROXY).build();
            var request = HttpRequest.newBuilder(uri(server, "aFile.txt")).build();
            var response = client.send(request, BodyHandlers.ofString());
            assert response.statusCode() == 200;
            assert response.body().equals("some text");
            assert response.headers().firstValue("content-type").get().equals("text/plain");
            assert response.headers().firstValue("content-length").get().equals(expectedLength);
            assert response.headers().firstValue("last-modified").get().equals(lastModifiedFile);
        } finally {
            server.stop(0);
        }
    }

<<<<<<<< HEAD:test/jdk/com/sun/net/httpserver/simpleserver/SecurityManagerTest.java
    @SuppressWarnings("removal")
    private static void testCreateHandler(){
========
    private void testCreateHandler(){
>>>>>>>> b685ea54081fcf54a6567dddb49b63435a6e1ea4:test/jdk/com/sun/net/httpserver/simpleserver/DocRootDirPermissionsTest.java
        try {
            SimpleFileServer.createFileServer(LOOPBACK_ADDR, TEST_DIR, OutputLevel.NONE);
            throw new RuntimeException("Handler creation expected to fail");
        } catch (AccessControlException expected) { }

        try {
            SimpleFileServer.createFileHandler(TEST_DIR);
            throw new RuntimeException("Handler creation expected to fail");
        } catch (AccessControlException expected) { }
    }

    private static final String openHTML = """
                <!DOCTYPE html>
                <html>
                <head>
                <meta charset="utf-8"/>
                </head>
                <body>
                """;

    private static final String closeHTML = """
                </body>
                </html>
                """;

    private URI uri(HttpServer server, String path) {
        return URIBuilder.newBuilder()
                .host("localhost")
                .port(server.getAddress().getPort())
                .scheme("http")
                .path("/" + path)
                .buildUnchecked();
    }

    private String getLastModified(Path path) throws IOException {
        return Files.getLastModifiedTime(path).toInstant().atZone(ZoneId.of("GMT"))
                .format(DateTimeFormatter.RFC_1123_DATE_TIME);
    }
}

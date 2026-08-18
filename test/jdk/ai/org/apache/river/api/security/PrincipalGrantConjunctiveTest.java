/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.security.CodeSource;
import java.security.Permission;
import java.security.Principal;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.apache.river.api.security.PermissionGrant;
import org.apache.river.api.security.PermissionGrantBuilder;

/**
 * @test
 * @summary Multi-principal grants must be CONJUNCTIVE: a grant naming principals
 *          {A,B} implies a domain ONLY when that domain holds BOTH. A disjunctive
 *          (any-of) reading is a silent over-grant -- the domain gets authority the
 *          policy author did not write. Defends the invariant stated in
 *          SECURITY_MODEL.md, "conjunctive multi-principal grants (all listed
 *          principals present)", as enforced by PrincipalGrant.implies(Principal[]).
 * @author Claude Opus 5 (claude-opus-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 * @run main PrincipalGrantConjunctiveTest
 */
public class PrincipalGrantConjunctiveTest {

    private static final Principal ALICE = new X500Principal("CN=Alice");
    private static final Principal BOB = new X500Principal("CN=Bob");
    private static final Principal CAROL = new X500Principal("CN=Carol");

    /** Grants carry a permission only so the grant is well-formed; it is never checked here. */
    private static final Permission ANY = new RuntimePermission("getClassLoader");

    private static final List<String> failures = new ArrayList<>();

    public static void main(String[] args) throws Exception {

        // A grant requiring BOTH Alice and Bob.
        PermissionGrant both = PermissionGrantBuilder.newBuilder()
                .context(PermissionGrantBuilder.PRINCIPAL)
                .principals(new Principal[]{ALICE, BOB})
                .permissions(new Permission[]{ANY})
                .build();

        // --- MUST imply: every required principal is present ---------------
        check(both, new Principal[]{ALICE, BOB}, true,
              "domain holds exactly the required principals");
        check(both, new Principal[]{ALICE, BOB, CAROL}, true,
              "domain holds a superset of the required principals");
        check(both, new Principal[]{CAROL, BOB, ALICE}, true,
              "match is order-independent");

        // --- MUST NOT imply: this is the conjunctive property --------------
        // Each of these passes under a disjunctive (any-of) implementation and
        // fails under the correct conjunctive (all-of) one. They are the reason
        // this test exists.
        check(both, new Principal[]{ALICE}, false,
              "domain holds only the FIRST required principal");
        check(both, new Principal[]{BOB}, false,
              "domain holds only the SECOND required principal");
        check(both, new Principal[]{CAROL}, false,
              "domain holds only an unrelated principal");
        check(both, new Principal[0], false,
              "domain holds no principals");
        check(both, null, false,
              "domain principals are null");

        // --- Boundary: a grant naming NO principals is unconstrained by them.
        // Guards the empty-set edge: 'requires nothing' must not collapse into
        // 'requires something', nor the reverse.
        PermissionGrant none = PermissionGrantBuilder.newBuilder()
                .context(PermissionGrantBuilder.PRINCIPAL)
                .principals(new Principal[0])
                .permissions(new Permission[]{ANY})
                .build();

        check(none, new Principal[]{ALICE}, true,
              "principal-less grant implies a domain with principals");
        check(none, new Principal[0], true,
              "principal-less grant implies a domain without principals");

        if (!failures.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            sb.append(failures.size()).append(" conjunctive-grant assertion(s) failed:");
            for (String f : failures) {
                sb.append(System.lineSeparator()).append("  - ").append(f);
            }
            throw new RuntimeException(sb.toString());
        }
        System.out.println("PASS: multi-principal grants are conjunctive (10 assertions)");
    }

    /**
     * Asserts {@code grant.implies(cs, domainPrincipals) == expected}.
     * <p>
     * Uses the public {@code implies(CodeSource, Principal[])} entry point:
     * {@code PrincipalGrant} and its {@code implies(Principal[])} are
     * package-private, and a classpath test cannot join a package exported by
     * {@code java.base}. A null-location, null-certificate CodeSource is used
     * because a PrincipalGrant's decision must turn on principals alone.
     */
    private static void check(PermissionGrant grant,
                              Principal[] domainPrincipals,
                              boolean expected,
                              String description) {
        CodeSource cs = new CodeSource(null, (Certificate[]) null);
        boolean actual;
        try {
            actual = grant.implies(cs, domainPrincipals);
        } catch (RuntimeException e) {
            failures.add(description + " -- threw " + e);
            return;
        }
        if (actual != expected) {
            failures.add(description
                    + " -- expected implies=" + expected + " but was " + actual);
        }
    }
}

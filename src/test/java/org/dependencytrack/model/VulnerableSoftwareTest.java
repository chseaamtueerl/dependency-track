/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.model;

import org.junit.Assert;
import org.junit.Test;
import org.junit.Assert;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.mockito.Mockito.*;

import java.util.UUID;

public class VulnerableSoftwareTest {

    @Test
    public void testId() {
        VulnerableSoftware vs = new VulnerableSoftware();
        vs.setId(111L);
        Assert.assertEquals(111L, vs.getId());
    }

    @Test
    public void testCpe22() {
        VulnerableSoftware vs = new VulnerableSoftware();
        vs.setCpe22("cpe:/a:gimp:gimp:2.10.0");
        Assert.assertEquals("cpe:/a:gimp:gimp:2.10.0", vs.getCpe22());
    }

    @Test
    public void testCpe23() {
        VulnerableSoftware vs = new VulnerableSoftware();
        vs.setCpe23("cpe:2.3:a:gimp:gimp:2.10.0:*:*:*:*:*:*:*");
        Assert.assertEquals("cpe:2.3:a:gimp:gimp:2.10.0:*:*:*:*:*:*:*", vs.getCpe23());
    }

    @Test
    public void testVulnerableSoftwareFields() {
        VulnerableSoftware vs = new VulnerableSoftware();
        vs.setPart("a");
        vs.setVendor("acme");
        vs.setProduct("cool-product");
        vs.setVersion("1.1.0");
        vs.setUpdate("*");
        vs.setEdition("*");
        vs.setLanguage("*");
        vs.setSwEdition("*");
        vs.setTargetSw("*");
        vs.setTargetHw("*");
        vs.setOther("*");
        vs.setVersionEndExcluding("111");
        vs.setVersionEndIncluding("222");
        vs.setVersionStartExcluding("333");
        vs.setVersionStartIncluding("444");
        vs.setVulnerable(true);
        Assert.assertEquals("a", vs.getPart());
        Assert.assertEquals("acme", vs.getVendor());
        Assert.assertEquals("cool-product", vs.getProduct());
        Assert.assertEquals("1.1.0", vs.getVersion());
        Assert.assertEquals("*", vs.getUpdate());
        Assert.assertEquals("*", vs.getEdition());
        Assert.assertEquals("*", vs.getLanguage());
        Assert.assertEquals("*", vs.getSwEdition());
        Assert.assertEquals("*", vs.getTargetSw());
        Assert.assertEquals("*", vs.getTargetHw());
        Assert.assertEquals("*", vs.getOther());
        Assert.assertEquals("111", vs.getVersionEndExcluding());
        Assert.assertEquals("222", vs.getVersionEndIncluding());
        Assert.assertEquals("333", vs.getVersionStartExcluding());
        Assert.assertEquals("444", vs.getVersionStartIncluding());
        Assert.assertTrue(vs.isVulnerable());
    }

    @Test
    public void testUuid() {
        UUID uuid = UUID.randomUUID();
        VulnerableSoftware vs = new VulnerableSoftware();
        vs.setUuid(uuid);
        Assert.assertEquals(uuid.toString(), vs.getUuid().toString());
    }


        @Test
        public void testEqualsIgnoringDatastoreIdentity() {
            VulnerableSoftware vs1 = new VulnerableSoftware();
            vs1.setPurl("pkg:maven/foo/bar@1.0.0");
            vs1.setCpe23("cpe:2.3:a:foo:bar:1.0.0:*:*:*:*:java:*:*");
            vs1.setVendor("foo");
            vs1.setProduct("bar");
            vs1.setVersion("1.0.0");

            VulnerableSoftware vs2 = new VulnerableSoftware();
            vs2.setPurl("pkg:maven/foo/bar@1.0.0");
            vs2.setCpe23("cpe:2.3:a:foo:bar:1.0.0:*:*:*:*:java:*:*");
            vs2.setVendor("foo");
            vs2.setProduct("bar");
            vs2.setVersion("1.0.0");

            VulnerableSoftware vs3 = new VulnerableSoftware();
            vs3.setPurl("pkg:maven/foo/baz@2.0.0");

            Assert.assertTrue(vs1.equalsIgnoringDatastoreIdentity(vs2));
            Assert.assertFalse(vs1.equalsIgnoringDatastoreIdentity(vs3));
        }

        @Test
        public void testHashCodeWithoutDatastoreIdentity() {
            VulnerableSoftware vs1 = new VulnerableSoftware();
            vs1.setPurl("pkg:maven/foo/bar@1.0.0");
            vs1.setVendor("foo");
            vs1.setProduct("bar");

            VulnerableSoftware vs2 = new VulnerableSoftware();
            vs2.setPurl("pkg:maven/foo/bar@1.0.0");
            vs2.setVendor("foo");
            vs2.setProduct("bar");

            VulnerableSoftware vs3 = new VulnerableSoftware();
            vs3.setPurl("pkg:maven/foo/baz@2.0.0");

            Assert.assertEquals(vs1.hashCodeWithoutDatastoreIdentity(), vs2.hashCodeWithoutDatastoreIdentity());
            Assert.assertNotEquals(vs1.hashCodeWithoutDatastoreIdentity(), vs3.hashCodeWithoutDatastoreIdentity());
        }

        @Test
        public void testToString() {
            VulnerableSoftware vs = new VulnerableSoftware();
            vs.setId(101);
            vs.setPurl("pkg:maven/foo/bar@1.0.0");
            vs.setCpe23("cpe:2.3:a:foo:bar:1.0.0:*:*:*:*:java:*:*");

            String result = vs.toString();
            Assert.assertTrue(result.contains("id=101"));
            Assert.assertTrue(result.contains("purl=pkg:maven/foo/bar@1.0.0"));
            Assert.assertTrue(result.contains("cpe23=cpe:2.3:a:foo:bar:1.0.0:*:*:*:*:java:*:*"));
        }

        @Test
        public void testAddVulnerability() {
            VulnerableSoftware vs = new VulnerableSoftware();
            Vulnerability mockVulnerability = mock(Vulnerability.class);

            Assert.assertNull(vs.getVulnerabilities());

            vs.addVulnerability(mockVulnerability);

            List<Vulnerability> vulnerabilities = vs.getVulnerabilities();
            Assert.assertNotNull(vulnerabilities);
            Assert.assertEquals(1, vulnerabilities.size());
            Assert.assertEquals(mockVulnerability, vulnerabilities.get(0));
        }

        @Test
        public void testAffectedVersionAttributions() {
            VulnerableSoftware vs = new VulnerableSoftware();
            List<AffectedVersionAttribution> attributions = new ArrayList<>();
            attributions.add(new AffectedVersionAttribution());

            Assert.assertNull(vs.getAffectedVersionAttributions());
            vs.setAffectedVersionAttributions(attributions);

            Assert.assertEquals(1, vs.getAffectedVersionAttributions().size());
        }

    @Test
    public void testGetVulnerabilitiesWithMocks() {
        VulnerableSoftware vs = new VulnerableSoftware();
        Vulnerability mockVuln1 = mock(Vulnerability.class);
        Vulnerability mockVuln2 = mock(Vulnerability.class);

        UUID uuid1 = UUID.randomUUID();
        UUID uuid2 = UUID.randomUUID();
        when(mockVuln1.getUuid()).thenReturn(uuid1);
        when(mockVuln2.getUuid()).thenReturn(uuid2);

        vs.addVulnerability(mockVuln1);
        vs.addVulnerability(mockVuln2);

        List<Vulnerability> retrievedVulnerabilities = vs.getVulnerabilities();
        Assert.assertNotNull(retrievedVulnerabilities);
        Assert.assertEquals(2, retrievedVulnerabilities.size());

        UUID retrievedUuid1 = retrievedVulnerabilities.get(0).getUuid();
        UUID retrievedUuid2 = retrievedVulnerabilities.get(1).getUuid();

        Assert.assertEquals(uuid1, retrievedUuid1);
        Assert.assertEquals(uuid2, retrievedUuid2);

        verify(mockVuln1, times(1)).getUuid();
        verify(mockVuln2, times(1)).getUuid();
    }
}

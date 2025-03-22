/*
 * Copyright 2023 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.jwt.token.jwks;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.net.ssl.SSLContext;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link TlsVersions} class.
 */
@DisplayName("Tests TlsVersions functionality")
class TlsVersionsTest {

    @Test
    @DisplayName("Should define correct TLS version constants")
    void shouldDefineCorrectConstants() {
        assertEquals("TLSv1.2", TlsVersions.TLS_V1_2);
        assertEquals("TLSv1.3", TlsVersions.TLS_V1_3);
        assertEquals("TLS", TlsVersions.TLS);
        assertEquals("TLSv1.0", TlsVersions.TLS_V1_0);
        assertEquals("TLSv1.1", TlsVersions.TLS_V1_1);
        assertEquals("SSLv3", TlsVersions.SSL_V3);
        assertEquals(TlsVersions.TLS_V1_2, TlsVersions.DEFAULT_TLS_VERSION);
    }

    @Test
    @DisplayName("Should have correct allowed TLS versions")
    void shouldHaveCorrectAllowedVersions() {
        assertEquals(3, TlsVersions.ALLOWED_TLS_VERSIONS.size());
        assertTrue(TlsVersions.ALLOWED_TLS_VERSIONS.contains(TlsVersions.TLS_V1_2));
        assertTrue(TlsVersions.ALLOWED_TLS_VERSIONS.contains(TlsVersions.TLS_V1_3));
        assertTrue(TlsVersions.ALLOWED_TLS_VERSIONS.contains(TlsVersions.TLS));
    }

    @Test
    @DisplayName("Should have correct forbidden TLS versions")
    void shouldHaveCorrectForbiddenVersions() {
        assertEquals(3, TlsVersions.FORBIDDEN_TLS_VERSIONS.size());
        assertTrue(TlsVersions.FORBIDDEN_TLS_VERSIONS.contains(TlsVersions.TLS_V1_0));
        assertTrue(TlsVersions.FORBIDDEN_TLS_VERSIONS.contains(TlsVersions.TLS_V1_1));
        assertTrue(TlsVersions.FORBIDDEN_TLS_VERSIONS.contains(TlsVersions.SSL_V3));
    }

    @ParameterizedTest
    @ValueSource(strings = {"TLSv1.2", "TLSv1.3", "TLS"})
    @DisplayName("Should identify secure TLS versions")
    void shouldIdentifySecureTlsVersions(String protocol) {
        assertTrue(TlsVersions.isSecureTlsVersion(protocol));
    }

    @ParameterizedTest
    @ValueSource(strings = {"TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2", "unknown"})
    @DisplayName("Should identify insecure TLS versions")
    void shouldIdentifyInsecureTlsVersions(String protocol) {
        assertFalse(TlsVersions.isSecureTlsVersion(protocol));
    }

    @Test
    @DisplayName("Should handle null protocol")
    void shouldHandleNullProtocol() {
        assertFalse(TlsVersions.isSecureTlsVersion(null));
    }

    @Test
    @DisplayName("Should have no overlap between allowed and forbidden versions")
    void shouldHaveNoOverlapBetweenAllowedAndForbidden() {
        for (String allowed : TlsVersions.ALLOWED_TLS_VERSIONS) {
            assertFalse(TlsVersions.FORBIDDEN_TLS_VERSIONS.contains(allowed),
                    "Protocol " + allowed + " should not be in both allowed and forbidden sets");
        }

        for (String forbidden : TlsVersions.FORBIDDEN_TLS_VERSIONS) {
            assertFalse(TlsVersions.ALLOWED_TLS_VERSIONS.contains(forbidden),
                    "Protocol " + forbidden + " should not be in both allowed and forbidden sets");
        }
    }

    @Test
    @DisplayName("Should create secure SSL context")
    void shouldCreateSecureSSLContext() throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        // When: Creating a secure SSL context
        SSLContext sslContext = TlsVersions.createSecureSSLContext();

        // Then: The context should not be null
        assertNotNull(sslContext, "SSL context should not be null");

        // And: The protocol should be the default TLS version
        assertEquals(TlsVersions.DEFAULT_TLS_VERSION, sslContext.getProtocol(), 
                "SSL context should use the default TLS version");
    }
}

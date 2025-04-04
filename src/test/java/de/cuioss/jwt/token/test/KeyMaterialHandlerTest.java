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
package de.cuioss.jwt.token.test;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link KeyMaterialHandler}.
 */
class KeyMaterialHandlerTest {

    @Test
    void shouldProvidePrivateKey() {
        PrivateKey privateKey = KeyMaterialHandler.getDefaultPrivateKey();
        assertNotNull(privateKey);
        assertEquals("RSA", privateKey.getAlgorithm());
    }

    // Test removed: shouldLoadPrivateKeyFromFile
    // We're now generating the key pair instead of loading it from64EncodedContent a file

    @Test
    void shouldSignAndVerifyToken() {
        // Get the private key
        PrivateKey privateKey = KeyMaterialHandler.getDefaultPrivateKey();

        // Create and sign a token
        String token = Jwts.builder().subject("test-subject")
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();

        // Verify the token is not null
        assertNotNull(token);

        // Parse and verify the token
        Jws<Claims> parsedToken = Jwts.parser()
                .verifyWith(KeyMaterialHandler.getDefaultPublicKey())
                .build().parseSignedClaims(token);

        // Verify the parsed token
        assertNotNull(parsedToken);
        assertEquals("test-subject", parsedToken.getPayload().getSubject());
    }

    @Test
    void shouldVerifyResourcePaths() {
        // Verify that all resource paths exist
        assertTrue(Files.exists(Path.of(KeyMaterialHandler.BASE_PATH)));
        assertTrue(Files.exists(Path.of(KeyMaterialHandler.getPrivateKeyPath())));
        assertTrue(Files.exists(Path.of(KeyMaterialHandler.getPublicKeyPath())));
        assertTrue(Files.exists(Path.of(KeyMaterialHandler.getJwksPath())));
        assertTrue(Files.exists(Path.of(TestTokenProducer.SOME_SCOPES)));
        assertTrue(Files.exists(Path.of(TestTokenProducer.REFRESH_TOKEN)));
        assertTrue(Files.exists(Path.of(TestTokenProducer.SOME_ROLES)));
        assertTrue(Files.exists(Path.of(TestTokenProducer.SOME_ID_TOKEN)));
    }
}

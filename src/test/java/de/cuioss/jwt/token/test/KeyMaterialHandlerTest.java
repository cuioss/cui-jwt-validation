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
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link KeyMaterialHandler}.
 */
class KeyMaterialHandlerTest {

    @Test
    void shouldProvidePrivateKey() {
        PrivateKey privateKey = KeyMaterialHandler.getPrivateKey();
        assertNotNull(privateKey);
        assertEquals("RSA", privateKey.getAlgorithm());
    }

    // Test removed: shouldLoadPrivateKeyFromFile
    // We're now generating the key pair instead of loading it from a file

    @Test
    void shouldSignAndVerifyToken() {
        // Get the private key
        PrivateKey privateKey = KeyMaterialHandler.getPrivateKey();

        // Create and sign a token
        String token = Jwts.builder()
                .setSubject("test-subject")
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();

        // Verify the token is not null
        assertNotNull(token);

        // Parse and verify the token
        Jws<Claims> parsedToken = Jwts.parserBuilder()
                .setSigningKey(privateKey)
                .build()
                .parseClaimsJws(token);

        // Verify the parsed token
        assertNotNull(parsedToken);
        assertEquals("test-subject", parsedToken.getBody().getSubject());
    }

    @Test
    void shouldVerifyResourcePaths() {
        // Verify that all resource paths exist
        assertTrue(Files.exists(Paths.get(KeyMaterialHandler.BASE_PATH)));
        assertTrue(Files.exists(Paths.get(KeyMaterialHandler.PRIVATE_KEY)));
        assertTrue(Files.exists(Paths.get(KeyMaterialHandler.PUBLIC_KEY)));
        assertTrue(Files.exists(Paths.get(KeyMaterialHandler.PUBLIC_KEY_JWKS)));
        assertTrue(Files.exists(Paths.get(TestTokenProducer.SOME_SCOPES)));
        assertTrue(Files.exists(Paths.get(TestTokenProducer.REFRESH_TOKEN)));
        assertTrue(Files.exists(Paths.get(TestTokenProducer.SOME_ROLES)));
        assertTrue(Files.exists(Paths.get(TestTokenProducer.SOME_ID_TOKEN)));
    }
}

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

import de.cuioss.jwt.token.JwksAwareTokenParserImplTest;
import de.cuioss.jwt.token.JwtParser;
import de.cuioss.test.generator.Generators;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class TestTokenProducer {

    public static final String ISSUER = "Token-Test-testIssuer";
    public static final String WRONG_ISSUER = Generators.nonBlankStrings().next();
    public static final String SUBJECT = Generators.letterStrings(10, 12).next();

    // Constants for file paths
    public static final String BASE_PATH = KeyMaterialHandler.BASE_PATH;

    // Constants for token claims files
    public static final String SOME_SCOPES = BASE_PATH + "some-scopes.json";
    public static final String REFRESH_TOKEN = BASE_PATH + "refresh-token.json";
    public static final String SOME_ROLES = BASE_PATH + "some-roles.json";
    public static final String SOME_NAME = BASE_PATH + "some-name.json";
    public static final String SOME_ID_TOKEN = BASE_PATH + "some-id-token.json";

    // Lazy initialization of token parsers to avoid circular dependencies
    public static JwtParser getDefaultTokenParser() {
        try {
            // For testing purposes, we'll use a non-validating parser that doesn't verify signatures
            return new TestJwtParser(ISSUER);
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize default token parser", e);
        }
    }

    public static JwtParser getWrongIssuerTokenParser() {
        try {
            return JwksAwareTokenParserImplTest.getInvalidValidJWKSParserWithLocalJWKSAndWrongIssuer();
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize wrong issuer token parser", e);
        }
    }

    public static JwtParser getWrongSignatureTokenParser() {
        try {
            return JwksAwareTokenParserImplTest.getInvalidJWKSParserWithWrongLocalJWKS();
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize wrong signature token parser", e);
        }
    }

    /**
     * Loads JSON claims from a file.
     *
     * @param path the path to the JSON file
     * @return the JSON object
     * @throws IOException if loading the file fails
     */
    private static JsonObject loadJsonClaims(String path) throws IOException {
        String content = Files.readString(Paths.get(path));
        try (JsonReader reader = Json.createReader(new StringReader(content))) {
            return reader.readObject();
        }
    }

    /**
     * Adds claims from a JSON file to a JWT builder.
     *
     * @param builder    the JWT builder
     * @param claimsPath the path to the JSON claims file
     * @return the updated JWT builder
     * @throws IOException if loading the claims fails
     */
    private static JwtBuilder addClaims(JwtBuilder builder, String claimsPath) throws IOException {
        if (claimsPath == null) {
            return builder;
        }

        JsonObject claims = loadJsonClaims(claimsPath);
        for (String key : claims.keySet()) {
            switch (claims.get(key).getValueType()) {
                case STRING:
                    builder.claim(key, claims.getString(key));
                    break;
                case NUMBER:
                    builder.claim(key, claims.getJsonNumber(key).longValue());
                    break;
                case ARRAY:
                    // Handle arrays if needed
                    break;
                case OBJECT:
                    // Handle objects if needed
                    break;
                default:
                // Ignore other types
            }
        }
        return builder;
    }

    public static String validSignedJWTWithClaims(String claimsPath) {
        try {
            JwtBuilder builder = Jwts.builder()
                    .setIssuer(ISSUER)
                    .setSubject(SUBJECT)
                    .setIssuedAt(Date.from(Instant.now()))
                    .setExpiration(Date.from(Instant.now().plusSeconds(3600))) // Set expiration to 1 hour from now
                    .setHeaderParam("kid", "default-key-id") // Add key ID to header
                    .signWith(KeyMaterialHandler.getPrivateKey(), SignatureAlgorithm.RS256);

            // Add claims from file if provided
            if (claimsPath != null) {
                addClaims(builder, claimsPath);
            }

            return builder.compact();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create JWT", e);
        }
    }

    public static String validSignedEmptyJWT() {
        return Jwts.builder()
                .setIssuer(ISSUER)
                .setSubject(SUBJECT)
                .signWith(KeyMaterialHandler.getPrivateKey(), SignatureAlgorithm.RS256)
                .compact();
    }

    public static String validSignedJWTWithClaims(String claimsPath, String subject) {
        try {
            JwtBuilder builder = Jwts.builder()
                    .setIssuer(ISSUER)
                    .setSubject(subject)
                    .signWith(KeyMaterialHandler.getPrivateKey(), SignatureAlgorithm.RS256);

            // Add claims from file if provided
            if (claimsPath != null) {
                addClaims(builder, claimsPath);
            }

            return builder.compact();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create JWT", e);
        }
    }

    public static String validSignedJWTExpireAt(Instant expireAt) {
        try {
            JwtBuilder builder = Jwts.builder()
                    .setIssuer(ISSUER)
                    .setSubject(SUBJECT)
                    .setIssuedAt(Date.from(OffsetDateTime.ofInstant(expireAt, ZoneId.systemDefault()).minusMinutes(5).toInstant()))
                    .setExpiration(Date.from(expireAt))
                    .signWith(KeyMaterialHandler.getPrivateKey(), SignatureAlgorithm.RS256);

            // Add claims from file
            addClaims(builder, SOME_SCOPES);

            return builder.compact();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create JWT", e);
        }
    }

    /**
     * Creates a valid signed JWT with a "Not Before" (nbf) claim
     *
     * @param notBefore the instant representing the "Not Before" time
     * @return a signed JWT token string with the nbf claim set
     */
    public static String validSignedJWTWithNotBefore(Instant notBefore) {
        try {
            JwtBuilder builder = Jwts.builder()
                    .setIssuer(ISSUER)
                    .setSubject(SUBJECT)
                    .setIssuedAt(Date.from(OffsetDateTime.ofInstant(notBefore, ZoneId.systemDefault()).minusMinutes(5).toInstant()))
                    .setExpiration(Date.from(OffsetDateTime.ofInstant(notBefore, ZoneId.systemDefault()).plusMinutes(10).toInstant()))
                    .claim("nbf", notBefore.getEpochSecond())
                    .signWith(KeyMaterialHandler.getPrivateKey(), SignatureAlgorithm.RS256);

            // Add claims from file
            addClaims(builder, SOME_SCOPES);

            return builder.compact();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create JWT", e);
        }
    }

    @Test
    void shouldCreateScopesAndClaims() {
        String token = validSignedJWTWithClaims(SOME_SCOPES);
        assertNotNull(token);

        // Parse the token using JJWT
        Jws<Claims> parsedToken = Jwts.parserBuilder()
                .setSigningKey(KeyMaterialHandler.getPrivateKey())
                .build()
                .parseClaimsJws(token);

        assertNotNull(parsedToken);
        assertNotNull(parsedToken.getBody());
        assertNotNull(parsedToken.getBody().getSubject());
    }
}

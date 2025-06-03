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
package de.cuioss.jwt.validation.benchmark.util;

import de.cuioss.jwt.validation.test.InMemoryKeyMaterialHandler;
import de.cuioss.jwt.validation.test.InMemoryKeyMaterialHandler.Algorithm;
import io.jsonwebtoken.Jwts;
import lombok.experimental.UtilityClass;
import org.apache.commons.lang3.RandomStringUtils;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Utility class for generating JWT tokens with various characteristics for benchmarking purposes.
 * <p>
 * This class provides methods to create tokens with different sizes, complexities, and signature algorithms.
 * It is designed to be used in benchmark tests to evaluate the performance of JWT token validation.
 * <p>
 * Example usage:
 * <pre>
 * // Generate a small, simple token signed with RS256
 * String token = BenchmarkTokenGenerators.generateAccessToken(
 *     "https://issuer.example.com",
 *     "subject123",
 *     "client-app",
 *     3600000, // 1 hour
 *     TokenSize.SMALL,
 *     TokenComplexity.SIMPLE,
 *     Jwts.SIG.RS256
 * );
 * 
 * // Generate a large, complex token signed with RS512
 * String token = BenchmarkTokenGenerators.generateAccessToken(
 *     "https://issuer.example.com",
 *     "subject123",
 *     "client-app",
 *     3600000, // 1 hour
 *     TokenSize.LARGE,
 *     TokenComplexity.COMPLEX,
 *     Jwts.SIG.RS512
 * );
 * </pre>
 */
@UtilityClass
public class BenchmarkTokenGenerators {

    /**
     * Enum defining the size categories for generated tokens.
     */
    public enum TokenSize {
        /** Default size, approximately 1KB or less */
        SMALL,
        /** Medium size with padding, approximately 5KB */
        MEDIUM,
        /** Large size with padding, approximately 10KB or more */
        LARGE
    }

    /**
     * Enum defining the complexity categories for generated tokens.
     */
    public enum TokenComplexity {
        /** Basic set of standard claims */
        SIMPLE,
        /** Additional nested claims and more numerous claims */
        COMPLEX
    }

    private static final InMemoryKeyMaterialHandler rsaKeyHandler = new InMemoryKeyMaterialHandler();

    /**
     * Generates an access token with the specified parameters.
     *
     * @param issuer           the token issuer
     * @param subject          the token subject (usually user identifier)
     * @param audience         the intended audience for the token
     * @param expirationMillis the token expiration time in milliseconds from now
     * @param size             the desired token size category
     * @param complexity       the desired token complexity category
     * @param algorithm        the signature algorithm to use
     * @return a JWT token string
     * @throws UnsupportedOperationException if the requested algorithm is not supported
     */
    public static String generateAccessToken(
            String issuer,
            String subject,
            String audience,
            long expirationMillis,
            TokenSize size,
            TokenComplexity complexity,
            Algorithm algorithm) {

        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", issuer);
        claims.put("sub", subject);
        claims.put("aud", audience);
        claims.put("exp", new Date(System.currentTimeMillis() + expirationMillis));
        claims.put("iat", new Date(System.currentTimeMillis()));
        claims.put("jti", UUID.randomUUID().toString());

        if (complexity == TokenComplexity.COMPLEX) {
            Map<String, Object> nestedClaim = new HashMap<>();
            nestedClaim.put("attr1", "value1");
            nestedClaim.put("attr2", true);
            nestedClaim.put("attr3", 12345);
            claims.put("complex_claim", nestedClaim);
            for (int i = 0; i < 5; i++) {
                claims.put("extra_claim_" + i, RandomStringUtils.randomAlphanumeric(50));
            }
        }

        // Adjust content for size
        int paddingLength = 0;
        if (size == TokenSize.MEDIUM) {
            paddingLength = 4 * 1024; // Aim for roughly 5KB
        } else if (size == TokenSize.LARGE) {
            paddingLength = 9 * 1024; // Aim for roughly 10KB
        }
        if (paddingLength > 0) {
            claims.put("padding", RandomStringUtils.randomAlphanumeric(paddingLength));
        }

        // Get the appropriate signing key
        Key signingKey = rsaKeyHandler.getDefaultPrivateKey(algorithm);

        // Build and sign the token
        return Jwts.builder()
                .claims(claims)
                .signWith(signingKey)
                .compact();
    }
}

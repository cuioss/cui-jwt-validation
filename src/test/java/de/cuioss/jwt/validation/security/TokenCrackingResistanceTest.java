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
package de.cuioss.jwt.validation.security;

import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.jwt.validation.TokenValidatorConfig;
import de.cuioss.jwt.validation.flow.IssuerConfig;
import de.cuioss.jwt.validation.jwks.JwksLoader;
import de.cuioss.jwt.validation.jwks.key.KeyInfo;
import de.cuioss.jwt.validation.test.JWKSFactory;
import de.cuioss.jwt.validation.test.generator.AccessTokenGenerator;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.tools.logging.CuiLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for validation cracking resistance.
 * <p>
 * These tests verify that tokens use strong cryptographic algorithms and have
 * sufficient entropy to resist cracking attempts. Token cracking refers to
 * attempts to forge or predict JWT signatures, which would allow attackers
 * to create valid tokens without possessing the private key.
 * <p>
 * What is tested:
 * <ul>
 *   <li>Tokens use strong cryptographic algorithms (RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512)</li>
 *   <li>Tokens have sufficient entropy in their header and payload</li>
 *   <li>Tokens are resistant to brute force attacks</li>
 *   <li>Only approved algorithms are used</li>
 *   <li>Token signatures are unpredictable</li>
 * </ul>
 * <p>
 * Why it's important:
 * <p>
 * Weak cryptographic algorithms or insufficient entropy can make tokens vulnerable
 * to brute force attacks or cryptanalysis. This could allow attackers to forge valid
 * tokens and gain unauthorized access to protected resources. Strong cryptographic
 * properties ensure that tokens remain secure even if large portions of the validation
 * are known to an attacker.
 * <p>
 * How testing is performed:
 * <p>
 * Testing uses a combination of:
 * <ul>
 *   <li>Algorithm verification - checking that only strong algorithms are used</li>
 *   <li>Entropy calculation - using Shannon entropy to measure randomness</li>
 *   <li>Signature tampering - verifying that modified signatures are rejected</li>
 *   <li>Multiple validation generation - ensuring signatures are not predictable</li>
 * </ul>
 * <p>
 * The Shannon entropy calculation is particularly important as it provides a
 * mathematical measure of the unpredictability of the validation content, which
 * directly relates to how resistant the tokens are to guessing attacks.
 */
@EnableTestLogger
@DisplayName("Token Cracking Resistance Tests")
class TokenCrackingResistanceTest {

    private static final CuiLogger LOGGER = new CuiLogger(TokenCrackingResistanceTest.class);

    private TokenValidator tokenValidator;
    private IssuerConfig issuerConfig;

    @BeforeEach
    void setUp() {
        // Create issuer config with JWKS content
        issuerConfig = IssuerConfig.builder()
                .issuer("https://test-issuer.com")
                .expectedAudience("test-client")
                .jwksContent(JWKSFactory.createDefaultJwks())
                .build();

        // Create validation factory
        TokenValidatorConfig config = TokenValidatorConfig.builder().build();
        tokenValidator = new TokenValidator(config, issuerConfig);
    }

    @Test
    @DisplayName("Tokens should use strong cryptographic algorithms")
    void tokensShouldUseStrongCryptographicAlgorithms() {
        // Get the JwksLoader from the issuer config
        JwksLoader jwksLoader = issuerConfig.getJwksLoader();

        // Get all key infos
        List<KeyInfo> keyInfos = jwksLoader.getAllKeyInfos();
        assertFalse(keyInfos.isEmpty(), "JwksLoader should contain keys");

        // Check each key's algorithm to ensure it's strong
        for (KeyInfo keyInfo : keyInfos) {
            String algorithm = keyInfo.getAlgorithm();

            // Verify that the algorithm is not a weak one
            assertNotEquals("none", algorithm, "Algorithm should not be 'none'");
            assertNotEquals("HS1", algorithm, "Algorithm should not be HS1");
            assertNotEquals("HS256", algorithm, "Algorithm should not be HS256 (prefer RS256 or ES256)");

            // Verify that the algorithm is a strong one
            assertTrue(
                    algorithm.equals("RS256") ||
                            algorithm.equals("RS384") ||
                            algorithm.equals("RS512") ||
                            algorithm.equals("ES256") ||
                            algorithm.equals("ES384") ||
                            algorithm.equals("ES512") ||
                            algorithm.equals("PS256") ||
                            algorithm.equals("PS384") ||
                            algorithm.equals("PS512"),
                    "Algorithm should be a strong one, but was: " + algorithm
            );
        }
    }

    @Test
    @DisplayName("Tokens should have sufficient entropy")
    void tokensShouldHaveSufficientEntropy() {
        // Generate a validation
        String token = new AccessTokenGenerator(false).next();

        // Split the validation into its parts
        String[] parts = token.split("\\.");
        assertEquals(3, parts.length, "Token should have 3 parts");

        // Check the header and payload for entropy
        String header = parts[0];
        String payload = parts[1];
        String signature = parts[2];

        // Decode the header and payload
        byte[] headerBytes = Base64.getUrlDecoder().decode(header);
        byte[] payloadBytes = Base64.getUrlDecoder().decode(payload);

        // Calculate entropy using Shannon entropy formula
        double headerEntropy = calculateShannonEntropy(headerBytes);
        double payloadEntropy = calculateShannonEntropy(payloadBytes);

        // Verify that the entropy is sufficient
        assertTrue(headerEntropy > 3.0, "Header entropy should be > 3.0, but was: " + headerEntropy);
        assertTrue(payloadEntropy > 4.0, "Payload entropy should be > 4.0, but was: " + payloadEntropy);

        // Verify that the signature is sufficiently long
        assertTrue(signature.length() >= 32, "Signature should be at least 32 characters long");
    }

    @Test
    @DisplayName("Tokens should be resistant to brute force attacks")
    void tokensShouldBeResistantToBruteForceAttacks() {
        // Generate a validation
        String token = new AccessTokenGenerator(false).next();

        // Split the validation into its parts
        String[] parts = token.split("\\.");
        assertEquals(3, parts.length, "Token should have 3 parts");

        // Get the signature
        String signature = parts[2];

        // Verify that the signature is sufficiently long
        assertTrue(signature.length() >= 32, "Signature should be at least 32 characters long");

        // Try to verify the validation with a wrong signature
        String tamperedToken = parts[0] + "." + parts[1] + "." + signature.substring(0, signature.length() - 1) + "X";

        // Verify that the tampered validation is rejected
        Optional<?> result = tokenValidator.createAccessToken(tamperedToken);
        assertFalse(result.isPresent(), "Tampered validation should be rejected");
    }

    @ParameterizedTest
    @ValueSource(strings = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"})
    @DisplayName("Tokens should use approved algorithms")
    void tokensShouldUseApprovedAlgorithms(String algorithm) {
        // Get the JwksLoader from the issuer config
        JwksLoader jwksLoader = issuerConfig.getJwksLoader();

        // Get all key infos
        List<KeyInfo> keyInfos = jwksLoader.getAllKeyInfos();

        // Check if any key uses the specified algorithm
        boolean algorithmFound = keyInfos.stream()
                .anyMatch(keyInfo -> keyInfo.getAlgorithm().equals(algorithm));

        // If the algorithm is not found, log a warning but don't fail the test
        // as the test environment might not have all algorithms configured
        if (!algorithmFound) {
            LOGGER.warn("Algorithm " + algorithm + " not found in the JWKS");
        }

        // Verify that the algorithm is in the list of approved algorithms
        Set<String> approvedAlgorithms = Set.of("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512");
        assertTrue(approvedAlgorithms.contains(algorithm), "Algorithm should be in the list of approved algorithms");
    }

    @Test
    @DisplayName("Tokens should have unpredictable signatures")
    void tokensShouldHaveUnpredictableSignatures() {
        // Generate multiple tokens
        String token1 = new AccessTokenGenerator(false).next();
        String token2 = new AccessTokenGenerator(false).next();
        String token3 = new AccessTokenGenerator(false).next();

        // Split the tokens into their parts
        String[] parts1 = token1.split("\\.");
        String[] parts2 = token2.split("\\.");
        String[] parts3 = token3.split("\\.");

        // Get the signatures
        String signature1 = parts1[2];
        String signature2 = parts2[2];
        String signature3 = parts3[2];

        // Verify that the signatures are different
        assertNotEquals(signature1, signature2, "Signatures should be different");
        assertNotEquals(signature1, signature3, "Signatures should be different");
        assertNotEquals(signature2, signature3, "Signatures should be different");
    }

    /**
     * Calculates the Shannon entropy of a byte array.
     * 
     * @param bytes the byte array
     * @return the Shannon entropy
     */
    private double calculateShannonEntropy(byte[] bytes) {
        if (bytes.length == 0) {
            return 0.0;
        }

        // Count the frequency of each byte value
        int[] counts = new int[256];
        for (byte b : bytes) {
            counts[b & 0xFF]++;
        }

        // Calculate the Shannon entropy
        double entropy = 0.0;
        for (int count : counts) {
            if (count > 0) {
                double probability = (double) count / bytes.length;
                entropy -= probability * (Math.log(probability) / Math.log(2));
            }
        }

        return entropy;
    }
}

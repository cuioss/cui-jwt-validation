/*
 * Copyright 2025 the original author or authors.
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
package de.cuioss.jwt.validation.test;

import de.cuioss.jwt.validation.jwks.JwksLoader;
import de.cuioss.jwt.validation.jwks.JwksLoaderFactory;
import de.cuioss.jwt.validation.security.BouncyCastleProviderSingleton;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.tools.logging.CuiLogger;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureAlgorithm;
import lombok.Getter;
import lombok.NonNull;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory key material handler for JWT token testing.
 * <p>
 * This class provides access to private and public keys used for signing and verifying tokens.
 * Unlike KeyMaterialHandler, this class:
 * <ul>
 *   <li>Creates keys on the fly</li>
 *   <li>Stores keys in static fields instead of the filesystem</li>
 *   <li>Supports multiple algorithms (RS256, RS384, RS512)</li>
 *   <li>Uses BouncyCastle for key material generation</li>
 * </ul>
 * <p>
 * All access to key materials should be through this class.
 */
public class InMemoryKeyMaterialHandler {

    private static final CuiLogger LOGGER = new CuiLogger(InMemoryKeyMaterialHandler.class);

    /**
     * Default key ID used when no key ID is specified.
     */
    public static final String DEFAULT_KEY_ID = "default-key-id";

    /**
     * Supported signature algorithms.
     */
    public enum Algorithm {
        RS256(Jwts.SIG.RS256),
        RS384(Jwts.SIG.RS384),
        RS512(Jwts.SIG.RS512);

        @Getter
        private final SignatureAlgorithm algorithm;

        Algorithm(SignatureAlgorithm algorithm) {
            this.algorithm = algorithm;
        }

        /**
         * Gets the JWK algorithm name.
         *
         * @return the algorithm name as used in JWK
         */
        public String getJwkAlgorithmName() {
            return name();
        }
    }

    // Static maps to store key pairs for different algorithms
    private static final Map<Algorithm, Map<String, KeyPair>> KEY_PAIRS = new ConcurrentHashMap<>();

    // Static initializer to ensure BouncyCastle provider is registered
    static {
        // Ensure BouncyCastle provider is registered
        BouncyCastleProviderSingleton.getInstance();

        // Initialize key pair maps for each algorithm
        for (Algorithm alg : Algorithm.values()) {
            KEY_PAIRS.put(alg, new ConcurrentHashMap<>());
        }

        // Generate default key pairs for each algorithm
        for (Algorithm alg : Algorithm.values()) {
            generateKeyPair(alg, DEFAULT_KEY_ID);
        }
    }

    /**
     * Generates a key pair for the specified algorithm and key ID.
     *
     * @param algorithm the algorithm to use
     * @param keyId the key ID
     * @return the generated key pair
     */
    private static KeyPair generateKeyPair(Algorithm algorithm, String keyId) {
        try {
            LOGGER.debug("Generating key pair for algorithm %s with key ID %s", algorithm, keyId);
            KeyPair keyPair = algorithm.getAlgorithm().keyPair().build();
            KEY_PAIRS.get(algorithm).put(keyId, keyPair);
            return keyPair;
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate key pair for algorithm " + algorithm, e);
        }
    }

    /**
     * Gets the private key for the specified algorithm and key ID.
     *
     * @param algorithm the algorithm
     * @param keyId the key ID
     * @return the private key
     */
    public static PrivateKey getPrivateKey(Algorithm algorithm, String keyId) {
        return getKeyPair(algorithm, keyId).getPrivate();
    }

    /**
     * Gets the public key for the specified algorithm and key ID.
     *
     * @param algorithm the algorithm
     * @param keyId the key ID
     * @return the public key
     */
    public static PublicKey getPublicKey(Algorithm algorithm, String keyId) {
        return getKeyPair(algorithm, keyId).getPublic();
    }

    /**
     * Gets the key pair for the specified algorithm and key ID.
     * If the key pair doesn't exist, it will be generated.
     *
     * @param algorithm the algorithm
     * @param keyId the key ID
     * @return the key pair
     */
    private static KeyPair getKeyPair(Algorithm algorithm, String keyId) {
        Map<String, KeyPair> keyPairsForAlg = KEY_PAIRS.get(algorithm);
        if (keyPairsForAlg.containsKey(keyId)) {
            return keyPairsForAlg.get(keyId);
        }
        return generateKeyPair(algorithm, keyId);
    }

    /**
     * Gets the default private key for the specified algorithm.
     *
     * @param algorithm the algorithm
     * @return the default private key
     */
    public static PrivateKey getDefaultPrivateKey(Algorithm algorithm) {
        return getPrivateKey(algorithm, DEFAULT_KEY_ID);
    }

    /**
     * Gets the default public key for the specified algorithm.
     *
     * @param algorithm the algorithm
     * @return the default public key
     */
    public static PublicKey getDefaultPublicKey(Algorithm algorithm) {
        return getPublicKey(algorithm, DEFAULT_KEY_ID);
    }

    /**
     * Gets the default private key for RS256.
     *
     * @return the default private key for RS256
     */
    public static PrivateKey getDefaultPrivateKey() {
        return getDefaultPrivateKey(Algorithm.RS256);
    }

    /**
     * Gets the default public key for RS256.
     *
     * @return the default public key for RS256
     */
    public static PublicKey getDefaultPublicKey() {
        return getDefaultPublicKey(Algorithm.RS256);
    }

    /**
     * Creates a JWKS string for the specified algorithm and key ID.
     *
     * @param algorithm the algorithm
     * @param keyId the key ID
     * @return a JWKS string containing the public key
     */
    public static String createJwks(Algorithm algorithm, String keyId) {
        RSAPublicKey publicKey = (RSAPublicKey) getPublicKey(algorithm, keyId);
        return createJwksFromRsaKey(publicKey, keyId, algorithm.getJwkAlgorithmName());
    }

    /**
     * Creates a JWKS string for the default key of the specified algorithm.
     *
     * @param algorithm the algorithm
     * @return a JWKS string containing the default public key
     */
    public static String createDefaultJwks(Algorithm algorithm) {
        return createJwks(algorithm, DEFAULT_KEY_ID);
    }

    /**
     * Creates a JWKS string for the default RS256 key.
     *
     * @return a JWKS string containing the default RS256 public key
     */
    public static String createDefaultJwks() {
        return createDefaultJwks(Algorithm.RS256);
    }

    /**
     * Creates a JWKS string from an RSA public key.
     *
     * @param publicKey the RSA public key
     * @param keyId the key ID
     * @param algorithm the algorithm name (e.g., "RS256")
     * @return a JWKS string
     */
    private static String createJwksFromRsaKey(RSAPublicKey publicKey, String keyId, String algorithm) {
        // Extract the modulus and exponent
        byte[] modulusBytes = publicKey.getModulus().toByteArray();
        byte[] exponentBytes = publicKey.getPublicExponent().toByteArray();

        // Remove leading zero byte if present (BigInteger sign bit)
        if (modulusBytes.length > 0 && modulusBytes[0] == 0) {
            byte[] tmp = new byte[modulusBytes.length - 1];
            System.arraycopy(modulusBytes, 1, tmp, 0, tmp.length);
            modulusBytes = tmp;
        }

        // Base64 URL encode
        String n = Base64.getUrlEncoder().withoutPadding().encodeToString(modulusBytes);
        String e = Base64.getUrlEncoder().withoutPadding().encodeToString(exponentBytes);

        // Create JWKS JSON with the specified key ID and algorithm
        return "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"%s\",\"n\":\"%s\",\"e\":\"%s\",\"alg\":\"%s\"}]}".formatted(
                keyId, n, e, algorithm);
    }

    /**
     * Creates a JwksLoader for the specified algorithm and key ID.
     *
     * @param algorithm the algorithm
     * @param keyId the key ID
     * @param securityEventCounter the security event counter
     * @return a JwksLoader instance
     */
    public static JwksLoader createJwksLoader(Algorithm algorithm, String keyId, SecurityEventCounter securityEventCounter) {
        String jwksContent = createJwks(algorithm, keyId);
        return JwksLoaderFactory.createInMemoryLoader(jwksContent, securityEventCounter);
    }

    /**
     * Creates a JwksLoader for the default key of the specified algorithm.
     *
     * @param algorithm the algorithm
     * @param securityEventCounter the security event counter
     * @return a JwksLoader instance
     */
    public static JwksLoader createDefaultJwksLoader(Algorithm algorithm, SecurityEventCounter securityEventCounter) {
        return createJwksLoader(algorithm, DEFAULT_KEY_ID, securityEventCounter);
    }

    /**
     * Creates a JwksLoader for the default RS256 key.
     *
     * @param securityEventCounter the security event counter
     * @return a JwksLoader instance
     */
    public static JwksLoader createDefaultJwksLoader(SecurityEventCounter securityEventCounter) {
        return createDefaultJwksLoader(Algorithm.RS256, securityEventCounter);
    }

    /**
     * Creates a JwksLoader for the default RS256 key with a new SecurityEventCounter.
     *
     * @return a JwksLoader instance
     */
    public static JwksLoader createDefaultJwksLoader() {
        return createDefaultJwksLoader(new SecurityEventCounter());
    }

    /**
     * Creates a multi-algorithm JWKS string containing keys for all supported algorithms.
     *
     * @return a JWKS string containing keys for all supported algorithms
     */
    public static String createMultiAlgorithmJwks() {
        StringBuilder jwksBuilder = new StringBuilder("{\"keys\":[");
        boolean first = true;

        for (Algorithm alg : Algorithm.values()) {
            RSAPublicKey publicKey = (RSAPublicKey) getDefaultPublicKey(alg);

            // Extract the modulus and exponent
            byte[] modulusBytes = publicKey.getModulus().toByteArray();
            byte[] exponentBytes = publicKey.getPublicExponent().toByteArray();

            // Remove leading zero byte if present (BigInteger sign bit)
            if (modulusBytes.length > 0 && modulusBytes[0] == 0) {
                byte[] tmp = new byte[modulusBytes.length - 1];
                System.arraycopy(modulusBytes, 1, tmp, 0, tmp.length);
                modulusBytes = tmp;
            }

            // Base64 URL encode
            String n = Base64.getUrlEncoder().withoutPadding().encodeToString(modulusBytes);
            String e = Base64.getUrlEncoder().withoutPadding().encodeToString(exponentBytes);

            // Create JWK JSON with the algorithm as key ID
            if (!first) {
                jwksBuilder.append(",");
            }
            jwksBuilder.append("{\"kty\":\"RSA\",\"kid\":\"").append(alg.name()).append("\",\"n\":\"")
                    .append(n).append("\",\"e\":\"").append(e).append("\",\"alg\":\"")
                    .append(alg.getJwkAlgorithmName()).append("\"}");
            first = false;
        }

        jwksBuilder.append("]}");
        return jwksBuilder.toString();
    }

    /**
     * Creates a JwksLoader containing keys for all supported algorithms.
     *
     * @param securityEventCounter the security event counter
     * @return a JwksLoader instance with keys for all supported algorithms
     */
    public static JwksLoader createMultiAlgorithmJwksLoader(@NonNull SecurityEventCounter securityEventCounter) {
        String jwksContent = createMultiAlgorithmJwks();
        return JwksLoaderFactory.createInMemoryLoader(jwksContent, securityEventCounter);
    }

    /**
     * Creates a JwksLoader containing keys for all supported algorithms with a new SecurityEventCounter.
     *
     * @return a JwksLoader instance with keys for all supported algorithms
     */
    public static JwksLoader createMultiAlgorithmJwksLoader() {
        return createMultiAlgorithmJwksLoader(new SecurityEventCounter());
    }
}
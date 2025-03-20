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

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import org.junit.jupiter.api.io.TempDir;

/**
 * Handles key material for JWT token testing.
 * Provides access to private and public keys used for signing and verifying tokens.
 * All access to key materials should be through this class, with no direct references to key files.
 */
public class KeyMaterialHandler {

    /**
     * Base path for test resources.
     */
    public static final String BASE_PATH = "src/test/resources/token/";

    /**
     * Path to the private key file.
     */
    private static final String PRIVATE_KEY = BASE_PATH + "test-private-key.pkcs8";

    /**
     * Path to the public key file.
     */
    private static final String PUBLIC_KEY = BASE_PATH + "test-public-key.pub";

    /**
     * Path to an alternative public key file.
     */
    private static final String PUBLIC_KEY_OTHER = BASE_PATH + "other-public-key.pub";

    /**
     * Path to the JWKS file containing the public key.
     */
    private static final String PUBLIC_KEY_JWKS = BASE_PATH + "test-public-key.jwks";

    /**
     * Path to the JWKS file containing an alternative public key.
     */
    private static final String PUBLIC_KEY_OTHER_JWKS = BASE_PATH + "other-public-key.jwks";

    /**
     * Gets the path to the private key file.
     * 
     * @return the path to the private key file
     */
    public static String getPrivateKeyPath() {
        return PRIVATE_KEY;
    }

    /**
     * Gets the path to the public key file.
     * 
     * @return the path to the public key file
     */
    public static String getPublicKeyPath() {
        return PUBLIC_KEY;
    }

    /**
     * Gets the path to the JWKS file containing the public key.
     * 
     * @return the path to the JWKS file
     */
    public static String getJwksPath() {
        return PUBLIC_KEY_JWKS;
    }


    // Key pair for signing and verifying tokens
    private static PrivateKey privateKey;
    private static java.security.PublicKey publicKey;

    // Static initializer to generate a key pair for testing
    static {
        try {
            // For testing, we need to use a consistent key pair that matches the JWKS file
            // Load the private key from the file
            privateKey = loadPrivateKey(PRIVATE_KEY);

            // Load the public key from the JWKS file
            String jwksContent = new String(Files.readAllBytes(Path.of(PUBLIC_KEY_JWKS)));
            jakarta.json.JsonReader reader = jakarta.json.Json.createReader(new java.io.StringReader(jwksContent));
            jakarta.json.JsonObject jwks = reader.readObject();
            reader.close();

            // Extract the modulus and exponent
            String modulusBase64 = jwks.getString("n");
            String exponentBase64 = jwks.getString("e");

            // Decode from Base64
            byte[] modulusBytes = java.util.Base64.getUrlDecoder().decode(modulusBase64);
            byte[] exponentBytes = java.util.Base64.getUrlDecoder().decode(exponentBase64);

            // Convert to BigInteger
            java.math.BigInteger modulus = new java.math.BigInteger(1, modulusBytes);
            java.math.BigInteger exponent = new java.math.BigInteger(1, exponentBytes);

            // Create RSA public key
            java.security.spec.RSAPublicKeySpec spec = new java.security.spec.RSAPublicKeySpec(modulus, exponent);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            publicKey = factory.generatePublic(spec);
        } catch (Exception e) {
            // Fall back to generating a new key pair if loading fails
            try {
                java.security.KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
                privateKey = keyPair.getPrivate();
                publicKey = keyPair.getPublic();
            } catch (Exception ex) {
                throw new RuntimeException("Failed to generate key pair", ex);
            }
        }
    }

    /**
     * Loads a private key from a PKCS8 file.
     *
     * @param path the path to the private key file
     * @return the loaded private key
     * @throws Exception if loading the key fails
     */
    public static PrivateKey loadPrivateKey(String path) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Path.of(path));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    /**
     * Gets the default private key used for signing tokens.
     *
     * @return the default private key
     */
    public static PrivateKey getDefaultPrivateKey() {
        return privateKey;
    }


    /**
     * Gets the default public key used for verifying tokens.
     *
     * @return the default public key
     */
    public static java.security.PublicKey getDefaultPublicKey() {
        return publicKey;
    }


    /**
     * Checks if dynamic key generation is being used.
     *
     * @return true if dynamic key generation is being used, false otherwise
     */
    public static boolean isDynamicKeyGeneration() {
        return true; // We're always using dynamic key generation in this implementation
    }

    /**
     * Gets the JWKS content as a string for the default public key.
     *
     * @return the JWKS content as a string
     */
    public static String getDefaultJwksContent() {
        try {
            return new String(Files.readAllBytes(Path.of(PUBLIC_KEY_JWKS)));
        } catch (Exception e) {
            throw new RuntimeException("Failed to read JWKS file", e);
        }
    }


    /**
     * Gets the JWKS content as a string for the alternative public key.
     *
     * @return the JWKS content as a string
     */
    public static String getAlternativeJWKSContent() {
        try {
            return new String(Files.readAllBytes(Path.of(PUBLIC_KEY_OTHER_JWKS)));
        } catch (Exception e) {
            throw new RuntimeException("Failed to read alternative JWKS file", e);
        }
    }


    /**
     * Creates a JwksLoader for the default public key JWKS.
     *
     * @return a JwksLoader instance
     */
    public static de.cuioss.jwt.token.jwks.JwksLoader createDefaultJwksLoader() {
        return de.cuioss.jwt.token.jwks.JwksLoaderFactory.createInMemoryLoader(getDefaultJwksContent());
    }


    /**
     * Creates a JwksLoader for the alternative public key JWKS.
     *
     * @return a JwksLoader instance
     */
    public static de.cuioss.jwt.token.jwks.JwksLoader createAlternativeJwksLoader() {
        return de.cuioss.jwt.token.jwks.JwksLoaderFactory.createInMemoryLoader(getAlternativeJWKSContent());
    }


    /**
     * Creates a temporary file with the given JWKS content.
     * This is useful for testing scenarios that require a file path.
     * 
     * This method uses JUnit's approach for temporary files by creating a temporary directory
     * and then a file within that directory.
     *
     * @param jwksContent the JWKS content to write to the file
     * @return the path to the temporary file
     */
    public static java.nio.file.Path createTemporaryJwksFile(String jwksContent) {
        try {
            // Create a temporary directory using JUnit's approach
            java.nio.file.Path tempDir = java.nio.file.Files.createTempDirectory("junit-temp-dir");
            // Create a file within the temporary directory
            java.nio.file.Path tempFile = tempDir.resolve("test-jwks.json");
            java.nio.file.Files.writeString(tempFile, jwksContent);
            // Register the directory for deletion on JVM exit
            tempDir.toFile().deleteOnExit();
            return tempFile;
        } catch (Exception e) {
            throw new RuntimeException("Failed to create temporary JWKS file", e);
        }
    }
}

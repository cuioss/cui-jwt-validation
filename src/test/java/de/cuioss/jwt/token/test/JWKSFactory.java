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

import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

/**
 * Factory for creating JWKS (JSON Web Key Set) content for testing purposes.
 * <p>
 * This class centralizes the creation of JWKS content that was previously
 * scattered across multiple test classes.
 * <p>
 * It provides methods to create various types of JWKS content:
 * <ul>
 *   <li>Valid JWKS with a single key</li>
 *   <li>Valid JWKS with multiple keys</li>
 *   <li>JWKS with missing required fields</li>
 *   <li>JWKS with unsupported key types</li>
 *   <li>Invalid JWKS format</li>
 *   <li>Empty JWKS</li>
 *   <li>JWKS with a specific key ID</li>
 *   <li>JWKS with no key ID (default key ID)</li>
 *   <li>JWKS from64EncodedContent a specific RSA key pair</li>
 * </ul>
 */
public class JWKSFactory {

    /**
     * Default key ID used when no key ID is specified.
     */
    public static final String DEFAULT_KEY_ID = "default-key-id";

    /**
     * Alternative key ID used in most test cases.
     */
    public static final String ALTERNATIVE_KEY_ID = "test-key-id";

    /**
     * Creates a valid JWKS with a single key using the default key from64EncodedContent KeyMaterialHandler.
     *
     * @return a valid JWKS JSON string
     */
    public static String createDefaultJwks() {
        return createValidJwksWithKeyId(DEFAULT_KEY_ID);
    }

    /**
     * Creates a valid JWKS with a single key using the default key from64EncodedContent KeyMaterialHandler
     * and the specified key ID.
     *
     * @param keyId the key ID to use
     * @return a valid JWKS JSON string
     */
    public static String createValidJwksWithKeyId(String keyId) {
        RSAPublicKey publicKey = (RSAPublicKey) KeyMaterialHandler.getDefaultPublicKey();
        return createJwksFromRsaKey(publicKey, keyId);
    }

    /**
     * Creates a valid JWKS with a single key using the specified RSA public key.
     *
     * @param publicKey the RSA public key to use
     * @param keyId     the key ID to use
     * @return a valid JWKS JSON string
     */
    public static String createJwksFromRsaKey(RSAPublicKey publicKey, String keyId) {
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

        // Create JWKS JSON with the specified key ID
        return "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"%s\",\"n\":\"%s\",\"e\":\"%s\",\"alg\":\"RS256\"}]}".formatted(
                keyId, n, e);
    }

    /**
     * Creates a valid single JWK (not in a keys array) using the default key from64EncodedContent KeyMaterialHandler.
     *
     * @param keyId the key ID to use
     * @return a valid JWK JSON string
     */
    public static String createSingleJwk(String keyId) {
        RSAPublicKey publicKey = (RSAPublicKey) KeyMaterialHandler.getDefaultPublicKey();

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

        // Create JWK JSON with the specified key ID
        return "{\"kty\":\"RSA\",\"kid\":\"%s\",\"n\":\"%s\",\"e\":\"%s\",\"alg\":\"RS256\"}".formatted(
                keyId, n, e);
    }

    /**
     * Creates a JWKS with a key that has missing required fields.
     *
     * @param keyId the key ID to use
     * @return a JWKS JSON string with missing required fields
     */
    public static String createJwksWithMissingFields(String keyId) {
        return "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"%s\"}]}".formatted(
                keyId);
    }

    /**
     * Creates an empty JWKS with no keys.
     *
     * @return an empty JWKS JSON string
     */
    public static String createEmptyJwks() {
        return "{\"keys\": []}";
    }

    /**
     * Creates an invalid JSON string that is not a valid JWKS.
     *
     * @return an invalid JSON string
     */
    public static String createInvalidJson() {
        return "invalid json";
    }

}

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

import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.MoreStrings;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;

import java.io.StringReader;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static de.cuioss.jwt.token.PortalTokenLogMessages.WARN;

/**
 * Utility class for parsing JWKS content and extracting keys.
 *
 * @author Oliver Wolff
 */
public class JwksParser {

    private static final CuiLogger LOGGER = new CuiLogger(JwksParser.class);

    /**
     * Parse JWKS content and extract keys.
     *
     * @param jwksContent the JWKS content as a string
     * @return a map of key IDs to keys
     */
    public Map<String, Key> parseJwks(String jwksContent) {
        Map<String, Key> result = new ConcurrentHashMap<>();

        try (JsonReader reader = Json.createReader(new StringReader(jwksContent))) {
            JsonObject jwks = reader.readObject();

            // Check if this is a JWKS with a "keys" array or a single key
            if (jwks.containsKey("keys")) {
                // This is a standard JWKS with a "keys" array
                JsonArray keysArray = jwks.getJsonArray("keys");
                if (keysArray != null) {
                    for (int i = 0; i < keysArray.size(); i++) {
                        JsonObject jwk = keysArray.getJsonObject(i);
                        processKey(jwk, result);
                    }
                }
            } else if (jwks.containsKey("kty")) {
                // This is a single key object
                processKey(jwks, result);
            } else {
                LOGGER.warn("JWKS JSON does not contain 'keys' array or 'kty' field");
            }
        } catch (Exception e) {
            // Handle invalid JSON format
            LOGGER.warn(e, WARN.JWKS_JSON_PARSE_FAILED.format(e.getMessage()));
            // Return empty map to clear existing keys
            return result;
        }

        return result;
    }

    private void processKey(JsonObject jwk, Map<String, Key> result) {
        try {
            String kty = jwk.getString("kty");

            // Generate a key ID if not present
            String kid = jwk.containsKey("kid") ? jwk.getString("kid") : "default-key-id";

            if ("RSA".equals(kty)) {
                try {
                    Key publicKey = parseRsaKey(jwk);
                    result.put(kid, publicKey);
                    LOGGER.debug("Parsed RSA key with ID: %s", kid);
                } catch (Exception e) {
                    LOGGER.warn(e, WARN.RSA_KEY_PARSE_FAILED.format(kid, e.getMessage()));
                }
            } else {
                LOGGER.debug("Unsupported key type: %s for key ID: %s", kty, kid);
            }
        } catch (Exception e) {
            LOGGER.warn(e, "Failed to process key: %s", e.getMessage());
        }
    }

    private Key parseRsaKey(JsonObject jwk) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Check if required fields exist
        if (!jwk.containsKey("n") || !jwk.containsKey("e")) {
            throw new InvalidKeySpecException("JWK is missing required fields 'n' or 'e'");
        }

        // Get the modulus and exponent
        String modulusBase64 = jwk.getString("n");
        String exponentBase64 = jwk.getString("e");

        // Validate Base64 format
        if (!isValidBase64UrlEncoded(modulusBase64) || !isValidBase64UrlEncoded(exponentBase64)) {
            throw new InvalidKeySpecException("Invalid Base64 URL encoded values for 'n' or 'e'");
        }

        // Decode from Base64
        byte[] modulusBytes = Base64.getUrlDecoder().decode(modulusBase64);
        byte[] exponentBytes = Base64.getUrlDecoder().decode(exponentBase64);

        // Convert to BigInteger
        BigInteger modulus = new BigInteger(1, modulusBytes);
        BigInteger exponent = new BigInteger(1, exponentBytes);

        // Create RSA public key
        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(spec);
    }

    /**
     * Validates if a string is a valid Base64 URL encoded value.
     *
     * @param value the string to validate
     * @return true if the string is a valid Base64 URL encoded value, false otherwise
     */
    private boolean isValidBase64UrlEncoded(String value) {
        if (MoreStrings.isEmpty(value)) {
            return false;
        }

        // Base64 URL encoded strings should only contain alphanumeric characters, '-', '_', and '='
        return value.matches("^[A-Za-z0-9\\-_]*=*$");
    }
}
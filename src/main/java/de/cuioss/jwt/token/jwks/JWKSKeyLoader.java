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
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.ToString;

import java.io.StringReader;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

import static de.cuioss.jwt.token.JWTTokenLogMessages.WARN;

/**
 * Implementation of {@link JwksLoader} that loads JWKS from a string content.
 * <p>
 * This implementation is useful when the JWKS content is already available as a string.
 * 
 * @author Oliver Wolff
 */
@ToString
@EqualsAndHashCode
public class JWKSKeyLoader implements JwksLoader {

    private static final CuiLogger LOGGER = new CuiLogger(JWKSKeyLoader.class);
    private static final String RSA_KEY_TYPE = "RSA";
    private static final Pattern BASE64_URL_PATTERN = Pattern.compile("^[A-Za-z0-9\\-_]*=*$");

    private final Map<String, Key> keyMap;

    /**
     * Creates a new JWKSKeyLoader with the specified JWKS content.
     *
     * @param jwksContent the JWKS content as a string, must not be null
     */
    public JWKSKeyLoader(@NonNull String jwksContent) {
        keyMap = parseJwks(jwksContent);
    }

    /**
     * Parse JWKS content and extract keys.
     *
     * @param jwksContent the JWKS content as a string
     * @return a map of key IDs to keys
     */
    private Map<String, Key> parseJwks(String jwksContent) {
        Map<String, Key> result = new ConcurrentHashMap<>();

        try (JsonReader reader = Json.createReader(new StringReader(jwksContent))) {
            JsonObject jwks = reader.readObject();
            parseJsonWebKeySet(jwks, result);
        } catch (Exception e) {
            // Handle invalid JSON format
            LOGGER.warn(e, WARN.JWKS_JSON_PARSE_FAILED.format(e.getMessage()));
        }

        return result;
    }

    /**
     * Parse a JSON Web Key Set object and extract keys.
     *
     * @param jwks the JSON Web Key Set object
     * @param result the map to store the extracted keys
     */
    private void parseJsonWebKeySet(JsonObject jwks, Map<String, Key> result) {
        // Check if this is a JWKS with a "keys" array or a single key
        if (jwks.containsKey("keys")) {
            parseStandardJwks(jwks, result);
        } else if (jwks.containsKey("kty")) {
            // This is a single key object
            processKey(jwks, result);
        } else {
            LOGGER.warn("JWKS JSON does not contain 'keys' array or 'kty' field");
        }
    }

    /**
     * Parse a standard JWKS with a "keys" array.
     *
     * @param jwks the JWKS object
     * @param result the map to store the extracted keys
     */
    private void parseStandardJwks(JsonObject jwks, Map<String, Key> result) {
        JsonArray keysArray = jwks.getJsonArray("keys");
        if (keysArray != null) {
            for (int i = 0; i < keysArray.size(); i++) {
                JsonObject jwk = keysArray.getJsonObject(i);
                processKey(jwk, result);
            }
        }
    }

    private void processKey(JsonObject jwk, Map<String, Key> result) {
        if (!jwk.containsKey("kty")) {
            LOGGER.warn("JWK is missing required field 'kty'");
            return;
        }

        String kty = jwk.getString("kty");

        // Generate a key ID if not present
        String kid = jwk.containsKey("kid") ? jwk.getString("kid") : "default-key-id";

        if (RSA_KEY_TYPE.equals(kty)) {
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
    }

    private Key parseRsaKey(JsonObject jwk) throws NoSuchAlgorithmException, InvalidKeySpecException {
        validateRsaKeyFields(jwk);

        // Get the modulus and exponent
        String modulusBase64 = jwk.getString("n");
        String exponentBase64 = jwk.getString("e");

        // Decode from Base64
        byte[] modulusBytes = Base64.getUrlDecoder().decode(modulusBase64);
        byte[] exponentBytes = Base64.getUrlDecoder().decode(exponentBase64);

        // Convert to BigInteger
        BigInteger modulus = new BigInteger(1, modulusBytes);
        BigInteger exponent = new BigInteger(1, exponentBytes);

        // Create RSA public key
        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory factory = KeyFactory.getInstance(RSA_KEY_TYPE);
        return factory.generatePublic(spec);
    }

    /**
     * Validates that the RSA key has all required fields and that they are properly formatted.
     *
     * @param jwk the JWK object
     * @throws InvalidKeySpecException if the JWK is missing required fields or has invalid values
     */
    private void validateRsaKeyFields(JsonObject jwk) throws InvalidKeySpecException {
        // Check if required fields exist
        if (!jwk.containsKey("n") || !jwk.containsKey("e")) {
            throw new InvalidKeySpecException("JWK is missing required fields 'n' or 'e'");
        }

        // Get the modulus and exponent
        String modulusBase64 = jwk.getString("n");
        String exponentBase64 = jwk.getString("e");

        // Validate Base64 format
        if (!isValidBase64UrlEncoded(modulusBase64)) {
            throw new InvalidKeySpecException("Invalid Base64 URL encoded value for 'n'");
        }

        if (!isValidBase64UrlEncoded(exponentBase64)) {
            throw new InvalidKeySpecException("Invalid Base64 URL encoded value for 'e'");
        }
    }

    /**
     * Validates if a string is a valid Base64 URL encoded value.
     *
     * @param value the string to validate
     * @return true if the string is a valid Base64 URL encoded value, false otherwise
     */
    private boolean isValidBase64UrlEncoded(String value) {
        return !MoreStrings.isEmpty(value) && BASE64_URL_PATTERN.matcher(value).matches();
    }

    @Override
    public Optional<Key> getKey(String kid) {
        if (MoreStrings.isBlank(kid)) {
            LOGGER.debug("Key ID is null or empty");
            return Optional.empty();
        }

        return Optional.ofNullable(keyMap.get(kid));
    }

    @Override
    public Optional<Key> getFirstKey() {
        if (keyMap.isEmpty()) {
            return Optional.empty();
        }
        // Return the first key in the map
        return Optional.of(keyMap.values().iterator().next());
    }

    @Override
    public Set<String> keySet() {
        return keyMap.keySet();
    }
}

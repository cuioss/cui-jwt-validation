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
package de.cuioss.jwt.token.util;

import de.cuioss.jwt.token.PortalTokenLogMessages;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.MoreStrings;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

/**
 * Utility class for inspecting JWT token content without signature validation.
 * This parser is designed for preliminary token analysis to extract claims and metadata
 * before full validation, particularly useful in multi-issuer scenarios.
 * <p>
 * Security features:
 * <ul>
 *   <li>Token size validation (max 16KB) to prevent memory exhaustion</li>
 *   <li>Payload size validation (max 16KB) for JSON parsing</li>
 *   <li>Standard Base64 decoding for JWT parts</li>
 *   <li>Proper character encoding handling</li>
 * </ul>
 * <p>
 * Important security note: This parser does NOT validate token signatures.
 * It should only be used for:
 * <ul>
 *   <li>Extracting issuer information to select the appropriate validator</li>
 *   <li>Preliminary token inspection and debugging</li>
 *   <li>Token format validation</li>
 * </ul>
 * <p>
 * Usage example:
 * <pre>
 * NonValidatingJwtParser parser = new NonValidatingJwtParser();
 * Optional&lt;String&gt; issuer = parser.extractIssuer(tokenString);
 * issuer.ifPresent(iss -> {
 *     // Use issuer to select appropriate validator
 * });
 * </pre>
 *
 * @author Oliver Wolff
 */
@ToString
@EqualsAndHashCode
public class NonValidatingJwtParser {

    private static final CuiLogger LOGGER = new CuiLogger(NonValidatingJwtParser.class);

    /**
     * Maximum size of a JWT token in bytes to prevent overflow attacks.
     * 16KB should be more than enough for any reasonable JWT token.
     */
    private static final int MAX_TOKEN_SIZE = 16 * 1024;

    /**
     * Maximum size of decoded JSON payload in bytes.
     * 16KB should be more than enough for any reasonable JWT claims.
     */
    private static final int MAX_PAYLOAD_SIZE = 16 * 1024;

    /**
     * Extracts the issuer from a JWT token without validating its signature.
     * <p>
     * Security considerations:
     * <ul>
     *   <li>Does not validate signatures - use only for inspection</li>
     *   <li>Implements size checks to prevent overflow attacks</li>
     *   <li>Uses standard Java Base64 decoder</li>
     * </ul>
     *
     * @param token the JWT token string to parse, must not be null
     * @return an Optional containing the issuer if parsing is successful,
     * or empty if the token is invalid or cannot be parsed
     */
    public Optional<String> extractIssuer(String token) {
        if (MoreStrings.isEmpty(token)) {
            LOGGER.debug("Token is empty or null");
            return Optional.empty();
        }

        if (token.getBytes(StandardCharsets.UTF_8).length > MAX_TOKEN_SIZE) {
            LOGGER.warn(PortalTokenLogMessages.WARN.TOKEN_SIZE_EXCEEDED.format(MAX_TOKEN_SIZE));
            return Optional.empty();
        }

        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            LOGGER.debug("Invalid JWT token format: expected 3 parts but got %s", parts.length);
            return Optional.empty();
        }

        try {
            // Decode the payload (second part)
            byte[] decoded = Base64.getUrlDecoder().decode(parts[1]);

            if (decoded.length > MAX_PAYLOAD_SIZE) {
                LOGGER.debug("Decoded payload exceeds maximum size limit of %s bytes", MAX_PAYLOAD_SIZE);
                return Optional.empty();
            }

            // Parse the payload as JSON
            JsonObject payload;
            try (JsonReader reader = Json.createReader(new StringReader(new String(decoded, StandardCharsets.UTF_8)))) {
                payload = reader.readObject();
            }

            // Extract the issuer claim
            if (payload.containsKey("iss")) {
                String issuer = payload.getString("iss");
                LOGGER.debug("Extracted issuer: %s", issuer);
                return Optional.of(issuer);
            } else {
                LOGGER.debug("No issuer claim found in token");
                return Optional.empty();
            }
        } catch (Exception e) {
            LOGGER.debug(e, "Failed to parse token: %s", e.getMessage());
            return Optional.empty();
        }
    }
}
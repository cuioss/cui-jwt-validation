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

import de.cuioss.jwt.token.JWTTokenLogMessages;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.MoreStrings;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

/**
 * Utility class for parsing JWT tokens and extracting common information from them.
 * This class provides a unified way to parse JWT tokens and extract common information
 * such as the header, body, signature, issuer, and kid-header.
 * <p>
 * Security features:
 * <ul>
 *   <li>Token size validation to prevent memory exhaustion</li>
 *   <li>Payload size validation for JSON parsing</li>
 *   <li>Standard Base64 decoding for JWT parts</li>
 *   <li>Proper character encoding handling</li>
 * </ul>
 * <p>
 * Usage example:
 * <pre>
 * NonValidatingJwtParser parser = NonValidatingJwtParser.builder().build();
 * Optional&lt;NonValidatingJwtParser.DecodedJwt&gt; decodedJwt = parser.decode(tokenString);
 * decodedJwt.ifPresent(jwt -> {
 *     // Access decoded JWT information
 *     jwt.getHeader().ifPresent(header -> System.out.println("Header: " + header));
 *     jwt.getBody().ifPresent(body -> System.out.println("Body: " + body));
 *     jwt.getIssuer().ifPresent(issuer -> System.out.println("Issuer: " + issuer));
 *     jwt.getKid().ifPresent(kid -> System.out.println("Kid: " + kid));
 * });
 * </pre>
 *
 * @author Oliver Wolff
 */
@ToString
@EqualsAndHashCode
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class NonValidatingJwtParser {

    private static final CuiLogger LOGGER = new CuiLogger(NonValidatingJwtParser.class);

    /**
     * Default maximum size of a JWT token in bytes to prevent overflow attacks.
     * 16KB should be more than enough for any reasonable JWT token.
     */
    public static final int DEFAULT_MAX_TOKEN_SIZE = 16 * 1024;

    /**
     * Default maximum size of decoded JSON payload in bytes.
     * 16KB should be more than enough for any reasonable JWT claims.
     */
    public static final int DEFAULT_MAX_PAYLOAD_SIZE = 16 * 1024;

    /**
     * Maximum size of a JWT token in bytes to prevent overflow attacks.
     */
    @Builder.Default
    private final int maxTokenSize = DEFAULT_MAX_TOKEN_SIZE;

    /**
     * Maximum size of decoded JSON payload in bytes.
     */
    @Builder.Default
    private final int maxPayloadSize = DEFAULT_MAX_PAYLOAD_SIZE;

    /**
     * Decodes a JWT token and returns a DecodedJwt object containing the decoded parts.
     * <p>
     * Security considerations:
     * <ul>
     *   <li>Does not validate signatures - use only for inspection</li>
     *   <li>Implements size checks to prevent overflow attacks</li>
     *   <li>Uses standard Java Base64 decoder</li>
     * </ul>
     *
     * @param token the JWT token string to parse
     * @return an Optional containing the DecodedJwt if parsing is successful,
     * or empty if the token is invalid or cannot be parsed
     */
    public Optional<DecodedJwt> decode(String token) {
        if (MoreStrings.isEmpty(token)) {
            LOGGER.warn(JWTTokenLogMessages.WARN.TOKEN_IS_EMPTY::format);
            return Optional.empty();
        }

        if (token.getBytes(StandardCharsets.UTF_8).length > maxTokenSize) {
            LOGGER.warn(JWTTokenLogMessages.WARN.TOKEN_SIZE_EXCEEDED.format(maxTokenSize));
            return Optional.empty();
        }

        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            LOGGER.warn("Invalid JWT token format: expected 3 parts but got %s", parts.length);
            return Optional.empty();
        }

        try {
            // Decode the header (first part)
            Optional<JsonObject> headerOpt = decodeJsonPart(parts[0]);
            if (headerOpt.isEmpty()) {
                LOGGER.warn("Failed to decode header part");
                return Optional.empty();
            }

            // Decode the payload (second part)
            Optional<JsonObject> bodyOpt = decodeJsonPart(parts[1]);
            if (bodyOpt.isEmpty()) {
                LOGGER.warn("Failed to decode payload part");
                return Optional.empty();
            }

            // The signature part (third part) is kept as is
            String signature = parts[2];

            return Optional.of(new DecodedJwt(headerOpt.get(), bodyOpt.get(), signature, parts, token));
        } catch (Exception e) {
            LOGGER.warn(e, "Failed to parse token: %s", e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Decodes a Base64Url encoded JSON part of a JWT token.
     *
     * @param encodedPart the Base64Url encoded part
     * @return an Optional containing the decoded JsonObject, or empty if decoding fails
     */
    private Optional<JsonObject> decodeJsonPart(String encodedPart) {
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(encodedPart);

            if (decoded.length > maxPayloadSize) {
                LOGGER.warn("Decoded part exceeds maximum size limit of %s bytes", maxPayloadSize);
                return Optional.empty();
            }

            // Parse the part as JSON
            try (JsonReader reader = Json.createReader(new StringReader(new String(decoded, StandardCharsets.UTF_8)))) {
                return Optional.of(reader.readObject());
            }
        } catch (Exception e) {
            LOGGER.warn(e, "Failed to decode part: %s", e.getMessage());
            return Optional.empty();
        }
    }

}

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
package de.cuioss.jwt.validation.flow;

import de.cuioss.jwt.validation.JWTValidationLogMessages;
import de.cuioss.jwt.validation.ParserConfig;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.MoreStrings;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

/**
 * This class provides a unified way to parse JWT tokens and extract common information
 * such as the header, body, signature, issuer, and kid-header.
 * <p>
 * Security features:
 * <ul>
 *   <li>Token size validation to prevent memory exhaustion</li>
 *   <li>Payload size validation for JSON parsing</li>
 *   <li>Standard Base64 decoding for JWT parts</li>
 *   <li>Proper character encoding handling</li>
 *   <li>JSON depth limits to prevent stack overflow attacks</li>
 *   <li>JSON array size limits to prevent denial of service attacks</li>
 *   <li>JSON string size limits to prevent memory exhaustion</li>
 * </ul>
 * <p>
 * Basic usage example:
 * <pre>
 * // Create a parser with default settings
 * NonValidatingJwtParser parser = NonValidatingJwtParser.builder().build();
 *
 * // Decode a JWT validation
 * Optional&lt;DecodedJwt&gt; decodedJwt = parser.decode(tokenString);
 *
 * // Access decoded JWT information
 * decodedJwt.ifPresent(jwt -> {
 *     // Access header information
 *     jwt.getHeader().ifPresent(header -> {
 *         String algorithm = header.getString("alg");
 *         String tokenType = header.getString("typ");
 *     });
 *
 *     // Access payload information
 *     jwt.getBody().ifPresent(body -> {
 *         String subject = body.getString("sub");
 *         String issuer = body.getString("iss");
 *         int expirationTime = body.getInt("exp");
 *     });
 *
 *     // Access common JWT fields with convenience methods
 *     jwt.getIssuer().ifPresent(issuer -> System.out.println("Issuer: " + issuer));
 *     jwt.getKid().ifPresent(kid -> System.out.println("Key ID: " + kid));
 *
 *     // Get the raw validation
 *     String rawToken = jwt.getRawToken();
 * });
 * </pre>
 * <p>
 * Example with custom security settings:
 * <pre>
 * // Create a parser with custom security settings using ParserConfig
 * ParserConfig config = ParserConfig.builder()
 *     .maxTokenSize(1024)  // 1KB max validation size
 *     .maxPayloadSize(512)  // 512 bytes max payload size
 *     .maxStringSize(256)   // 256 bytes max string size
 *     .maxArraySize(10)     // 10 elements max array size
 *     .maxDepth(5)          // 5 levels max JSON depth
 *     .logWarningsOnDecodeFailure(false)  // suppress warnings
 *     .build();
 *
 * NonValidatingJwtParser customParser = NonValidatingJwtParser.builder()
 *     .config(config)
 *     .build();
 *
 * // Decode a validation with the custom parser
 * Optional&lt;DecodedJwt&gt; result = customParser.decode(tokenString);
 * </pre>
 * <p>
 * Example handling empty or invalid tokens:
 * <pre>
 * // Handle empty or null tokens
 * Optional&lt;DecodedJwt&gt; emptyResult = parser.decode("");
 * assertFalse(emptyResult.isPresent());
 *
 * // Handle invalid validation format
 * Optional&lt;DecodedJwt&gt; invalidResult = parser.decode("invalid.validation.format");
 * assertFalse(invalidResult.isPresent());
 * </pre>
 * <p>
 * Implements requirements: {@code CUI-JWT-8.1: Token Size Limits} and {@code CUI-JWT-8.2: Safe Parsing}
 * <p>
 * For more details on the security aspects, see the
 * <a href="../../../../../../../doc/specification/security.adoc">Security Specification</a>.
 *
 * @author Oliver Wolff
 * @since 1.0
 */
@ToString
@EqualsAndHashCode
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class NonValidatingJwtParser {

    /**
     * Builder for configuring NonValidatingJwtParser with specific security settings.
     * <p>
     * You can use this builder to configure the parser with specific security settings:
     * <pre>
     * // Using ParserConfig
     * ParserConfig config = ParserConfig.builder()
     *     .maxTokenSize(16 * 1024)  // 16KB
     *     .maxPayloadSize(8 * 1024)  // 8KB
     *     .logWarningsOnDecodeFailure(false)  // suppress warnings
     *     .build();
     *
     * NonValidatingJwtParser parser = NonValidatingJwtParser.builder()
     *     .config(config)
     *     .build();
     * </pre>
     */
    @SuppressWarnings("java:S2094") // owolff: Suppressing SonarLint warning for builder class. Needed for javadoc
    public static class NonValidatingJwtParserBuilder {
        // Content generated by Lombok
    }

    private static final CuiLogger LOGGER = new CuiLogger(NonValidatingJwtParser.class);

    // No individual fields needed as they are all in the config object

    /**
     * Configuration for the parser, containing all security settings.
     */
    @Builder.Default
    private final ParserConfig config = ParserConfig.builder().build();

    /**
     * Counter for security events that occur during validation processing.
     */
    @NonNull
    private final SecurityEventCounter securityEventCounter;

    /**
     * Decodes a JWT validation and returns a DecodedJwt object containing the decoded parts.
     * <p>
     * Security considerations:
     * <ul>
     *   <li>Does not validate signatures - use only for inspection</li>
     *   <li>Implements size checks to prevent overflow attacks</li>
     *   <li>Uses standard Java Base64 decoder</li>
     * </ul>
     *
     * @param token the JWT validation string to parse
     * @return an Optional containing the DecodedJwt if parsing is successful,
     * or empty if the validation is invalid or cannot be parsed
     */
    public Optional<DecodedJwt> decode(String token) {
        return decode(token, config.isLogWarningsOnDecodeFailure());
    }

    /**
     * Decodes a JWT validation and returns a DecodedJwt object containing the decoded parts.
     * <p>
     * Security considerations:
     * <ul>
     *   <li>Does not validate signatures - use only for inspection</li>
     *   <li>Implements size checks to prevent overflow attacks</li>
     *   <li>Uses standard Java Base64 decoder</li>
     * </ul>
     * <p>
     * This method allows controlling whether warnings are logged when decoding fails.
     * This is useful when checking if a validation is a JWT without logging warnings.
     *
     * @param token       the JWT validation string to parse
     * @param logWarnings whether to log warnings when decoding fails
     * @return an Optional containing the DecodedJwt if parsing is successful,
     * or empty if the validation is invalid or cannot be parsed
     */
    public Optional<DecodedJwt> decode(String token, boolean logWarnings) {
        // Check if validation is empty
        if (isTokenEmpty(token, logWarnings)) {
            return Optional.empty();
        }

        // Check if validation size exceeds maximum
        if (isTokenSizeExceeded(token, logWarnings)) {
            return Optional.empty();
        }

        // Split validation and validate format
        String[] parts = token.split("\\.");
        if (isInvalidTokenFormat(parts, logWarnings)) {
            return Optional.empty();
        }

        try {
            // Decode validation parts
            return decodeTokenParts(parts, token, logWarnings);
        } catch (Exception e) {
            if (logWarnings) {
                LOGGER.warn(e, JWTValidationLogMessages.WARN.FAILED_TO_DECODE_JWT.format());
            }
            securityEventCounter.increment(SecurityEventCounter.EventType.FAILED_TO_DECODE_JWT);
            return Optional.empty();
        }
    }

    /**
     * Checks if the validation is empty.
     *
     * @param token       the validation to check
     * @param logWarnings whether to log warnings
     * @return true if the validation is empty, false otherwise
     */
    private boolean isTokenEmpty(String token, boolean logWarnings) {
        if (MoreStrings.isEmpty(token)) {
            if (logWarnings) {
                LOGGER.warn(JWTValidationLogMessages.WARN.TOKEN_IS_EMPTY::format);
            }
            securityEventCounter.increment(SecurityEventCounter.EventType.TOKEN_EMPTY);
            return true;
        }
        return false;
    }

    /**
     * Checks if the validation size exceeds the maximum allowed size.
     *
     * @param token       the validation to check
     * @param logWarnings whether to log warnings
     * @return true if the validation size exceeds the maximum, false otherwise
     */
    private boolean isTokenSizeExceeded(String token, boolean logWarnings) {
        if (token.getBytes(StandardCharsets.UTF_8).length > config.getMaxTokenSize()) {
            if (logWarnings) {
                LOGGER.warn(JWTValidationLogMessages.WARN.TOKEN_SIZE_EXCEEDED.format(config.getMaxTokenSize()));
            }
            securityEventCounter.increment(SecurityEventCounter.EventType.TOKEN_SIZE_EXCEEDED);
            return true;
        }
        return false;
    }

    /**
     * Checks if the validation format is invalid.
     *
     * @param parts       the validation parts
     * @param logWarnings whether to log warnings
     * @return true if the validation format is invalid, false otherwise
     */
    private boolean isInvalidTokenFormat(String[] parts, boolean logWarnings) {
        if (parts.length != 3) {
            if (logWarnings) {
                LOGGER.warn(JWTValidationLogMessages.WARN.INVALID_JWT_FORMAT.format(parts.length));
            }
            securityEventCounter.increment(SecurityEventCounter.EventType.INVALID_JWT_FORMAT);
            return true;
        }
        return false;
    }

    /**
     * Decodes the validation parts and creates a DecodedJwt object.
     *
     * @param parts       the validation parts
     * @param token       the original validation
     * @param logWarnings whether to log warnings
     * @return an Optional containing the DecodedJwt if decoding is successful, or empty otherwise
     */
    private Optional<DecodedJwt> decodeTokenParts(String[] parts, String token, boolean logWarnings) {
        // Decode the header (first part)
        Optional<JsonObject> headerOpt = decodeJsonPart(parts[0], logWarnings);
        if (headerOpt.isEmpty()) {
            if (logWarnings) {
                LOGGER.warn(JWTValidationLogMessages.WARN.FAILED_TO_DECODE_HEADER::format);
            }
            securityEventCounter.increment(SecurityEventCounter.EventType.FAILED_TO_DECODE_HEADER);
            return Optional.empty();
        }

        // Decode the payload (second part)
        Optional<JsonObject> bodyOpt = decodeJsonPart(parts[1], logWarnings);
        if (bodyOpt.isEmpty()) {
            if (logWarnings) {
                LOGGER.warn(JWTValidationLogMessages.WARN.FAILED_TO_DECODE_PAYLOAD::format);
            }
            securityEventCounter.increment(SecurityEventCounter.EventType.FAILED_TO_DECODE_PAYLOAD);
            return Optional.empty();
        }

        // The signature part (third part) is kept as is
        String signature = parts[2];

        return Optional.of(new DecodedJwt(headerOpt.get(), bodyOpt.get(), signature, parts, token));
    }

    /**
     * Decodes a Base64Url encoded JSON part of a JWT validation.
     * Implements security measures to prevent JSON parsing attacks:
     * - JSON depth limits
     * - JSON object size limits
     * - Protection against duplicate keys
     *
     * @param encodedPart the Base64Url encoded part
     * @param logWarnings whether to log warnings when decoding fails
     * @return an Optional containing the decoded JsonObject, or empty if decoding fails
     */
    private Optional<JsonObject> decodeJsonPart(String encodedPart, boolean logWarnings) {
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(encodedPart);

            if (decoded.length > config.getMaxPayloadSize()) {
                if (logWarnings) {
                    LOGGER.warn(JWTValidationLogMessages.WARN.DECODED_PART_SIZE_EXCEEDED.format(config.getMaxPayloadSize()));
                }
                securityEventCounter.increment(SecurityEventCounter.EventType.DECODED_PART_SIZE_EXCEEDED);
                return Optional.empty();
            }

            // Use the cached JsonReaderFactory with security settings
            try (JsonReader reader = config.getJsonReaderFactory()
                    .createReader(new StringReader(new String(decoded, StandardCharsets.UTF_8)))) {
                return Optional.of(reader.readObject());
            }
        } catch (Exception e) {
            if (logWarnings) {
                LOGGER.warn(e, JWTValidationLogMessages.WARN.FAILED_TO_DECODE_JWT.format());
            }
            securityEventCounter.increment(SecurityEventCounter.EventType.FAILED_TO_DECODE_JWT);
            return Optional.empty();
        }
    }

}

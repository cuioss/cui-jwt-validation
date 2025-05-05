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
package de.cuioss.jwt.validation;

import de.cuioss.tools.logging.LogRecord;
import de.cuioss.tools.logging.LogRecordModel;
import lombok.experimental.UtilityClass;

/**
 * Provides logging messages for the cui-jwt-validation module.
 * All messages follow the format: JWTValidation-[identifier]: [message]
 *
 * @since 1.0
 */
@UtilityClass
public final class JWTValidationLogMessages {

    private static final String PREFIX = "JWTValidation";

    /**
     * Contains debug-level log messages for informational and diagnostic purposes.
     * These messages are typically used for tracing program pipeline and providing
     * detailed information about normal operations.
     */
    @UtilityClass
    public static final class DEBUG {
        public static final LogRecord SSL_CONTEXT_PROTOCOL = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(500)
                .template("Provided SSL context uses protocol: %s")
                .build();

        public static final LogRecord USING_SSL_CONTEXT = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(501)
                .template("Using provided SSL context with protocol: %s")
                .build();

        public static final LogRecord CREATED_SECURE_CONTEXT = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(502)
                .template("Created secure SSL context with %s")
                .build();

        public static final LogRecord NO_SSL_CONTEXT = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(503)
                .template("No SSL context provided, created secure SSL context with %s")
                .build();

        public static final LogRecord INITIALIZED_JWKS_LOADER = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(504)
                .template("Initialized HttpJwksLoader with URL: %s, refresh interval: %s seconds")
                .build();

        public static final LogRecord RESOLVING_KEY_LOADER = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(505)
                .template("Resolving key loader for JWKS endpoint: %s")
                .build();

        public static final LogRecord REFRESHING_KEYS = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(506)
                .template("Refreshing keys from JWKS endpoint: %s")
                .build();

        public static final LogRecord FETCHED_JWKS = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(507)
                .template("Successfully fetched JWKS from URL: %s")
                .build();

        public static final LogRecord KEY_ID_EMPTY = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(508)
                .template("Key ID is null or empty")
                .build();

        public static final LogRecord KEY_NOT_FOUND_REFRESHING = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(509)
                .template("Key with ID %s not found, refreshing keys")
                .build();

        public static final LogRecord RECEIVED_304_NOT_MODIFIED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(510)
                .template("Received 304 Not Modified response, using cached JWKS")
                .build();

        public static final LogRecord CONTENT_UNCHANGED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(511)
                .template("JWKS content unchanged, using existing key loader")
                .build();

        // Token creation success events
        public static final LogRecord ACCESS_TOKEN_CREATED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(512)
                .template("Successfully created access token")
                .build();

        public static final LogRecord ID_TOKEN_CREATED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(513)
                .template("Successfully created ID-Token")
                .build();

        public static final LogRecord REFRESH_TOKEN_CREATED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(514)
                .template("Successfully created Refresh-Token")
                .build();

    }

    /**
     * Contains error-level log messages for significant problems that require attention.
     * These messages indicate failures that impact functionality but don't necessarily
     * prevent the application from continuing to run.
     */
    @UtilityClass
    public static final class ERROR {
        public static final LogRecord SIGNATURE_VALIDATION_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(201)
                .template("Failed to validate validation signature: %s")
                .build();
    }

    /**
     * Contains info-level log messages for general operational information.
     * These messages provide high-level information about the normal operation
     * of the application that is useful for monitoring.
     */
    @UtilityClass
    public static final class INFO {
        public static final LogRecord TOKEN_FACTORY_INITIALIZED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(1)
                .template("TokenValidator initialized with %s issuer configurations")
                .build();

        public static final LogRecord JWKS_LOADED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(2)
                .template("Successfully loaded and parsed JWKS from %s with %s keys")
                .build();
    }

    /**
     * Contains warning-level log messages for potential issues that don't prevent
     * normal operation but may indicate problems. These messages highlight situations
     * that should be monitored or addressed to prevent future errors.
     */
    @UtilityClass
    public static final class WARN {

        public static final LogRecord FALLBACK_TO_LAST_VALID_JWKS_EMPTY = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(129)
                .template("New JWKS response has no valid keys, falling back to previous valid keys")
                .build();

        public static final LogRecord FALLBACK_TO_LAST_VALID_JWKS_EXCEPTION = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(130)
                .template("Falling back to last valid JWKS due to exception: %s")
                .build();

        public static final LogRecord TOKEN_SIZE_EXCEEDED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(100)
                .template("Token exceeds maximum size limit of %s bytes, validation will be rejected")
                .build();

        public static final LogRecord TOKEN_IS_EMPTY = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(101)
                .template("The given validation was empty, request will be rejected")
                .build();


        public static final LogRecord KEY_NOT_FOUND = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(103)
                .template("No key found with ID: %s")
                .build();

        public static final LogRecord ISSUER_MISMATCH = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(104)
                .template("Token issuer '%s' does not match expected issuer '%s'")
                .build();

        public static final LogRecord JWKS_FETCH_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(105)
                .template("Failed to fetch JWKS: HTTP %s")
                .build();

        public static final LogRecord JWKS_REFRESH_ERROR = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(106)
                .template("Error refreshing JWKS: %s")
                .build();

        public static final LogRecord RSA_KEY_PARSE_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(107)
                .template("Failed to parse RSA key with ID %s: %s")
                .build();

        public static final LogRecord JWKS_JSON_PARSE_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(108)
                .template("Failed to parse JWKS JSON: %s")
                .build();

        public static final LogRecord FAILED_TO_DECODE_JWT = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(109)
                .template("Failed to decode JWT Token")
                .build();


        public static final LogRecord INVALID_JWT_FORMAT = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(112)
                .template("Invalid JWT Token format: expected 3 parts but got %s")
                .build();

        public static final LogRecord FAILED_TO_DECODE_HEADER = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(113)
                .template("Failed to decode header part")
                .build();

        public static final LogRecord FAILED_TO_DECODE_PAYLOAD = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(114)
                .template("Failed to decode payload part")
                .build();


        public static final LogRecord DECODED_PART_SIZE_EXCEEDED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(116)
                .template("Decoded part exceeds maximum size limit of %s bytes")
                .build();


        public static final LogRecord FAILED_TO_FETCH_JWKS = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(118)
                .template("Failed to fetch JWKS from URL: %s")
                .build();

        public static final LogRecord UNSUPPORTED_ALGORITHM = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(119)
                .template("Unsupported algorithm: %s")
                .build();


        public static final LogRecord JWKS_MISSING_KEYS = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(122)
                .template("JWKS JSON does not contain 'keys' array or 'kty' field")
                .build();

        public static final LogRecord JWK_MISSING_KTY = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(123)
                .template("JWK is missing required field 'kty'")
                .build();

        public static final LogRecord TOKEN_NBF_FUTURE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(124)
                .template("Token has a 'not before' claim that is more than 60 seconds in the future")
                .build();

        public static final LogRecord UNKNOWN_TOKEN_TYPE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(125)
                .template("Unknown validation type: %s")
                .build();

        public static final LogRecord FAILED_TO_READ_JWKS_FILE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(126)
                .template("Failed to read JWKS from file: %s")
                .build();

        public static final LogRecord MISSING_CLAIM = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(127)
                .template("Token is missing required claim: %s")
                .build();

        public static final LogRecord TOKEN_EXPIRED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(134)
                .template("Token has expired")
                .build();

        public static final LogRecord INSECURE_SSL_PROTOCOL = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(135)
                .template("Provided SSL context uses insecure protocol: %s. Creating a secure context instead.")
                .build();


        public static final LogRecord AZP_MISMATCH = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(137)
                .template("Token authorized party '%s' does not match expected client ID '%s'")
                .build();

        public static final LogRecord MISSING_RECOMMENDED_ELEMENT = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(138)
                .template("Missing recommended element: %s")
                .build();

        public static final LogRecord AUDIENCE_MISMATCH = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(139)
                .template("Token audience %s does not match any of the expected audiences %s")
                .build();

        public static final LogRecord NO_ISSUER_CONFIG = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(140)
                .template("No configuration found for issuer: %s")
                .build();

        public static final LogRecord INVALID_BASE64_CONTENT = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(141)
                .template("Given contentKey '%s' does not resolve to a non base64 encoded String, actual content = %s")
                .build();

        public static final LogRecord ALGORITHM_REJECTED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(142)
                .template("Algorithm %s is explicitly rejected for security reasons")
                .build();

        public static final LogRecord KEY_ROTATION_DETECTED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(143)
                .template("Key rotation detected: JWKS content has changed")
                .build();
    }

}

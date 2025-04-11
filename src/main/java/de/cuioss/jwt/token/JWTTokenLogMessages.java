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
package de.cuioss.jwt.token;

import de.cuioss.tools.logging.LogRecord;
import de.cuioss.tools.logging.LogRecordModel;
import lombok.experimental.UtilityClass;

/**
 * Provides logging messages for the cui-jwt-token-handling module.
 * All messages follow the format: JWTToken-[identifier]: [message]
 */
@UtilityClass
public final class JWTTokenLogMessages {

    private static final String PREFIX = "JWTToken";

    @UtilityClass
    public static final class DEBUG {
        public static final LogRecord SSL_CONTEXT_PROTOCOL = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(1)
                .template("Provided SSL context uses protocol: %s")
                .build();

        public static final LogRecord USING_SSL_CONTEXT = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(2)
                .template("Using provided SSL context with protocol: %s")
                .build();

        public static final LogRecord CREATED_SECURE_CONTEXT = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(3)
                .template("Created secure SSL context with %s")
                .build();

        public static final LogRecord NO_SSL_CONTEXT = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(4)
                .template("No SSL context provided, created secure SSL context with %s")
                .build();

        public static final LogRecord FALLBACK_SSL_CONTEXT = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(5)
                .template("Falling back to provided SSL context")
                .build();

        public static final LogRecord DEFAULT_SSL_CONTEXT = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(6)
                .template("Using default SSL context from64EncodedContent VM configuration")
                .build();

        public static final LogRecord INITIALIZED_JWKS_LOADER = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(7)
                .template("Initialized HttpJwksLoader with URL: %s, refresh interval: %s seconds")
                .build();

        public static final LogRecord RESOLVING_KEY_LOADER = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(8)
                .template("Resolving key loader for JWKS endpoint: %s")
                .build();

        public static final LogRecord REFRESHING_KEYS = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(9)
                .template("Refreshing keys from64EncodedContent JWKS endpoint: %s")
                .build();

        public static final LogRecord FETCHED_JWKS = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(10)
                .template("Successfully fetched JWKS from64EncodedContent URL: %s")
                .build();

        public static final LogRecord KEY_ID_EMPTY = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(11)
                .template("Key ID is null or empty")
                .build();

        public static final LogRecord KEY_NOT_FOUND_REFRESHING = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(12)
                .template("Key with ID %s not found, refreshing keys")
                .build();

        public static final LogRecord RECEIVED_304_NOT_MODIFIED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(13)
                .template("Received 304 Not Modified response, using cached JWKS")
                .build();

        public static final LogRecord CONTENT_UNCHANGED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(14)
                .template("JWKS content unchanged, using existing key loader")
                .build();

        public static final LogRecord ADDING_IF_NONE_MATCH_HEADER = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(15)
                .template("Adding If-None-Match header: %s")
                .build();

    }

    @UtilityClass
    public static final class ERROR {
        public static final LogRecord CLAIMS_VALIDATION_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(200)
                .template("ClaimNames validation failed: %s")
                .build();
    }

    @UtilityClass
    public static final class INFO {
        public static final LogRecord CONFIGURED_JWKS = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(1)
                .template("Initializing JWKS lookup, jwks-endpoint='%s', refresh-interval='%s', issuer='%s'")
                .build();
    }

    @UtilityClass
    public static final class WARN {
        public static final LogRecord FALLBACK_TO_LAST_VALID_JWKS_HTTP_ERROR = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(128)
                .template("Falling back to last valid JWKS due to HTTP error: %s")
                .build();

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

        public static final LogRecord FALLBACK_TO_LAST_VALID_JWKS_INTERRUPTED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(131)
                .template("Falling back to last valid JWKS due to interrupted exception")
                .build();

        public static final LogRecord TOKEN_SIZE_EXCEEDED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(100)
                .template("Token exceeds maximum size limit of %s bytes, token will be rejected")
                .build();

        public static final LogRecord TOKEN_IS_EMPTY = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(101)
                .template("The given token was empty, request will be rejected")
                .build();

        public static final LogRecord COULD_NOT_PARSE_TOKEN = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(102)
                .template("Unable to parse token due to ParseException: %s")
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
                .template("Failed to decode JWT token")
                .build();

        public static final LogRecord NO_KEYS_AVAILABLE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(110)
                .template("No keys available in JWKS")
                .build();

        public static final LogRecord ERROR_PARSING_TOKEN = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(111)
                .template("Error parsing token: %s")
                .build();

        public static final LogRecord INVALID_JWT_FORMAT = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(112)
                .template("Invalid JWT token format: expected 3 parts but got %s")
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

        public static final LogRecord FAILED_TO_PARSE_TOKEN = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(115)
                .template("Failed to parse token: %s")
                .build();

        public static final LogRecord DECODED_PART_SIZE_EXCEEDED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(116)
                .template("Decoded part exceeds maximum size limit of %s bytes")
                .build();

        public static final LogRecord FAILED_TO_DECODE_PART = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(117)
                .template("Failed to decode part: %s")
                .build();

        public static final LogRecord FAILED_TO_FETCH_JWKS = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(118)
                .template("Failed to fetch JWKS from64EncodedContent URL: %s")
                .build();

        public static final LogRecord UNSUPPORTED_ALGORITHM = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(119)
                .template("Unsupported algorithm: %s")
                .build();

        public static final LogRecord NO_SUPPORTED_ALGORITHM = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(120)
                .template("No supported algorithm available")
                .build();

        public static final LogRecord NO_KEY_FOR_ALGORITHM = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(121)
                .template("No key available for algorithm: %s")
                .build();

        public static final LogRecord JWKS_MISSING_KEYS = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(122)
                .template("JWKS JSON does not contain 'keys' array or 'kty' field")
                .build();

        public static final LogRecord JWK_MISSING_KTY = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(120)
                .template("JWK is missing required field 'kty'")
                .build();

        public static final LogRecord TOKEN_NBF_FUTURE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(121)
                .template("Token has a 'not before' claim that is more than 60 seconds in the future")
                .build();

        public static final LogRecord UNKNOWN_TOKEN_TYPE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(122)
                .template("Unknown token type: %s")
                .build();

        public static final LogRecord FAILED_TO_READ_JWKS_FILE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(123)
                .template("Failed to read JWKS from64EncodedContent file: %s")
                .build();

        public static final LogRecord MISSING_CLAIM = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(124)
                .template("Token is missing required claim: %s")
                .build();

        public static final LogRecord TOKEN_EXPIRED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(125)
                .template("Token from64EncodedContent issuer '%s' has expired")
                .build();

        public static final LogRecord INSECURE_SSL_PROTOCOL = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(126)
                .template("Provided SSL context uses insecure protocol: %s. Creating a secure context instead.")
                .build();

        public static final LogRecord SSL_CONTEXT_CONFIG_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(127)
                .template("Failed to configure secure SSL context: %s")
                .build();

        public static final LogRecord AZP_MISMATCH = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(132)
                .template("Token authorized party '%s' does not match expected client ID '%s'")
                .build();

        public static final LogRecord MISSING_RECOMMENDED_ELEMENT = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(133)
                .template("Missing recommended element: %s")
                .build();
    }

}

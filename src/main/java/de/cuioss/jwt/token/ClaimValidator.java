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

import de.cuioss.tools.logging.CuiLogger;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

import java.time.Instant;
import java.util.*;

import static de.cuioss.jwt.token.JWTTokenLogMessages.WARN;

/**
 * Validator for JWT claims as defined in RFC 7519.
 * <p>
 * This class validates the following required claims:
 * <ul>
 *   <li>Issuer (iss)</li>
 *   <li>Subject (sub)</li>
 *   <li>Expiration Time (exp)</li>
 *   <li>Issued At (iat)</li>
 *   <li>Audience (aud) - if expected audience is provided</li>
 * </ul>
 * <p>
 * The validator logs appropriate warning messages for validation failures.
 * <p>
 * Implements requirement: {@code CUI-JWT-8.4: Claims Validation}
 * <p>
 * For more details on the security aspects, see the
 * <a href="../../../../../../doc/specification/security.adoc">Security Specification</a>.
 */
class ClaimValidator {

    private static final CuiLogger LOGGER = new CuiLogger(ClaimValidator.class);

    private final String expectedIssuer;
    private final Set<String> expectedAudience;

    /**
     * Creates a new ClaimValidator with the specified issuer.
     *
     * @param expectedIssuer the expected issuer
     */
    ClaimValidator(String expectedIssuer) {
        this(expectedIssuer, null);
    }

    /**
     * Creates a new ClaimValidator with the specified issuer and audience.
     *
     * @param expectedIssuer the expected issuer
     * @param expectedAudience the expected audience, may be null if no audience validation is required
     */
    ClaimValidator(String expectedIssuer, Set<String> expectedAudience) {
        this.expectedIssuer = expectedIssuer;
        this.expectedAudience = expectedAudience != null ?
                Collections.unmodifiableSet(new HashSet<>(expectedAudience)) : null;
    }

    /**
     * Validates all required claims in the JWT.
     *
     * @param jws the parsed JWT with claims
     * @return true if all required claims are valid, false otherwise
     */
    boolean validateClaims(Jws<Claims> jws) {
        LOGGER.debug("Validating claims");

        try {
            Claims claims = jws.getBody();

            // Validate issuer
            if (!validateIssuer(claims)) {
                return false;
            }

            // Validate subject
            if (!validateSubject(claims)) {
                return false;
            }

            // Validate expiration time
            if (!validateExpiration(claims)) {
                return false;
            }

            // Validate issued at time
            if (!validateIssuedAt(claims)) {
                return false;
            }

            // Validate not before time
            if (!validateNotBefore(claims)) {
                return false;
            }

            // Validate audience if expected audience is provided
            return expectedAudience == null || validateAudience(claims);
        } catch (Exception e) {
            LOGGER.error(e, JWTTokenLogMessages.ERROR.CLAIMS_VALIDATION_FAILED.format(e.getMessage()));
            return false;
        }
    }

    /**
     * Validates the audience claim.
     * <p>
     * The "aud" (audience) claim identifies the recipients that the JWT is intended for.
     * If the expected audience is provided, this method checks if the token's audience claim
     * contains at least one of the expected audience values.
     * <p>
     * If the audience claim is missing but expected audience is provided, the validation fails.
     *
     * @param claims the JWT claims
     * @return true if the audience is valid or no audience validation is required, false otherwise
     */
    private boolean validateAudience(Claims claims) {
        // If no expected audience is provided, skip validation
        if (expectedAudience == null || expectedAudience.isEmpty()) {
            return true;
        }

        // Get the audience claim
        Object audienceObj = claims.get("aud");
        if (audienceObj == null) {
            LOGGER.warn(WARN.MISSING_CLAIM.format("aud"));
            return false;
        }

        // Handle different audience formats (string or array)
        Set<String> tokenAudience = new HashSet<>();
        if (audienceObj instanceof String string) {
            tokenAudience.add(string);
        } else if (audienceObj instanceof List) {
            @SuppressWarnings("unchecked")
            List<String> audienceList = (List<String>) audienceObj;
            tokenAudience.addAll(audienceList);
        } else {
            LOGGER.warn("Unexpected audience claim format: {}", audienceObj.getClass().getName());
            return false;
        }

        // Check if there's at least one matching audience
        for (String audience : expectedAudience) {
            if (tokenAudience.contains(audience)) {
                return true;
            }
        }

        LOGGER.warn("Token audience {} does not match any of the expected audiences {}",
                tokenAudience, expectedAudience);
        return false;
    }

    /**
     * Validates the issuer claim.
     *
     * @param claims the JWT claims
     * @return true if the issuer is valid, false otherwise
     */
    private boolean validateIssuer(Claims claims) {
        String tokenIssuer = claims.getIssuer();
        if (tokenIssuer == null) {
            LOGGER.warn(WARN.MISSING_CLAIM.format("iss"));
            return false;
        }

        if (!expectedIssuer.equals(tokenIssuer)) {
            LOGGER.warn(WARN.ISSUER_MISMATCH.format(tokenIssuer, expectedIssuer));
            return false;
        }

        return true;
    }

    /**
     * Validates the subject claim.
     *
     * @param claims the JWT claims
     * @return true if the subject is valid, false otherwise
     */
    private boolean validateSubject(Claims claims) {
        if (claims.getSubject() == null) {
            LOGGER.warn(WARN.MISSING_CLAIM.format("sub"));
            return false;
        }
        return true;
    }

    /**
     * Validates the expiration time claim.
     *
     * @param claims the JWT claims
     * @return true if the expiration time is valid, false otherwise
     */
    private boolean validateExpiration(Claims claims) {
        Date expiration = claims.getExpiration();
        if (expiration == null) {
            LOGGER.warn(WARN.MISSING_CLAIM.format("exp"));
            return false;
        }

        if (expiration.before(new Date())) {
            LOGGER.warn(WARN.TOKEN_EXPIRED.format(claims.getIssuer()));
            return false;
        }

        return true;
    }

    /**
     * Validates the issued at time claim.
     *
     * @param claims the JWT claims
     * @return true if the issued at time is valid, false otherwise
     */
    private boolean validateIssuedAt(Claims claims) {
        if (claims.getIssuedAt() == null) {
            LOGGER.warn(WARN.MISSING_CLAIM.format("iat"));
            return false;
        }
        return true;
    }

    /**
     * Validates the "not before time" claim.
     * <p>
     * The "nbf" (not before) claim identifies the time before which the JWT must not be accepted for processing.
     * This claim is optional, so if it's not present, the validation passes.
     * <p>
     * If the claim is present, this method checks if the token's not-before time is more than 60 seconds
     * in the future.
     * If it is, the token is considered invalid.
     *
     * @param claims the JWT claims
     * @return true if "the not before" time is valid or not present, false otherwise
     */
    private boolean validateNotBefore(Claims claims) {
        Date notBefore = claims.getNotBefore();
        if (notBefore == null) {
            // Not before claim is optional, so if it's not present, validation passes
            return true;
        }

        // Check if the token has a "not before" claim that is more than 60 seconds in the future
        long currentTime = Instant.now().getEpochSecond();
        long notBeforeTime = notBefore.getTime() / 1000; // Convert milliseconds to seconds

        if (notBeforeTime > currentTime + 60) {
            LOGGER.warn(WARN.TOKEN_NBF_FUTURE::format);
            return false;
        }

        return true;
    }
}

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
package de.cuioss.jwt.validation.pipeline;

import de.cuioss.jwt.validation.IssuerConfig;
import de.cuioss.jwt.validation.JWTValidationLogMessages;
import de.cuioss.jwt.validation.TokenType;
import de.cuioss.jwt.validation.domain.claim.ClaimName;
import de.cuioss.jwt.validation.domain.claim.ClaimValue;
import de.cuioss.jwt.validation.domain.claim.ClaimValueType;
import de.cuioss.jwt.validation.domain.token.TokenContent;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.tools.collect.MoreCollections;
import de.cuioss.tools.logging.CuiLogger;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.stream.Collectors;

/**
 * Validator for JWT claims as defined in RFC 7519.
 * <p>
 * This class validates the following mandatory claims:
 * <ul>
 *   <li>Subject (sub)</li>
 *   <li>Expiration Time (exp)</li>
 *   <li>Issued At (iat)</li>
 *   <li>Not Before (nbf) - if present</li>
 *   <li>Audience (aud) - if expected audience is provided</li>
 *   <li>Authorized Party (azp) - if expected client ID is provided</li>
 * </ul>
 * <p>
 * The validator logs appropriate warning messages for validation failures.
 * <p>
 * The azp claim validation is an important security measure to prevent client confusion attacks
 * where tokens issued for one client are used with a different client.
 * <p>
 * For more details on the security aspects, see the
 * <a href="https://github.com/cuioss/cui-jwt-validation/tree/main/doc/specification/security.adoc">Security Specification</a>
 * <p>
 * Note: Issuer (iss) validation is handled by {@link TokenHeaderValidator}.
 *
 * @author Oliver Wolff
 * @since 1.0
 */
@Builder
public class TokenClaimValidator {

    private static final CuiLogger LOGGER = new CuiLogger(TokenClaimValidator.class);
    public static final String AUDIENCE_MATCHES_EXPECTED_AUDIENCE_S = "Token audience matches expected audience: %s";

    @Getter
    private final Set<String> expectedAudience;

    @Getter
    private final Set<String> expectedClientId;

    @NonNull
    private final SecurityEventCounter securityEventCounter;

    /**
     * Constructs a TokenClaimValidator with the specified IssuerConfig.
     *
     * @param issuerConfig the issuer configuration containing expected audience and client ID
     * @param securityEventCounter the counter for security events
     */
    public TokenClaimValidator(@NonNull IssuerConfig issuerConfig, @NonNull SecurityEventCounter securityEventCounter) {
        this(issuerConfig.getExpectedAudience(), issuerConfig.getExpectedClientId(), securityEventCounter);
    }


    /**
     * Constructs a TokenClaimValidator with the specified expected audience and client ID.
     * This constructor is used by the Builder.
     *
     * @param expectedAudience the expected audience values
     * @param expectedClientId the expected client ID values
     * @param securityEventCounter the counter for security events
     */
    public TokenClaimValidator(Set<String> expectedAudience, Set<String> expectedClientId, @NonNull SecurityEventCounter securityEventCounter) {
        this.expectedAudience = expectedAudience;
        this.expectedClientId = expectedClientId;
        this.securityEventCounter = securityEventCounter;

        if (MoreCollections.isEmpty(expectedAudience)) {
            LOGGER.warn(JWTValidationLogMessages.WARN.MISSING_RECOMMENDED_ELEMENT.format("expectedAudience"));
            securityEventCounter.increment(SecurityEventCounter.EventType.MISSING_RECOMMENDED_ELEMENT);
        }

        if (MoreCollections.isEmpty(expectedClientId)) {
            LOGGER.warn(JWTValidationLogMessages.WARN.MISSING_RECOMMENDED_ELEMENT.format("azp claim validation (expectedClientId)"));
            securityEventCounter.increment(SecurityEventCounter.EventType.MISSING_RECOMMENDED_ELEMENT);
        }
    }

    /**
     * Validates a validation against expected values for issuer, audience, and client ID.
     *
     * @param token the validation to validate
     * @return An Optional containing the validated validation if all validations pass, or empty if any validation fails
     */
    public Optional<TokenContent> validate(@NonNull TokenContent token) {
        LOGGER.trace("Validating validation: %s", token);
        if (!validateMandatoryClaims(token)) {
            return Optional.empty();
        }
        if (!validateAudience(token)) {
            return Optional.empty();
        }
        if (!validateAuthorizedParty(token)) {
            return Optional.empty();
        }
        if (!validateNotBefore(token)) {
            return Optional.empty();
        }
        if (!validateNotExpired(token)) {
            return Optional.empty();
        }
        LOGGER.debug("Token is valid");
        return Optional.of(token);
    }

    /**
     * Validates the "not before time" claim.
     * <p>
     * The "nbf" (not before) claim identifies the time before which the JWT must not be accepted for processing.
     * This claim is optional, so if it's not present, the validation passes.
     * <p>
     * If the claim is present, this method checks if the validation's not-before time is more than 60 seconds
     * in the future. This 60-second window allows for clock skew between the validation issuer and the validation validator.
     * If the not-before time is more than 60 seconds in the future, the validation is considered invalid.
     * If the not-before time is in the past or less than 60 seconds in the future, the validation is considered valid.
     *
     * @param token the JWT claims
     * @return true if the "not before" time is valid or not present, false otherwise
     */
    private boolean validateNotBefore(TokenContent token) {
        var notBefore = token.getNotBefore();
        if (notBefore.isEmpty()) {
            LOGGER.debug("Not before claim is optional, so if it's not present, validation passes");
            return true;
        }

        if (notBefore.get().isAfter(OffsetDateTime.now().plusSeconds(60))) {
            LOGGER.warn(JWTValidationLogMessages.WARN.TOKEN_NBF_FUTURE::format);
            securityEventCounter.increment(SecurityEventCounter.EventType.TOKEN_NBF_FUTURE);
            return false;
        }
        LOGGER.debug("Not before claim is present, and not more than 60 seconds in the future");
        return true;
    }

    private boolean validateNotExpired(TokenContent token) {
        LOGGER.debug("validate expiration. Can be done directly, because ", token);
        if (token.isExpired()) {
            LOGGER.warn(JWTValidationLogMessages.WARN.TOKEN_EXPIRED::format);
            securityEventCounter.increment(SecurityEventCounter.EventType.TOKEN_EXPIRED);
            return false;
        }
        LOGGER.debug("Token is not expired");
        return true;
    }

    /**
     * Validates whether all mandatory claims for the current toke-type are present and set.
     *
     * @return a boolean indicating If the validation is valid regarding mandatory claims.
     */
    private boolean validateMandatoryClaims(TokenContent tokenContent) {
        var mandatoryNames = tokenContent.getTokenType().getMandatoryClaims().stream().map(ClaimName::getName).collect(Collectors.toSet());
        LOGGER.debug("%s, verifying mandatory claims: %s", tokenContent.getTokenType(), mandatoryNames);
        SortedSet<String> missingClaims = new TreeSet<>();
        for (var claimName : mandatoryNames) {
            if (!tokenContent.getClaims().containsKey(claimName)) {
                missingClaims.add(claimName);
            } else {
                ClaimValue claimValue = tokenContent.getClaims().get(claimName);
                if (!claimValue.isPresent()) {
                    LOGGER.debug("Claim %s is present but not set as expected: %s", claimName, claimValue);
                    missingClaims.add(claimName);
                }
            }
        }
        if (!missingClaims.isEmpty()) {
            LOGGER.warn(JWTValidationLogMessages.WARN.MISSING_CLAIM.format(missingClaims));
            securityEventCounter.increment(SecurityEventCounter.EventType.MISSING_CLAIM);
        } else {
            LOGGER.debug("All mandatory claims are present and set as expected");
        }
        return missingClaims.isEmpty();
    }


    /**
     * Validates that the validation's audience contains at least one of the expected audiences.
     * Audience claim is optional for access tokens, so if it's not present, validation passes for AccessTokens.
     * <p>
     * This method is optimized to avoid unnecessary Set creation and iteration for common cases:
     * - Early return if no expected audience is configured
     * - Special handling for STRING type audience claims (common case)
     * - Fallback to azp claim if audience is missing
     * - Different validation rules for ID tokens vs. access tokens
     * - Optimized iteration strategy based on collection sizes
     *
     * @param token the validation to validate
     * @return true if the audience is valid, false otherwise
     */
    private boolean validateAudience(TokenContent token) {
        // Fast path: Skip validation if no expected audience is configured
        if (expectedAudience.isEmpty()) {
            LOGGER.debug("no expected audience is provided, skip validation");
            return true;
        }

        var audienceClaim = token.getClaimOption(ClaimName.AUDIENCE);

        // Handle missing or empty audience claim
        if (audienceClaim.isEmpty() || audienceClaim.get().isNotPresentForClaimValueType()) {
            return handleMissingAudience(token);
        }

        return validateAudienceClaim(audienceClaim.get());
    }

    /**
     * Handles the case when the audience claim is missing or empty.
     * Tries to use azp claim as fallback and applies different rules for ID tokens vs. access tokens.
     *
     * @param token the validation to validate
     * @return true if the validation passes, false otherwise
     */
    private boolean handleMissingAudience(TokenContent token) {
        // Try to use azp claim as fallback (optimization for common test case)
        if (isAzpClaimMatchingExpectedAudience(token)) {
            return true;
        }

        // ID tokens require audience, access tokens don't
        if (TokenType.ID_TOKEN.equals(token.getTokenType())) {
            LOGGER.warn(JWTValidationLogMessages.WARN.MISSING_CLAIM.format(ClaimName.AUDIENCE.getName()));
            return false;
        } else {
            LOGGER.debug("Audience claim is optional for access tokens, so if it's not present, validation passes");
            return true;
        }
    }

    /**
     * Checks if the azp claim matches any of the expected audiences.
     *
     * @param token the validation to validate
     * @return true if the azp claim matches any expected audience, false otherwise
     */
    private boolean isAzpClaimMatchingExpectedAudience(TokenContent token) {
        var azpClaim = token.getClaimOption(ClaimName.AUTHORIZED_PARTY);
        if (azpClaim.isPresent() && !azpClaim.get().isEmpty()) {
            String azp = azpClaim.get().getOriginalString();
            if (expectedAudience.contains(azp)) {
                LOGGER.debug("Audience claim is missing but azp claim matches expected audience: %s", azp);
                return true;
            }
        }
        return false;
    }

    /**
     * Validates the audience claim based on its type.
     *
     * @param claim the audience claim to validate
     * @return true if the validation passes, false otherwise
     */
    private boolean validateAudienceClaim(ClaimValue claim) {
        if (claim.getType() == ClaimValueType.STRING_LIST) {
            return validateStringListAudience(claim.getAsList());
        } else if (claim.getType() == ClaimValueType.STRING) {
            return validateStringAudience(claim.getOriginalString());
        }

        // Fallback for unexpected claim type
        LOGGER.warn(JWTValidationLogMessages.WARN.AUDIENCE_MISMATCH.format(claim.getOriginalString(), expectedAudience));
        return false;
    }

    /**
     * Validates a string list audience claim.
     * Uses an optimized iteration strategy based on collection sizes.
     *
     * @param audienceList the list of audiences from the validation
     * @return true if any audience matches, false otherwise
     */
    private boolean validateStringListAudience(List<String> audienceList) {
        // Optimization: Iterate through the smaller collection to minimize comparisons
        if (expectedAudience.size() < audienceList.size()) {
            // If expected audience is smaller, check if any expected audience is in the token audience
            for (String audience : expectedAudience) {
                if (audienceList.contains(audience)) {
                    LOGGER.debug(AUDIENCE_MATCHES_EXPECTED_AUDIENCE_S, audience);
                    return true;
                }
            }
        } else {
            // If validation audience is smaller or equal, check if any validation audience is in the expected audience
            for (String audience : audienceList) {
                if (expectedAudience.contains(audience)) {
                    LOGGER.debug(AUDIENCE_MATCHES_EXPECTED_AUDIENCE_S, audience);
                    return true;
                }
            }
        }

        LOGGER.warn(JWTValidationLogMessages.WARN.AUDIENCE_MISMATCH.format(audienceList, expectedAudience));
        securityEventCounter.increment(SecurityEventCounter.EventType.AUDIENCE_MISMATCH);
        return false;
    }

    /**
     * Validates a string audience claim.
     *
     * @param singleAudience the audience from the validation
     * @return true if the audience matches any expected audience, false otherwise
     */
    private boolean validateStringAudience(String singleAudience) {
        if (expectedAudience.contains(singleAudience)) {
            LOGGER.debug(AUDIENCE_MATCHES_EXPECTED_AUDIENCE_S, singleAudience);
            return true;
        }

        LOGGER.warn(JWTValidationLogMessages.WARN.AUDIENCE_MISMATCH.format(singleAudience, expectedAudience));
        securityEventCounter.increment(SecurityEventCounter.EventType.AUDIENCE_MISMATCH);
        return false;
    }

    /**
     * Validates the authorized party claim.
     * <p>
     * The "azp" (authorized party) claim identifies the client that the validation was issued for.
     * This claim is used to prevent client confusion attacks where tokens issued for one client
     * are used with a different client.
     * <p>
     * If the expected client ID is provided, this method checks if the validation's azp claim
     * matches the expected client ID.
     * <p>
     * If the azp claim is missing but expected client ID is provided, the validation fails.
     *
     * @param token the JWT claims
     * @return true, if the authorized party is valid or no client ID-Token is required, false otherwise
     */
    private boolean validateAuthorizedParty(TokenContent token) {
        // If no expected client ID is provided, skip validation
        if (expectedClientId.isEmpty()) {
            LOGGER.debug("No expectedClientId configured to check against");
            return true;
        }
        var azpObj = token.getClaimOption(ClaimName.AUTHORIZED_PARTY);
        if (azpObj.isEmpty() || azpObj.get().isEmpty()) {
            LOGGER.warn(JWTValidationLogMessages.WARN.MISSING_CLAIM.format(ClaimName.AUTHORIZED_PARTY.getName()));
            securityEventCounter.increment(SecurityEventCounter.EventType.MISSING_CLAIM);
            return false;
        }

        String azp = azpObj.get().getOriginalString();
        if (!expectedClientId.contains(azp)) {
            LOGGER.warn(JWTValidationLogMessages.WARN.AZP_MISMATCH.format(azp, expectedClientId));
            securityEventCounter.increment(SecurityEventCounter.EventType.AZP_MISMATCH);
            return false;
        }
        LOGGER.debug("Successfully validated authorized party: %s", azp);
        return true;
    }

}

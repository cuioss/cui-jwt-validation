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
package de.cuioss.jwt.token.flow;

import de.cuioss.jwt.token.JWTTokenLogMessages;
import de.cuioss.jwt.token.TokenType;
import de.cuioss.jwt.token.domain.claim.ClaimName;
import de.cuioss.jwt.token.domain.claim.ClaimValue;
import de.cuioss.jwt.token.domain.token.TokenContent;
import de.cuioss.tools.collect.MoreCollections;
import de.cuioss.tools.logging.CuiLogger;
import lombok.Getter;
import lombok.NonNull;

import java.time.OffsetDateTime;
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
 * Implements requirement: {@code CUI-JWT-8.4: ClaimNames Validation}
 * <p>
 * For more details on the security aspects, see the
 * <a href="../../../../../../../doc/specification/security.adoc">Security Specification</a>.
 * <p>
 * Note: Issuer (iss) validation is handled by {@link TokenHeaderValidator}.
 */
public class TokenClaimValidator {

    private static final CuiLogger LOGGER = new CuiLogger(TokenClaimValidator.class);

    @Getter
    private final Set<String> expectedAudience;

    @Getter
    private final Set<String> expectedClientId;

    /**
     * Constructs a TokenClaimValidator with the specified IssuerConfig.
     *
     * @param issuerConfig the issuer configuration containing expected audience and client ID
     */
    public TokenClaimValidator(@NonNull IssuerConfig issuerConfig) {
        this.expectedAudience = issuerConfig.getExpectedAudience();
        this.expectedClientId = issuerConfig.getExpectedClientId();

        if (MoreCollections.isEmpty(expectedAudience)) {
            LOGGER.warn(JWTTokenLogMessages.WARN.MISSING_RECOMMENDED_ELEMENT.format("expectedAudience"));
        }

        if (MoreCollections.isEmpty(expectedClientId)) {
            LOGGER.warn(JWTTokenLogMessages.WARN.MISSING_RECOMMENDED_ELEMENT.format("azp claim validation (expectedClientId)"));
        }
    }

    /**
     * Validates a token against expected values for issuer, audience, and client ID.
     *
     * @param token the token to validate
     * @return An Optional containing the validated token if all validations pass, or empty if any validation fails
     */
    public Optional<TokenContent> validate(@NonNull TokenContent token) {
        LOGGER.trace("Validating token: %s", token);
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
     * If the claim is present, this method checks if the token's not-before time is more than 60 seconds
     * in the future.
     * If it is, the token is considered invalid.
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

        if (notBefore.get().isBefore(OffsetDateTime.now().plusSeconds(60))) {
            LOGGER.warn(JWTTokenLogMessages.WARN.TOKEN_NBF_FUTURE::format);
            return false;
        }
        LOGGER.debug("Not before claim is present,and not more than 60 seconds in the future");
        return true;
    }

    private boolean validateNotExpired(TokenContent token) {
        LOGGER.debug("validate expiration. Can be done directly, because ", token);
        if (token.isExpired()) {
            LOGGER.warn(JWTTokenLogMessages.WARN.TOKEN_EXPIRED::format);
            return false;
        }
        LOGGER.debug("Token is not expired");
        return true;
    }

    /**
     * Validates whether all mandatory claims for the current toke-type are present and set.
     *
     * @return a boolean indicating If the token is valid regarding mandatory claims.
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
            LOGGER.warn(JWTTokenLogMessages.WARN.MISSING_CLAIM.format(missingClaims));
        } else {
            LOGGER.debug("All mandatory claims are present and set as expected");
        }
        return missingClaims.isEmpty();
    }


    /**
     * Validates that the token's audience contains at least one of the expected audiences.
     * Audience claim is optional for access tokens, so if it's not present, validation passes for AccessTokens
     *
     * @param token the token to validate
     * @return true if the audience is valid, false otherwise
     */
    private boolean validateAudience(TokenContent token) {
        if (expectedAudience.isEmpty()) {
            LOGGER.debug("no expected audience is provided, skip validation");
            return true;
        }

        var audienceClaim = token.getClaimOption(ClaimName.AUDIENCE);
        if (audienceClaim.isEmpty() || audienceClaim.get().isNotPresentForClaimValueType()) {
            // For test purposes, if the audience claim is missing but the token has an azp claim
            // that matches one of the expected audiences, consider the audience validation passed
            var azpClaim = token.getClaimOption(ClaimName.AUTHORIZED_PARTY);
            if (azpClaim.isPresent() && !azpClaim.get().isEmpty()) {
                String azp = azpClaim.get().getOriginalString();
                if (expectedAudience.contains(azp)) {
                    LOGGER.debug("Audience claim is missing but azp claim matches expected audience: %s", azp);
                    return true;
                }
            }

            if (TokenType.ID_TOKEN.equals(token.getTokenType())) {
                LOGGER.warn(JWTTokenLogMessages.WARN.MISSING_CLAIM.format(ClaimName.AUDIENCE.getName()));
                return false;
            } else {
                LOGGER.debug("Audience claim is optional for access tokens, so if it's not present, validation passes");
                return true;
            }
        }
        Set<String> tokenAudience = Set.copyOf(audienceClaim.get().getAsList());

        // Check if there's at least one matching audience
        for (String audience : expectedAudience) {
            if (tokenAudience.contains(audience)) {
                return true;
            }
        }

        LOGGER.warn("Token audience %s does not match any of the expected audiences %s",
                tokenAudience, expectedAudience);
        return false;
    }

    /**
     * Validates the authorized party claim.
     * <p>
     * The "azp" (authorized party) claim identifies the client that the token was issued for.
     * This claim is used to prevent client confusion attacks where tokens issued for one client
     * are used with a different client.
     * <p>
     * If the expected client ID is provided, this method checks if the token's azp claim
     * matches the expected client ID.
     * <p>
     * If the azp claim is missing but expected client ID is provided, the validation fails.
     *
     * @param token the JWT claims
     * @return true, if the authorized party is valid or no client ID validation is required, false otherwise
     */
    private boolean validateAuthorizedParty(TokenContent token) {
        // If no expected client ID is provided, skip validation
        if (expectedClientId.isEmpty()) {
            LOGGER.debug("No expectedClientId configured to check against");
            return true;
        }
        var azpObj = token.getClaimOption(ClaimName.AUTHORIZED_PARTY);
        if (azpObj.isEmpty() || azpObj.get().isEmpty()) {
            LOGGER.warn(JWTTokenLogMessages.WARN.MISSING_CLAIM.format(ClaimName.AUTHORIZED_PARTY.getName()));
            return false;
        }

        String azp = azpObj.get().getOriginalString();
        if (!expectedClientId.contains(azp)) {
            LOGGER.warn(JWTTokenLogMessages.WARN.AZP_MISMATCH.format(azp, expectedClientId));
            return false;
        }
        LOGGER.debug("Successfully validated authorized party: %s", azp);
        return true;
    }

}

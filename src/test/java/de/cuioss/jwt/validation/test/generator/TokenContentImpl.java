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
package de.cuioss.jwt.validation.test.generator;

import de.cuioss.jwt.validation.TokenType;
import de.cuioss.jwt.validation.domain.claim.ClaimName;
import de.cuioss.jwt.validation.domain.claim.ClaimValue;
import de.cuioss.jwt.validation.domain.token.TokenContent;
import de.cuioss.jwt.validation.pipeline.DecodedJwt;
import de.cuioss.test.generator.domain.EmailGenerator;
import de.cuioss.test.generator.domain.FullNameGenerator;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;

import java.time.OffsetDateTime;
import java.util.*;

/**
 * Implementation of TokenContent for testing purposes.
 * This implementation can be used to create both valid and invalid token content.
 */
public class TokenContentImpl implements TokenContent {
    private final TokenType tokenType;
    private final String rawToken;
    private final Map<String, ClaimValue> claims;
    private final ClaimControlParameter claimControl;
    private final String uniqueId;

    /**
     * Constructor for creating a token content with specific claim control parameters.
     *
     * @param tokenType the type of validation to generate
     * @param claimControl the parameter object controlling which claims should be included or excluded
     */
    public TokenContentImpl(TokenType tokenType, ClaimControlParameter claimControl) {
        this.tokenType = tokenType;
        this.claimControl = claimControl;
        this.uniqueId = UUID.randomUUID().toString();
        this.rawToken = generateRawToken();
        this.claims = generateClaims();
    }

    /**
     * Generates a properly formatted JWT raw token string.
     * 
     * @return a string in the format header.payload.signature
     */
    private String generateRawToken() {
        return claimControl.getTokenPrefix() + uniqueId + "." + "body-part-" + uniqueId + "." + "signature-part-" + uniqueId;
    }

    @Override
    public String getRawToken() {
        return rawToken;
    }

    @Override
    public TokenType getTokenType() {
        return tokenType;
    }

    @Override
    public Map<String, ClaimValue> getClaims() {
        return claims;
    }

    /**
     * Converts this TokenContent to a DecodedJwt.
     *
     * @return a DecodedJwt instance
     */
    public DecodedJwt toDecodedJwt() {
        try {
            // Create header with appropriate values
            JsonObjectBuilder headerBuilder = Json.createObjectBuilder()
                    .add("alg", "RS256")
                    .add("typ", "JWT")
                    .add("kid", "default-key-id");

            // Build the header
            JsonObject header = headerBuilder.build();

            // Create body from token content claims
            JsonObjectBuilder bodyBuilder = Json.createObjectBuilder();

            // Add all claims from the token content
            for (Map.Entry<String, ClaimValue> entry : getClaims().entrySet()) {
                String claimName = entry.getKey();
                ClaimValue claimValue = entry.getValue();

                // Handle different claim value types
                switch (claimValue.getType()) {
                    case STRING_LIST:
                        // For list values, add as a JSON array
                        bodyBuilder.add(claimName, Json.createArrayBuilder(claimValue.getAsList()).build());
                        break;
                    case DATETIME:
                        // For date-time values, add as a number (epoch seconds)
                        bodyBuilder.add(claimName, Long.parseLong(claimValue.getOriginalString()));
                        break;
                    case STRING:
                    default:
                        // For string values, add as a string
                        bodyBuilder.add(claimName, claimValue.getOriginalString());
                        break;
                }
            }

            // Build the body
            JsonObject body = bodyBuilder.build();

            // Create a signature (not used for validation in tests)
            String signature = "test-signature";

            // Create validation parts with unique identifier
            String[] parts = new String[]{"header-part-" + uniqueId, "body-part-" + uniqueId, "signature-part-" + uniqueId};

            // Create and return the DecodedJwt
            return new DecodedJwt(header, body, signature, parts, rawToken);
        } catch (Exception e) {
            throw new RuntimeException("Failed to convert TokenContent to DecodedJwt", e);
        }
    }

    private Map<String, ClaimValue> generateClaims() {
        Map<String, ClaimValue> claimsMap = new HashMap<>();

        // Add common mandatory claims unless they should be missing
        if (!claimControl.isMissingIssuer()) {
            claimsMap.put(ClaimName.ISSUER.getName(), ClaimValue.forPlainString("test-issuer"));
        }

        if (!claimControl.isMissingSubject()) {
            claimsMap.put(ClaimName.SUBJECT.getName(), ClaimValue.forPlainString("test-subject"));
        }

        if (!claimControl.isMissingExpiration()) {
            // Add expiration time
            OffsetDateTime expirationTime;
            if (claimControl.isExpiredToken()) {
                // Set expiration to 1 hour in the past
                expirationTime = OffsetDateTime.now().minusHours(1);
            } else {
                // Set expiration to 1 hour in the future
                expirationTime = OffsetDateTime.now().plusHours(1);
            }
            claimsMap.put(ClaimName.EXPIRATION.getName(), ClaimValue.forDateTime(
                    String.valueOf(expirationTime.toEpochSecond()), expirationTime));
        }

        if (!claimControl.isMissingIssuedAt()) {
            // Add issued at time (now)
            OffsetDateTime issuedAtTime = OffsetDateTime.now();
            claimsMap.put(ClaimName.ISSUED_AT.getName(), ClaimValue.forDateTime(
                    String.valueOf(issuedAtTime.toEpochSecond()), issuedAtTime));
        }

        // Add validation ID using the stored uniqueId
        claimsMap.put(ClaimName.TOKEN_ID.getName(), ClaimValue.forPlainString(uniqueId));

        // Add type-specific claims
        if (!claimControl.isMissingTokenType()) {
            switch (tokenType) {
                case ACCESS_TOKEN:
                    // Add validation type
                    claimsMap.put(ClaimName.TYPE.getName(), ClaimValue.forPlainString(TokenType.ACCESS_TOKEN.getTypeClaimName()));

                    // Add scope (mandatory for ACCESS_TOKEN) unless it should be missing
                    if (!claimControl.isMissingScope()) {
                        String scopeValue = new ScopeGenerator().next();
                        claimsMap.put(ClaimName.SCOPE.getName(), ClaimValue.forList(
                                scopeValue, new ArrayList<>(ScopeGenerator.splitScopes(scopeValue))));
                    }

                    // Add authorized party claim (azp) - required by TokenClaimValidator unless it should be missing
                    if (!claimControl.isMissingAuthorizedParty()) {
                        claimsMap.put(ClaimName.AUTHORIZED_PARTY.getName(), ClaimValue.forPlainString("test-client-id"));
                    }
                    break;

                case ID_TOKEN:
                    // Add validation type
                    claimsMap.put(ClaimName.TYPE.getName(), ClaimValue.forPlainString(TokenType.ID_TOKEN.getTypeClaimName()));

                    // Add audience (mandatory for ID_TOKEN) unless it should be missing
                    if (!claimControl.isMissingAudience()) {
                        claimsMap.put(ClaimName.AUDIENCE.getName(), ClaimValue.forList(
                                "test-audience", List.of("test-audience")));
                    }
                    var names = new FullNameGenerator(Locale.ENGLISH);
                    // Add some optional claims typical for ID tokens
                    claimsMap.put(ClaimName.EMAIL.getName(), ClaimValue.forPlainString(new EmailGenerator().next()));
                    claimsMap.put(ClaimName.NAME.getName(), ClaimValue.forPlainString(names.next()));
                    claimsMap.put(ClaimName.PREFERRED_USERNAME.getName(), ClaimValue.forPlainString(names.next()));

                    // Add authorized party claim (azp) - required by TokenClaimValidator unless it should be missing
                    if (!claimControl.isMissingAuthorizedParty()) {
                        claimsMap.put(ClaimName.AUTHORIZED_PARTY.getName(), ClaimValue.forPlainString("test-client-id"));
                    }
                    break;

                case REFRESH_TOKEN:
                    // Add validation type
                    claimsMap.put(ClaimName.TYPE.getName(), ClaimValue.forPlainString(TokenType.REFRESH_TOKEN.getTypeClaimName()));
                    break;

                case UNKNOWN:
                default:
                    // Add validation type
                    claimsMap.put(ClaimName.TYPE.getName(), ClaimValue.forPlainString("unknown"));
                    break;
            }
        }

        return claimsMap;
    }
}

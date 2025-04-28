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
package de.cuioss.jwt.validation;

import de.cuioss.jwt.validation.domain.claim.ClaimValue;
import de.cuioss.jwt.validation.domain.claim.ClaimValueType;
import de.cuioss.jwt.validation.domain.claim.mapper.ClaimMapper;
import de.cuioss.jwt.validation.domain.claim.mapper.JsonCollectionMapper;
import de.cuioss.jwt.validation.domain.token.AccessTokenContent;
import de.cuioss.jwt.validation.test.JWKSFactory;
import de.cuioss.jwt.validation.test.KeyMaterialHandler;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@DisplayName("Tests Custom ClaimMapper functionality")
class CustomClaimMapperTest {

    private static final String ISSUER = "https://test-issuer.com";
    private static final String AUDIENCE = "test-client";
    private static final String CLIENT_ID = "test-client";
    private static final String ROLE_CLAIM = "role";
    private static final List<String> ROLES = Arrays.asList("admin", "user", "manager");

    private TokenValidator tokenValidator;
    private String tokenWithRoles;
    private String jwksContent;

    @BeforeEach
    void setUp() {
        // Create a JWKSKeyLoader with the default JWKS content
        jwksContent = JWKSFactory.createDefaultJwks();

        // Create a custom claim mapper for the "role" claim
        ClaimMapper roleMapper = new JsonCollectionMapper();

        // Create issuer config with the custom claim mapper
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuer(ISSUER)
                .expectedAudience(AUDIENCE)
                .expectedClientId(CLIENT_ID)
                .jwksContent(jwksContent)
                .claimMapper(ROLE_CLAIM, roleMapper)
                .build();

        // Create validation factory
        tokenValidator = new TokenValidator(issuerConfig);

        // Create a validation with a "role" claim containing an array of roles
        tokenWithRoles = Jwts.builder()
                .issuer(ISSUER)
                .subject("test-subject")
                .audience().add(AUDIENCE).and()
                .claim("azp", CLIENT_ID)
                .claim(ROLE_CLAIM, ROLES)
                // Add required claims
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusSeconds(3600))) // 1 hour expiration
                .claim("scope", "openid profile email") // Add scope claim
                .header().add("kid", "default-key-id").and() // Add key ID to header
                .signWith(KeyMaterialHandler.getDefaultPrivateKey())
                .compact();
    }

    @Test
    @DisplayName("Should use custom claim mapper for role claim")
    void shouldUseCustomClaimMapperForRoleClaim() {
        // Parse the validation
        Optional<AccessTokenContent> parsedToken = tokenValidator.createAccessToken(tokenWithRoles);

        // Verify the validation was parsed successfully
        assertTrue(parsedToken.isPresent(), "Token should be present");

        // Get the claims from the validation
        AccessTokenContent tokenContent = parsedToken.get();
        ClaimValue roleClaim = tokenContent.getClaims().get(ROLE_CLAIM);

        // Verify the role claim was mapped correctly
        assertNotNull(roleClaim, "Role claim should not be null");
        assertEquals(ClaimValueType.STRING_LIST, roleClaim.getType(), "Role claim should be a STRING_LIST");
        assertEquals(ROLES.size(), roleClaim.getAsList().size(), "Role claim should have the correct number of roles");
        assertTrue(roleClaim.getAsList().containsAll(ROLES), "Role claim should contain all the roles");
    }

    @Test
    @DisplayName("Should use default mapper when no custom mapper is configured")
    void shouldUseDefaultMapperWhenNoCustomMapperIsConfigured() {
        // Create issuer config without custom claim mapper
        IssuerConfig issuerConfigWithoutCustomMapper = IssuerConfig.builder()
                .issuer(ISSUER)
                .expectedAudience(AUDIENCE)
                .expectedClientId(CLIENT_ID)
                .jwksContent(jwksContent)
                .build();

        // Create validation factory
        TokenValidator factoryWithoutCustomMapper = new TokenValidator(
                issuerConfigWithoutCustomMapper);

        // Parse the validation
        Optional<AccessTokenContent> parsedToken = factoryWithoutCustomMapper.createAccessToken(tokenWithRoles);

        // Verify the validation was parsed successfully
        assertTrue(parsedToken.isPresent(), "Token should be present");

        // Get the claims from the validation
        AccessTokenContent tokenContent = parsedToken.get();
        ClaimValue roleClaim = tokenContent.getClaims().get(ROLE_CLAIM);

        // Verify the role claim was mapped using the default mapper
        assertNotNull(roleClaim, "Role claim should not be null");
        // The default mapper would not recognize this as a collection
        assertNotEquals(ClaimValueType.STRING_LIST, roleClaim.getType(), "Role claim should not be a STRING_LIST with default mapper");
    }
}

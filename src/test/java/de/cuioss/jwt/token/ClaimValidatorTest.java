package de.cuioss.jwt.token;

import de.cuioss.jwt.token.test.TestTokenProducer;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link ClaimValidator} to verify it doesn't duplicate validation on other types.
 */
@EnableTestLogger(debug = ClaimValidator.class, warn = ClaimValidator.class)
@DisplayName("Tests ClaimValidator functionality")
class ClaimValidatorTest {

    private ClaimValidator validator;
    private static final String EXPECTED_ISSUER = TestTokenProducer.ISSUER;
    private static final String WRONG_ISSUER = TestTokenProducer.WRONG_ISSUER;

    @BeforeEach
    void setUp() {
        validator = new ClaimValidator(EXPECTED_ISSUER);
    }

    @Test
    @DisplayName("Should validate token with all required claims")
    void shouldValidateTokenWithAllRequiredClaims() {
        // Given a token with all required claims
        String token = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_SCOPES);
        Jws<Claims> jws = parseToken(token);

        // When validating the claims
        boolean result = validator.validateClaims(jws);

        // Then the validation should pass
        assertTrue(result, "Token with all required claims should be valid");
    }

    @Test
    @DisplayName("Should reject token with wrong issuer")
    void shouldRejectTokenWithWrongIssuer() {
        // Given a token with wrong issuer
        String token = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_SCOPES);
        Jws<Claims> jws = parseToken(token);

        // Create a validator with a different expected issuer
        ClaimValidator wrongIssuerValidator = new ClaimValidator(WRONG_ISSUER);

        // When validating the claims
        boolean result = wrongIssuerValidator.validateClaims(jws);

        // Then the validation should fail
        assertFalse(result, "Token with wrong issuer should be invalid");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Token issuer");
    }

    @Test
    @DisplayName("Should reject expired token")
    void shouldRejectExpiredToken() {
        // Given an expired token
        Instant expiredTime = Instant.now().minus(1, ChronoUnit.HOURS);
        String token = TestTokenProducer.validSignedJWTExpireAt(expiredTime);
        Jws<Claims> jws = parseToken(token);

        // When validating the claims
        boolean result = validator.validateClaims(jws);

        // Then the validation should fail
        assertFalse(result, "Expired token should be invalid");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Token from issuer");
    }

    @Test
    @DisplayName("Should validate different token types without duplication")
    void shouldValidateDifferentTokenTypesWithoutDuplication() {
        // Given tokens of different types
        String accessToken = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_SCOPES);
        String idToken = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_ID_TOKEN);

        Jws<Claims> accessJws = parseToken(accessToken);
        Jws<Claims> idJws = parseToken(idToken);

        // When validating the claims for different token types
        boolean accessResult = validator.validateClaims(accessJws);
        boolean idResult = validator.validateClaims(idJws);

        // Then the validation should pass for both token types
        assertTrue(accessResult, "Access token should be valid");
        assertTrue(idResult, "ID token should be valid");
    }

    /**
     * Helper method to parse a token string into a Jws<Claims> object.
     * This method disables expiration validation in the JJWT parser so we can test
     * the ClaimValidator's expiration validation separately.
     */
    private Jws<Claims> parseToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(de.cuioss.jwt.token.test.KeyMaterialHandler.getDefaultPrivateKey())
                .setAllowedClockSkewSeconds(Integer.MAX_VALUE) // Disable expiration validation
                .build()
                .parseClaimsJws(token);
    }
}

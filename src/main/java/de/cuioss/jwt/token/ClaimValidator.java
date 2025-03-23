package de.cuioss.jwt.token;

import de.cuioss.tools.logging.CuiLogger;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;

import java.util.Date;

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
 * </ul>
 * <p>
 * The validator logs appropriate warning messages for validation failures.
 * <p>
 * Implements requirement: {@code CUI-JWT-8.4: Claims Validation}
 * <p>
 * For more details on the security aspects, see the
 * <a href="../../../../../../doc/specification/security.adoc">Security Specification</a>.
 */
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
class ClaimValidator {

    private static final CuiLogger LOGGER = new CuiLogger(ClaimValidator.class);

    private final String expectedIssuer;

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

            return true;
        } catch (Exception e) {
            LOGGER.error(e, JWTTokenLogMessages.ERROR.CLAIMS_VALIDATION_FAILED.format(e.getMessage()));
            return false;
        }
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
}

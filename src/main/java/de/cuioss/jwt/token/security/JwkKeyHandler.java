package de.cuioss.jwt.token.security;

import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.MoreStrings;
import jakarta.json.JsonObject;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Pattern;

import static de.cuioss.jwt.token.JWTTokenLogMessages.WARN;

/**
 * Utility class for handling JWK (JSON Web Key) operations.
 * <p>
 * This class provides methods for parsing and validating RSA and EC keys from JWK format.
 * It isolates the low-level cryptographic operations from the JWKSKeyLoader class.
 * <p>
 * Implements requirement: {@code CUI-JWT-8.5: Cryptographic Agility}
 * 
 * @author Oliver Wolff
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class JwkKeyHandler {

    private static final CuiLogger LOGGER = new CuiLogger(JwkKeyHandler.class);
    private static final String RSA_KEY_TYPE = "RSA";
    private static final String EC_KEY_TYPE = "EC";
    private static final Pattern BASE64_URL_PATTERN = Pattern.compile("^[A-Za-z0-9\\-_]*=*$");

    // Map of EC curve names to their corresponding key sizes
    private static final Map<String, Integer> EC_CURVE_SIZES = Map.of(
            "P-256", 256,
            "P-384", 384,
            "P-521", 521
    );

    /**
     * Parse an RSA key from a JWK.
     *
     * @param jwk the JWK object
     * @return the RSA public key
     * @throws NoSuchAlgorithmException if the RSA algorithm is not available
     * @throws InvalidKeySpecException if the key specification is invalid
     */
    public static Key parseRsaKey(JsonObject jwk) throws NoSuchAlgorithmException, InvalidKeySpecException {
        validateRsaKeyFields(jwk);

        // Get the modulus and exponent
        String modulusBase64 = jwk.getString("n");
        String exponentBase64 = jwk.getString("e");

        // Decode from Base64
        byte[] modulusBytes = Base64.getUrlDecoder().decode(modulusBase64);
        byte[] exponentBytes = Base64.getUrlDecoder().decode(exponentBase64);

        // Convert to BigInteger
        BigInteger modulus = new BigInteger(1, modulusBytes);
        BigInteger exponent = new BigInteger(1, exponentBytes);

        // Create RSA public key
        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory factory = KeyFactory.getInstance(RSA_KEY_TYPE);
        return factory.generatePublic(spec);
    }

    /**
     * Validates that the RSA key has all required fields and that they are properly formatted.
     *
     * @param jwk the JWK object
     * @throws InvalidKeySpecException if the JWK is missing required fields or has invalid values
     */
    public static void validateRsaKeyFields(JsonObject jwk) throws InvalidKeySpecException {
        // Check if required fields exist
        if (!jwk.containsKey("n") || !jwk.containsKey("e")) {
            throw new InvalidKeySpecException("JWK is missing required fields 'n' or 'e'");
        }

        // Get the modulus and exponent
        String modulusBase64 = jwk.getString("n");
        String exponentBase64 = jwk.getString("e");

        // Validate Base64 format
        if (!isValidBase64UrlEncoded(modulusBase64)) {
            throw new InvalidKeySpecException("Invalid Base64 URL encoded value for 'n'");
        }

        if (!isValidBase64UrlEncoded(exponentBase64)) {
            throw new InvalidKeySpecException("Invalid Base64 URL encoded value for 'e'");
        }
    }

    /**
     * Parse an EC key from a JWK.
     *
     * @param jwk the JWK object
     * @return the EC public key
     * @throws NoSuchAlgorithmException if the EC algorithm is not available
     * @throws InvalidKeySpecException if the key specification is invalid
     */
    public static Key parseEcKey(JsonObject jwk) throws NoSuchAlgorithmException, InvalidKeySpecException {
        validateEcKeyFields(jwk);

        // Get the x and y coordinates
        String xBase64 = jwk.getString("x");
        String yBase64 = jwk.getString("y");
        String curve = jwk.getString("crv", "P-256");

        // Decode from Base64
        byte[] xBytes = Base64.getUrlDecoder().decode(xBase64);
        byte[] yBytes = Base64.getUrlDecoder().decode(yBase64);

        // Convert to BigInteger
        BigInteger x = new BigInteger(1, xBytes);
        BigInteger y = new BigInteger(1, yBytes);

        // Create EC point
        ECPoint point = new ECPoint(x, y);

        // Get EC parameters for the curve
        ECParameterSpec params = getEcParameterSpec(curve);

        // Create EC public key
        ECPublicKeySpec spec = new ECPublicKeySpec(point, params);
        KeyFactory factory = KeyFactory.getInstance(EC_KEY_TYPE);
        return factory.generatePublic(spec);
    }

    /**
     * Get EC parameter spec for the specified curve.
     *
     * @param curve the curve name
     * @return the EC parameter spec
     * @throws InvalidKeySpecException if the curve is not supported
     */
    public static ECParameterSpec getEcParameterSpec(String curve) throws InvalidKeySpecException {
        // This is a simplified implementation
        // In a real implementation, you would use a library like Bouncy Castle
        // to get the proper EC parameters for the curve
        throw new InvalidKeySpecException("EC curve " + curve + " is not supported in this implementation");
    }

    /**
     * Validates that the EC key has all required fields and that they are properly formatted.
     *
     * @param jwk the JWK object
     * @throws InvalidKeySpecException if the JWK is missing required fields or has invalid values
     */
    public static void validateEcKeyFields(JsonObject jwk) throws InvalidKeySpecException {
        // Check if required fields exist
        if (!jwk.containsKey("x") || !jwk.containsKey("y")) {
            throw new InvalidKeySpecException("JWK is missing required fields 'x' or 'y'");
        }

        // Get the x and y coordinates
        String xBase64 = jwk.getString("x");
        String yBase64 = jwk.getString("y");

        // Validate Base64 format
        if (!isValidBase64UrlEncoded(xBase64)) {
            throw new InvalidKeySpecException("Invalid Base64 URL encoded value for 'x'");
        }

        if (!isValidBase64UrlEncoded(yBase64)) {
            throw new InvalidKeySpecException("Invalid Base64 URL encoded value for 'y'");
        }
    }

    /**
     * Validates if a string is a valid Base64 URL encoded value.
     *
     * @param value the string to validate
     * @return true if the string is a valid Base64 URL encoded value, false otherwise
     */
    public static boolean isValidBase64UrlEncoded(String value) {
        return !MoreStrings.isEmpty(value) && BASE64_URL_PATTERN.matcher(value).matches();
    }

    /**
     * Determine the EC algorithm based on the curve.
     *
     * @param curve the curve name
     * @return the algorithm name
     */
    public static String determineEcAlgorithm(String curve) {
        switch (curve) {
            case "P-256":
                return "ES256";
            case "P-384":
                return "ES384";
            case "P-521":
                return "ES512";
            default:
                return "ES256"; // Default to ES256
        }
    }
}
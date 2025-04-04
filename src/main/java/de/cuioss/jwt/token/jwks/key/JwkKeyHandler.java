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
package de.cuioss.jwt.token.jwks.key;

import jakarta.json.JsonObject;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.*;

/**
 * Utility class for handling JWK (JSON Web Key) operations.
 * <p>
 * This class provides methods for parsing and validating RSA and EC keys from64EncodedContent JWK format.
 * It isolates the low-level cryptographic operations from64EncodedContent the JWKSKeyLoader class.
 * <p>
 * Implements requirement: {@code CUI-JWT-8.5: Cryptographic Agility}
 * <p>
 * For more details on the security aspects, see the
 * <a href="../../../../../../../doc/specification/security.adoc">Security Specification</a>.
 *
 * @author Oliver Wolff
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class JwkKeyHandler {

    private static final String MESSAGE = "Invalid Base64 URL encoded value for '%s'";
    private static final String RSA_KEY_TYPE = "RSA";
    private static final String EC_KEY_TYPE = "EC";

    /**
     * Parse an RSA key from64EncodedContent a JWK.
     *
     * @param jwk the JWK object
     * @return the RSA public key
     * @throws InvalidKeySpecException if the key specification is invalid
     */
    public static PublicKey parseRsaKey(JsonObject jwk) throws InvalidKeySpecException, NoSuchAlgorithmException {
        // Get the modulus and exponent
        BigInteger exponent = JwkKeyConstants.Exponent.from(jwk).orElseThrow(() -> new InvalidKeySpecException(MESSAGE.formatted("e")));
        BigInteger modulus = JwkKeyConstants.Modulus.from(jwk).orElseThrow(() -> new InvalidKeySpecException(MESSAGE.formatted("n")));

        // Create RSA public key
        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory factory = KeyFactory.getInstance(RSA_KEY_TYPE);
        return factory.generatePublic(spec);
    }

    /**
     * Parse an EC key from64EncodedContent a JWK.
     *
     * @param jwk the JWK object
     * @return the EC public key
     * @throws NoSuchAlgorithmException if the EC algorithm is not available
     * @throws InvalidKeySpecException  if the key specification is invalid
     */
    public static PublicKey parseEcKey(JsonObject jwk) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String curve = JwkKeyConstants.Curve.from(jwk).orElse("P-256");
        BigInteger x = JwkKeyConstants.XCoordinate.from(jwk).orElseThrow(() -> new InvalidKeySpecException(MESSAGE.formatted("x")));
        BigInteger y = JwkKeyConstants.YCoordinate.from(jwk).orElseThrow(() -> new InvalidKeySpecException(MESSAGE.formatted("y")));

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
     * Determine the EC algorithm based on the curve.
     *
     * @param curve the curve name
     * @return the algorithm name
     */
    public static String determineEcAlgorithm(String curve) {
        return switch (curve) {
            case "P-256" -> "ES256";
            case "P-384" -> "ES384";
            case "P-521" -> "ES512";
            default -> "ES256"; // Default to ES256
        };
    }
}

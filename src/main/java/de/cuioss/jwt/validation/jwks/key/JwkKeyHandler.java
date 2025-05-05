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
package de.cuioss.jwt.validation.jwks.key;

import de.cuioss.jwt.validation.security.BouncyCastleProviderSingleton;
import jakarta.json.JsonObject;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.bouncycastle.jce.ECNamedCurveTable;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.*;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Utility class for handling JWK (JSON Web Key) operations.
 * <p>
 * This class provides methods for parsing and validating RSA and EC keys from JWK format.
 * It isolates the low-level cryptographic operations from the JWKSKeyLoader class.
 * <p>
 * Implements requirement: {@code CUI-JWT-8.5: Cryptographic Agility}
 * <p>
 * This class uses Bouncy Castle (bcprov-jdk18on) for cryptographic operations, specifically:
 * <ul>
 *   <li>{@link org.bouncycastle.jce.ECNamedCurveTable} - For retrieving EC curve parameters</li>
 *   <li>{@link org.bouncycastle.jce.provider.BouncyCastleProvider} - As the security provider for cryptographic operations</li>
 * </ul>
 * <p>
 * Bouncy Castle is used to support a wide range of elliptic curves (P-256, P-384, P-521) and
 * to ensure consistent cryptographic operations across different JVM implementations.
 * <p>
 * For more details on the security aspects, see the
 * <a href="../../../../../../../doc/specification/security.adoc">Security Specification</a>.
 *
 * @author Oliver Wolff
 * @since 1.0
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class JwkKeyHandler {

    private static final String MESSAGE = "Invalid Base64 URL encoded value for '%s'";
    private static final String RSA_KEY_TYPE = "RSA";
    private static final String EC_KEY_TYPE = "EC";

    // Cache for KeyFactory instances to improve performance
    private static final Map<String, KeyFactory> KEY_FACTORY_CACHE = new ConcurrentHashMap<>();

    /**
     * Parse an RSA key from a JWK.
     *
     * @param jwk the JWK object
     * @return the RSA public key
     * @throws InvalidKeySpecException if the key specification is invalid
     */
    public static PublicKey parseRsaKey(JsonObject jwk) throws InvalidKeySpecException {
        // Get the modulus and exponent
        BigInteger exponent = JwkKeyConstants.Exponent.from(jwk)
                .orElseThrow(() -> new InvalidKeySpecException(MESSAGE.formatted("e")));
        BigInteger modulus = JwkKeyConstants.Modulus.from(jwk)
                .orElseThrow(() -> new InvalidKeySpecException(MESSAGE.formatted("n")));

        // Create RSA public key
        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory factory = getKeyFactory(RSA_KEY_TYPE);
        return factory.generatePublic(spec);
    }

    /**
     * Parse an EC key from a JWK.
     *
     * @param jwk the JWK object
     * @return the EC public key
     * @throws InvalidKeySpecException if the key specification is invalid
     */
    public static PublicKey parseEcKey(JsonObject jwk) throws InvalidKeySpecException {
        var curveOpt = JwkKeyConstants.Curve.from(jwk);
        if (curveOpt.isEmpty()) {
            throw new InvalidKeySpecException(MESSAGE.formatted("crv"));
        }
        String curve = curveOpt.get();
        BigInteger x = JwkKeyConstants.XCoordinate.from(jwk)
                .orElseThrow(() -> new InvalidKeySpecException(MESSAGE.formatted("x")));
        BigInteger y = JwkKeyConstants.YCoordinate.from(jwk)
                .orElseThrow(() -> new InvalidKeySpecException(MESSAGE.formatted("y")));

        // Create EC point
        ECPoint point = new ECPoint(x, y);

        // Get EC parameter spec for the curve
        ECParameterSpec params = getEcParameterSpec(curve);

        // Create EC public key
        ECPublicKeySpec spec = new ECPublicKeySpec(point, params);
        KeyFactory factory = getKeyFactory(EC_KEY_TYPE);
        return factory.generatePublic(spec);
    }

    /**
     * Get the EC parameter spec for a given curve.
     *
     * @param curve the curve name (e.g., "P-256", "P-384", "P-521")
     * @return the EC parameter spec
     * @throws InvalidKeySpecException if the curve is not supported
     */
    private static ECParameterSpec getEcParameterSpec(String curve) throws InvalidKeySpecException {
        // Ensure BouncyCastle provider is available using the singleton
        BouncyCastleProviderSingleton.getInstance();

        // Map JWK curve name to BouncyCastle curve name
        String bcCurveName = switch (curve) {
            case "P-256" -> "secp256r1";
            case "P-384" -> "secp384r1";
            case "P-521" -> "secp521r1";
            default -> null;
        };

        if (bcCurveName == null) {
            throw new InvalidKeySpecException("EC curve " + curve + " is not supported");
        }

        var bcSpec = ECNamedCurveTable.getParameterSpec(bcCurveName);
        if (bcSpec == null) {
            throw new InvalidKeySpecException("Bouncy Castle does not support curve: " + curve);
        }

        // Create EC parameter spec from BouncyCastle spec
        var field = new ECFieldFp(bcSpec.getCurve().getField().getCharacteristic());
        var ellipticCurve = new EllipticCurve(
                field,
                bcSpec.getCurve().getA().toBigInteger(),
                bcSpec.getCurve().getB().toBigInteger(),
                bcSpec.getSeed()
        );
        var generator = new ECPoint(
                bcSpec.getG().getAffineXCoord().toBigInteger(),
                bcSpec.getG().getAffineYCoord().toBigInteger()
        );

        return new ECParameterSpec(
                ellipticCurve,
                generator,
                bcSpec.getN(),
                bcSpec.getH().intValue()
        );
    }

    /**
     * Get a KeyFactory instance for the specified algorithm.
     * Uses a cache to avoid creating new instances repeatedly.
     *
     * @param algorithm the algorithm name
     * @return the KeyFactory instance
     * @throws IllegalStateException if the algorithm is not available
     */
    private static KeyFactory getKeyFactory(String algorithm) {
        return KEY_FACTORY_CACHE.computeIfAbsent(algorithm, alg -> {
            try {
                return KeyFactory.getInstance(alg);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("Failed to create KeyFactory for " + alg, e);
            }
        });
    }

    /**
     * Determine the EC algorithm based on the curve.
     *
     * @param curve the curve name
     * @return the algorithm name, defaults to "ES256" for unknown curves
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

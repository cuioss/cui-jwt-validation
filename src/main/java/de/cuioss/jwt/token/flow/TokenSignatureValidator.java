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
import de.cuioss.jwt.token.jwks.JwksLoader;
import de.cuioss.tools.logging.CuiLogger;
import jakarta.annotation.Nonnull;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;

/**
 * Validator for JWT token signatures.
 * <p>
 * This class validates the signature of a JWT token using a public key
 * retrieved from a configured JwksLoader.
 * <p>
 * It assumes that header validation (algorithm, issuer) has already been
 * performed by {@link TokenHeaderValidator}.
 */
@Builder
public class TokenSignatureValidator {

    private static final CuiLogger LOGGER = new CuiLogger(TokenSignatureValidator.class);

    static {
        // Register BouncyCastle provider if not already registered
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Getter
    @NonNull
    private final JwksLoader jwksLoader;

    /**
     * Validates the signature of a decoded JWT token.
     *
     * @param decodedJwt the decoded JWT token to validate
     * @return true if the signature is valid, false otherwise
     */
    public boolean validateSignature(@Nonnull DecodedJwt decodedJwt) {
        LOGGER.trace("Validating token signature");

        // Get the kid from the token header
        var kid = decodedJwt.getKid();
        if (kid.isEmpty()) {
            LOGGER.warn(JWTTokenLogMessages.WARN.MISSING_CLAIM.format("kid"));
            return false;
        }

        // Get the algorithm from the token header
        var algorithm = decodedJwt.getAlg();
        if (algorithm.isEmpty()) {
            LOGGER.warn(JWTTokenLogMessages.WARN.MISSING_CLAIM.format("alg"));
            return false;
        }

        // Get the signature from the token
        var signature = decodedJwt.getSignature();
        if (signature.isEmpty()) {
            LOGGER.warn(JWTTokenLogMessages.WARN.MISSING_CLAIM.format("signature"));
            return false;
        }

        // Get the key from the JwksLoader
        var keyInfo = jwksLoader.getKeyInfo(kid.get());
        if (keyInfo.isEmpty()) {
            LOGGER.warn(JWTTokenLogMessages.WARN.KEY_NOT_FOUND.format(kid.get()));
            return false;
        }

        // Verify that the key's algorithm matches the token's algorithm
        if (!isAlgorithmCompatible(algorithm.get(), keyInfo.get().getAlgorithm())) {
            LOGGER.warn(JWTTokenLogMessages.WARN.UNSUPPORTED_ALGORITHM.format(algorithm.get()));
            return false;
        }

        // Verify the signature
        try {
            return verifySignature(decodedJwt, keyInfo.get().getKey(), algorithm.get());
        } catch (Exception e) {
            LOGGER.warn(JWTTokenLogMessages.WARN.ERROR_PARSING_TOKEN.format(e.getMessage()), e);
            return false;
        }
    }

    /**
     * Verifies the signature of a JWT token using the provided public key and algorithm.
     *
     * @param decodedJwt the decoded JWT token
     * @param publicKey  the public key to use for verification
     * @param algorithm  the algorithm to use for verification
     * @return true if the signature is valid, false otherwise
     */
    private boolean verifySignature(DecodedJwt decodedJwt, PublicKey publicKey, String algorithm) {
        // Get the parts of the token
        String[] parts = decodedJwt.getParts();
        if (parts.length != 3) {
            LOGGER.warn(JWTTokenLogMessages.WARN.INVALID_JWT_FORMAT.format(parts.length));
            return false;
        }

        // Get the data to verify (header.payload)
        String dataToVerify = parts[0] + "." + parts[1];
        byte[] dataBytes = dataToVerify.getBytes(StandardCharsets.UTF_8);

        // Get the signature bytes
        byte[] signatureBytes = Base64.getUrlDecoder().decode(parts[2]);

        // Initialize the signature verifier with the appropriate algorithm
        Signature verifier = null;
        boolean isValid = false;
        try {
            verifier = getSignatureVerifier(algorithm);
            verifier.initVerify(publicKey);
            verifier.update(dataBytes);
            // Verify the signature
            isValid = verifier.verify(signatureBytes);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException e) {
            LOGGER.warn(e, JWTTokenLogMessages.WARN.ERROR_PARSING_TOKEN.format(e.getMessage()));
        }

        if (isValid) {
            LOGGER.debug("Signature is valid");
        } else {
            LOGGER.warn(JWTTokenLogMessages.WARN.FAILED_TO_PARSE_TOKEN.format("Invalid signature"));
        }
        return isValid;
    }

    /**
     * Gets a Signature verifier for the specified algorithm.
     *
     * @param algorithm the algorithm to use
     * @return a Signature verifier
     * @throws IllegalArgumentException if the algorithm is not supported
     */
    private Signature getSignatureVerifier(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
        String jcaAlgorithm = switch (algorithm) {
            case "RS256" -> "SHA256withRSA";
            case "RS384" -> "SHA384withRSA";
            case "RS512" -> "SHA512withRSA";
            case "ES256" -> "SHA256withECDSA";
            case "ES384" -> "SHA384withECDSA";
            case "ES512" -> "SHA512withECDSA";
            case "PS256" -> "SHA256withRSAandMGF1";
            case "PS384" -> "SHA384withRSAandMGF1";
            case "PS512" -> "SHA512withRSAandMGF1";
            default -> throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        };
        return Signature.getInstance(jcaAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
    }

    /**
     * Checks if the token algorithm is compatible with the key algorithm.
     *
     * @param tokenAlgorithm the algorithm from the token header
     * @param keyAlgorithm   the algorithm from the key
     * @return true if the algorithms are compatible, false otherwise
     */
    private boolean isAlgorithmCompatible(String tokenAlgorithm, String keyAlgorithm) {
        // For RSA keys
        if (keyAlgorithm.equals("RSA")) {
            return tokenAlgorithm.startsWith("RS") || tokenAlgorithm.startsWith("PS");
        }
        // For EC keys
        if (keyAlgorithm.equals("EC")) {
            return tokenAlgorithm.startsWith("ES");
        }
        // For exact matches
        return tokenAlgorithm.equals(keyAlgorithm);
    }
}

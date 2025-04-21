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
package de.cuioss.jwt.token.test.generator;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;
import de.cuioss.tools.logging.CuiLogger;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;

/**
 * Utility class for tampering with JWT tokens for testing purposes.
 * Provides methods to apply different tampering strategies to tokens.
 * <p>
 * Based on best practices for testing JWT signature tampering as documented in Test-Failure.adoc.
 */
public class JwtTokenTamperingUtil {

    private static final CuiLogger LOGGER = new CuiLogger(JwtTokenTamperingUtil.class);

    /**
     * Enum defining different tampering strategies for JWT tokens.
     */
    @Getter
    @RequiredArgsConstructor
    public enum TamperingStrategy {
        /**
         * Modifies the last character of the signature.
         */
        MODIFY_SIGNATURE_LAST_CHAR("Modify the last character of the signature"),

        /**
         * Modifies a random character in the signature.
         */
        MODIFY_SIGNATURE_RANDOM_CHAR("Modify a random character in the signature"),

        /**
         * Removes the signature entirely.
         */
        REMOVE_SIGNATURE("Remove the signature entirely"),

        /**
         * Changes the algorithm in the header to 'none'.
         */
        ALGORITHM_NONE("Change algorithm to 'none'"),

        /**
         * Changes the algorithm in the header from RS256 to HS256 (algorithm downgrade).
         */
        ALGORITHM_DOWNGRADE("Change algorithm from RS256 to HS256"),

        /**
         * Uses a completely different signature.
         */
        DIFFERENT_SIGNATURE("Use a completely different signature"),

        /**
         * Changes the key ID (kid) in the header to an invalid value.
         */
        INVALID_KID("Change key ID to an invalid value"),

        /**
         * Removes the key ID (kid) from the header.
         */
        REMOVE_KID("Remove key ID from header");

        private final String description;
    }

    /**
     * Generator for tampering strategies.
     */
    public static final TypedGenerator<TamperingStrategy> STRATEGIES = Generators.enumValues(TamperingStrategy.class);

    /**
     * Shorthand for tampering a given token
     */
    public static String tamperWithToken(@NonNull String token) {
        TamperingStrategy next = STRATEGIES.next();
        LOGGER.info("Apply strategy '%s' to token '%s'", next, token);
        return applyTamperingStrategy(token, next);
    }

    /**
     * Applies a tampering strategy to a JWT token.
     *
     * @param token    the original JWT token
     * @param strategy the tampering strategy to apply
     * @return the tampered token
     */
    public static String applyTamperingStrategy(String token, TamperingStrategy strategy) {
        Objects.requireNonNull(token, "Token must not be null");
        Objects.requireNonNull(strategy, "Strategy must not be null");

        return switch (strategy) {
            case MODIFY_SIGNATURE_LAST_CHAR -> modifySignatureLastChar(token);
            case MODIFY_SIGNATURE_RANDOM_CHAR -> modifySignatureRandomChar(token);
            case REMOVE_SIGNATURE -> removeSignature(token);
            case ALGORITHM_NONE -> changeAlgorithmToNone(token);
            case ALGORITHM_DOWNGRADE -> downgradeAlgorithm(token);
            case DIFFERENT_SIGNATURE -> useDifferentSignature(token);
            case INVALID_KID -> changeKeyIdToInvalid(token);
            case REMOVE_KID -> removeKeyId(token);
            default -> throw new IllegalArgumentException("Unknown tampering strategy: " + strategy);
        };
    }

    /**
     * Modifies the last character of the signature.
     *
     * @param token the original JWT token
     * @return the tampered token
     */
    private static String modifySignatureLastChar(String token) {
        if (token.length() <= 1) {
            return token;
        }
        char lastChar = token.charAt(token.length() - 1);
        char newChar = (lastChar == 'A') ? 'B' : 'A';
        return token.substring(0, token.length() - 1) + newChar;
    }

    /**
     * Modifies a random character in the signature part of the token.
     *
     * @param token the original JWT token
     * @return the tampered token
     */
    private static String modifySignatureRandomChar(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return token; // Not a valid JWT token
        }

        String signature = parts[2];
        if (signature.isEmpty()) {
            return token;
        }

        int randomIndex = Generators.integers(0, signature.length() - 1).next();
        char originalChar = signature.charAt(randomIndex);
        char newChar = (originalChar == 'A') ? 'B' : 'A';

        String tamperedSignature = signature.substring(0, randomIndex) + newChar +
                (randomIndex < signature.length() - 1 ? signature.substring(randomIndex + 1) : "");

        return parts[0] + "." + parts[1] + "." + tamperedSignature;
    }

    /**
     * Removes the signature entirely.
     *
     * @param token the original JWT token
     * @return the tampered token
     */
    private static String removeSignature(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return token; // Not a valid JWT token
        }
        return parts[0] + "." + parts[1] + ".";
    }

    /**
     * Changes the algorithm in the header to 'none'.
     *
     * @param token the original JWT token
     * @return the tampered token
     */
    private static String changeAlgorithmToNone(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return token; // Not a valid JWT token
        }

        try {
            // Decode the header
            String decodedHeader = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            // Replace the algorithm with "none"
            String modifiedHeader = decodedHeader.replaceAll("\"alg\"\\s*:\\s*\"[^\"]*\"", "\"alg\":\"none\"");
            // Encode the modified header
            String encodedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(modifiedHeader.getBytes(StandardCharsets.UTF_8));

            // Return the modified token
            return encodedHeader + "." + parts[1] + "." + parts[2];
        } catch (Exception e) {
            return token; // In case of any error, return the original token
        }
    }

    /**
     * Changes the algorithm in the header from RS256 to HS256 (algorithm downgrade).
     *
     * @param token the original JWT token
     * @return the tampered token
     */
    private static String downgradeAlgorithm(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return token; // Not a valid JWT token
        }

        try {
            // Decode the header
            String decodedHeader = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            // Replace RS256 with HS256
            String modifiedHeader = decodedHeader.replaceAll("\"alg\"\\s*:\\s*\"RS256\"", "\"alg\":\"HS256\"");
            // Encode the modified header
            String encodedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(modifiedHeader.getBytes(StandardCharsets.UTF_8));

            // Return the modified token
            return encodedHeader + "." + parts[1] + "." + parts[2];
        } catch (Exception e) {
            return token; // In case of any error, return the original token
        }
    }

    /**
     * Uses a completely different signature.
     *
     * @param token the original JWT token
     * @return the tampered token
     */
    private static String useDifferentSignature(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return token; // Not a valid JWT token
        }

        try {
            // Create a completely different signature
            // We'll just reverse the original signature to make it invalid
            String originalSignature = parts[2];
            StringBuilder reversedSignature = new StringBuilder(originalSignature).reverse();

            // If the reversed signature is the same as the original (e.g., for palindromes),
            // change a character to ensure it's different
            if (reversedSignature.toString().equals(originalSignature) && !originalSignature.isEmpty()) {
                char firstChar = reversedSignature.charAt(0);
                reversedSignature.setCharAt(0, (firstChar == 'A') ? 'B' : 'A');
            }

            // Return the original token with the different signature
            return parts[0] + "." + parts[1] + "." + reversedSignature;
        } catch (Exception e) {
            return token; // In case of any error, return the original token
        }
    }

    /**
     * Changes the key ID (kid) in the header to an invalid value.
     *
     * @param token the original JWT token
     * @return the tampered token
     */
    private static String changeKeyIdToInvalid(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return token; // Not a valid JWT token
        }

        try {
            // Decode the header
            String decodedHeader = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            // Replace the kid with an invalid value
            String modifiedHeader = decodedHeader.replaceAll("\"kid\"\\s*:\\s*\"[^\"]*\"", "\"kid\":\"invalid-key-id\"");
            // Encode the modified header
            String encodedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(modifiedHeader.getBytes(StandardCharsets.UTF_8));

            // Return the modified token
            return encodedHeader + "." + parts[1] + "." + parts[2];
        } catch (Exception e) {
            return token; // In case of any error, return the original token
        }
    }

    /**
     * Removes the key ID (kid) from the header.
     *
     * @param token the original JWT token
     * @return the tampered token
     */
    private static String removeKeyId(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return token; // Not a valid JWT token
        }

        try {
            // Decode the header
            String decodedHeader = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            // Remove the kid claim
            String modifiedHeader = decodedHeader.replaceAll(",?\\s*\"kid\"\\s*:\\s*\"[^\"]*\"", "");
            // Encode the modified header
            String encodedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(modifiedHeader.getBytes(StandardCharsets.UTF_8));

            // Return the modified token
            return encodedHeader + "." + parts[1] + "." + parts[2];
        } catch (Exception e) {
            return token; // In case of any error, return the original token
        }
    }
}

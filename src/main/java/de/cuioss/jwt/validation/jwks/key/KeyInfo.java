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
package de.cuioss.jwt.validation.jwks.key;

import lombok.Getter;
import lombok.NonNull;
import lombok.Value;

import java.security.PublicKey;

/**
 * Class that holds information about a key, including the key itself and its algorithm.
 * <p>
 * This class is used to store keys along with their algorithm information to support
 * cryptographic agility.
 * <p>
 * Implements requirement: {@code CUI-JWT-8.5: Cryptographic Agility}
 * <p>
 * For more details on the security aspects, see the
 * <a href="../../../../../../../doc/specification/security.adoc">Security Specification</a>.
 *
 * @author Oliver Wolff
 */
@Value
public class KeyInfo {

    /**
     * The public key used for JWT signature verification.
     * <p>
     * This is the cryptographic key extracted from the JWK that will be used
     * to verify the signature of JWT tokens. It's typically an RSA or EC public key.
     */
    @Getter
    @NonNull
    PublicKey key;

    /**
     * The algorithm identifier associated with this key.
     * <p>
     * This field contains the algorithm name (e.g., "RS256", "ES384") that should be
     * used with this key for signature verification. The algorithm must match the
     * "alg" header in the JWT validation for successful verification.
     * <p>
     * Common values include:
     * <ul>
     *   <li>RS256 - RSA Signature with SHA-256</li>
     *   <li>RS384 - RSA Signature with SHA-384</li>
     *   <li>RS512 - RSA Signature with SHA-512</li>
     *   <li>ES256 - ECDSA Signature with SHA-256</li>
     *   <li>ES384 - ECDSA Signature with SHA-384</li>
     *   <li>ES512 - ECDSA Signature with SHA-512</li>
     * </ul>
     */
    @Getter
    @NonNull
    String algorithm;

    /**
     * The unique identifier for this key.
     * <p>
     * This is the "kid" (Key ID) value from the JWK, which is used to identify
     * the specific key within a JWKS. When verifying a JWT validation, the "kid" in the
     * validation header is matched against this value to select the correct key for
     * signature verification.
     * <p>
     * Key IDs are particularly important in environments with key rotation, where
     * multiple valid keys may exist simultaneously.
     */
    @Getter
    @NonNull
    String keyId;
}

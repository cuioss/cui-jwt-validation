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
package de.cuioss.jwt.validation.pipeline;

import de.cuioss.jwt.validation.domain.claim.ClaimName;
import jakarta.json.JsonObject;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.util.Optional;

/**
 * Class representing a decoded JWT token.
 * <p>
 * This class holds the parsed components of a JWT token after Base64 decoding and JSON parsing,
 * but before any validation occurs. It contains:
 * <ul>
 *   <li>The decoded header as a JsonObject</li>
 *   <li>The decoded payload (body) as a JsonObject</li>
 *   <li>The signature part as a String</li>
 *   <li>Convenience methods for accessing common JWT fields</li>
 *   <li>The original token parts and raw token string</li>
 * </ul>
 * <p>
 * <strong>Security Note:</strong> This class is not guaranteed to contain a validated token.
 * It is usually created by {@link NonValidatingJwtParser} and should be passed to
 * {@link TokenHeaderValidator}, {@link TokenSignatureValidator}, and {@link TokenClaimValidator}
 * for proper validation.
 * <p>
 * For more details on the token validation process, see the
 * <a href="https://github.com/cuioss/cui-jwt-validation/tree/main/doc/specification/technical-components.adoc#token-validation-pipeline">Token Validation Pipeline</a>
 *
 * @author Oliver Wolff
 * @since 1.0
 */
@ToString
@EqualsAndHashCode
@Builder
@AllArgsConstructor
public class DecodedJwt {
    private final JsonObject header;
    private final JsonObject body;
    private final String signature;
    private final String issuer;
    private final String kid;
    private final String alg;
    @Getter
    private final String[] parts;
    @Getter
    private final String rawToken;

    /**
     * Constructor for DecodedJwt.
     *
     * @param header    the decoded header as a JsonObject
     * @param body      the decoded body as a JsonObject
     * @param signature the signature part as a String
     * @param parts     the original token parts
     * @param rawToken  the original raw token string
     */
    public DecodedJwt(JsonObject header, JsonObject body, String signature, String[] parts, String rawToken) {
        this.header = header;
        this.body = body;
        this.signature = signature;
        this.parts = parts;
        this.rawToken = rawToken;

        // Extract issuer from body if present
        this.issuer = body != null && body.containsKey(ClaimName.ISSUER.getName()) ? body.getString(ClaimName.ISSUER.getName()) : null;

        // Extract kid from header if present
        this.kid = header != null && header.containsKey("kid") ? header.getString("kid") : null;

        // Extract alg from header if present
        this.alg = header != null && header.containsKey("alg") ? header.getString("alg") : null;
    }

    /**
     * Gets the header of the JWT token.
     *
     * @return an Optional containing the header if present
     */
    public Optional<JsonObject> getHeader() {
        return Optional.ofNullable(header);
    }

    /**
     * Gets the body of the JWT token.
     *
     * @return an Optional containing the body if present
     */
    public Optional<JsonObject> getBody() {
        return Optional.ofNullable(body);
    }

    /**
     * Gets the signature of the JWT token.
     *
     * @return an Optional containing the signature if present
     */
    public Optional<String> getSignature() {
        return Optional.ofNullable(signature);
    }

    /**
     * Gets the issuer of the JWT token.
     *
     * @return an Optional containing the issuer if present
     */
    public Optional<String> getIssuer() {
        return Optional.ofNullable(issuer);
    }

    /**
     * Gets the kid (key ID) from the JWT token header.
     *
     * @return an Optional containing the kid if present
     */
    public Optional<String> getKid() {
        return Optional.ofNullable(kid);
    }

    /**
     * Gets the alg (algorithm) from the JWT token header.
     *
     * @return an Optional containing the algorithm if present
     */
    public Optional<String> getAlg() {
        return Optional.ofNullable(alg);
    }
}

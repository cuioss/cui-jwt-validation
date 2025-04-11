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

import de.cuioss.jwt.token.TokenType;
import de.cuioss.jwt.token.flow.DecodedJwt;
import de.cuioss.test.generator.TypedGenerator;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * Generator for DecodedJwt instances.
 * Can be configured with different {@link TokenType} values to generate
 * appropriate token content.
 */
public class DecodedJwtGenerator implements TypedGenerator<DecodedJwt> {

    private static final String DEFAULT_KEY_ID = "default-key-id";
    private static final String DEFAULT_ISSUER = "test-issuer";
    private static final String DEFAULT_SUBJECT = "test-subject";
    private static final String DEFAULT_AUDIENCE = "test-audience";

    private final TokenType tokenType;

    /**
     * Constructor with token type.
     *
     * @param tokenType the type of token to generate
     */
    public DecodedJwtGenerator(TokenType tokenType) {
        this.tokenType = tokenType;
    }

    /**
     * Default constructor that creates ACCESS_TOKEN type.
     */
    public DecodedJwtGenerator() {
        this(TokenType.ACCESS_TOKEN);
    }

    @Override
    public DecodedJwt next() {
        try {
            // Create header with appropriate values
            JsonObjectBuilder headerBuilder = Json.createObjectBuilder()
                    .add("alg", "RS256")
                    .add("typ", "JWT")
                    .add("kid", DEFAULT_KEY_ID);

            // Create body with appropriate values based on token type
            JsonObjectBuilder bodyBuilder = Json.createObjectBuilder()
                    .add("iss", DEFAULT_ISSUER)
                    .add("sub", DEFAULT_SUBJECT)
                    .add("iat", Date.from(Instant.now()).getTime() / 1000)
                    .add("exp", Date.from(Instant.now().plusSeconds(3600)).getTime() / 1000)
                    .add("jti", UUID.randomUUID().toString());

            // Add type-specific claims
            switch (tokenType) {
                case ACCESS_TOKEN:
                    bodyBuilder.add("typ", TokenType.ACCESS_TOKEN.getTypeClaimName())
                            .add("scope", "openid profile email");
                    break;
                case ID_TOKEN:
                    bodyBuilder.add("typ", TokenType.ID_TOKEN.getTypeClaimName())
                            .add("aud", DEFAULT_AUDIENCE)
                            .add("email", "test@example.com");
                    break;
                case REFRESH_TOKEN:
                    bodyBuilder.add("typ", TokenType.REFRESH_TOKEN.getTypeClaimName());
                    break;
                case UNKNOWN:
                default:
                    bodyBuilder.add("typ", "unknown");
                    break;
            }

            // Build the JSON objects
            JsonObject header = headerBuilder.build();
            JsonObject body = bodyBuilder.build();

            // Create a signature (not actually used for validation in tests)
            String signature = "test-signature";

            // Generate a unique identifier for this token
            String uniqueId = UUID.randomUUID().toString();

            // Create token parts with unique identifier
            String[] parts = new String[]{"header-part-" + uniqueId, "body-part-" + uniqueId, "signature-part-" + uniqueId};

            // Create raw token with unique identifier
            String rawToken = parts[0] + "." + parts[1] + "." + parts[2];

            // Create and return the DecodedJwt
            return new DecodedJwt(header, body, signature, parts, rawToken);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate DecodedJwt", e);
        }
    }
}

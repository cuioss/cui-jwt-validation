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
package de.cuioss.jwt.token;

import de.cuioss.jwt.token.adapter.JsonWebToken;
import de.cuioss.tools.logging.CuiLogger;
import lombok.ToString;

import java.util.Optional;

/**
 * Represents a parsed OpenID Connect ID token.
 * Provides access to identity information claims as specified by the OpenID Connect Core specification.
 * <p>
 * Key features:
 * <ul>
 *   <li>Email claim access</li>
 *   <li>Token validation and parsing</li>
 *   <li>Type verification (expects "ID" type claim)</li>
 * </ul>
 * <p>
 * Note: This implementation is primarily tested with Keycloak ID tokens.
 * While it follows OpenID Connect standards, some behavior may be specific to Keycloak.
 * <p>
 * Usage example:
 * <pre>
 * TokenFactory factory = TokenFactory.builder()
 *     .addParser(parser)
 *     .build();
 * Optional&lt;ParsedIdToken&gt; token = factory.createIdToken(tokenString);
 * token.flatMap(ParsedIdToken::getEmail).ifPresent(email -> {
 *     // Process user's email
 * });
 * </pre>
 *
 * @author Oliver Wolff
 * @see ParsedToken
 */
@ToString
public class ParsedIdToken extends ParsedToken {

    private static final CuiLogger LOGGER = new CuiLogger(ParsedIdToken.class);

    /**
     * Creates a new {@link ParsedIdToken} from the given JsonWebToken.
     *
     * @param jsonWebToken The JsonWebToken to wrap, must not be null
     */
    public ParsedIdToken(JsonWebToken jsonWebToken) {
        super(jsonWebToken);
        LOGGER.debug("Successfully created ID token");
    }

    /**
     * Resolves the email from the token. Only available, if the current token is an ID token.
     *
     * @return email if present
     */
    public Optional<String> getEmail() {
        LOGGER.debug("Retrieving email from ID token");
        Optional<String> email = jsonWebToken.claim(de.cuioss.jwt.token.adapter.Claims.EMAIL);
        if (email.isEmpty()) {
            LOGGER.debug("No email claim found in ID token");
        } else {
            LOGGER.debug("Found email in ID token: %s", email.get());
        }
        return email;
    }
}

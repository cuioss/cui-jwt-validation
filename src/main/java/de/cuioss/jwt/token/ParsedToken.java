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

import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.MoreStrings;
import io.smallrye.jwt.auth.principal.JWTParser;
import io.smallrye.jwt.auth.principal.ParseException;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.eclipse.microprofile.jwt.JsonWebToken;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.Optional;

import static de.cuioss.tools.string.MoreStrings.trimOrNull;

/**
 * Abstract base class for parsed JWT token representations.
 * Provides common functionality for working with {@link JsonWebToken} instances
 * including token validation, expiration checking, and type determination.
 * <p>
 * Key features:
 * <ul>
 *   <li>Token parsing and validation</li>
 *   <li>Expiration time management</li>
 *   <li>Token type determination via "typ" claim</li>
 *   <li>Access to raw token string and JWT claims</li>
 * </ul>
 * <p>
 * Concrete implementations are available for specific token types:
 * <ul>
 *   <li>{@link ParsedAccessToken}: For OAuth2 access tokens</li>
 *   <li>{@link ParsedIdToken}: For OpenID Connect ID tokens</li>
 *   <li>{@link ParsedRefreshToken}: For OAuth2 refresh tokens</li>
 * </ul>
 * <p>
 * Note: The implementation is primarily tested with Keycloak tokens.
 * Some features may be specific to Keycloak's token format.
 *
 * @author Oliver Wolff
 */
@RequiredArgsConstructor
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public abstract class ParsedToken {

    /**
     * @return the token as encoded String.
     */
    public String getTokenString() {
        return jsonWebToken.getRawToken();
    }

    protected static Optional<JsonWebToken> jsonWebTokenFrom(String tokenString, JWTParser tokenParser, CuiLogger givenLogger) {
        givenLogger.trace("Parsing token '%s'", tokenString);
        if (MoreStrings.isEmpty(trimOrNull(tokenString))) {
            givenLogger.warn(PortalTokenLogMessages.WARN.TOKEN_IS_EMPTY::format);
            return Optional.empty();
        }
        try {
            return Optional.ofNullable(tokenParser.parse(tokenString));
        } catch (ParseException e) {
            givenLogger.warn(e, PortalTokenLogMessages.WARN.COULD_NOT_PARSE_TOKEN.format(e.getMessage()));
            givenLogger.trace("Offending token '%s'", tokenString);
            return Optional.empty();
        }
    }

    @Getter
    @EqualsAndHashCode.Include
    protected final JsonWebToken jsonWebToken;

    /**
     * @return boolean indicating whether the token is already expired. Shorthand for
     * {@link #willExpireInSeconds(int)}
     * with '0'.
     */
    public boolean isExpired() {
        return willExpireInSeconds(0);
    }

    /**
     * @param seconds maybe {@code 0}. Calling it with a negative number is not defined.
     * @return boolean indicating whether the token will expired within the given number of seconds.
     */
    public boolean willExpireInSeconds(int seconds) {
        return OffsetDateTime.now().plusSeconds(seconds).isAfter(getExpirationTime());
    }

    /**
     * Extracts the {@link TokenType} from the claim "type."
     * <em>Caution:</em> This is only tested for keycloak.
     * The claim 'typ' is not from the oauth spec.
     */
    public TokenType getType() {
        return TokenType.fromTypClaim(jsonWebToken.getClaim("typ"));
    }

    /**
     * @return {@link OffsetDateTime} representation of the expiration-Time
     */
    public OffsetDateTime getExpirationTime() {
        return OffsetDateTime
                .ofInstant(Instant.ofEpochSecond(jsonWebToken.getExpirationTime()), ZoneId.systemDefault());
    }

    /**
     * @return the subject from the underlying JWT token
     */
    public String getSubject() {
        return jsonWebToken.getSubject();
    }

    /**
     * @return the issuer from the underlying JWT token
     */
    public String getIssuer() {
        return jsonWebToken.getIssuer();
    }
    
    /**
     * Returns the "Not Before" time from the token if present.
     * The "nbf" (not before) claim identifies the time before which the JWT must not be accepted for processing.
     * This claim is optional, according to the JWT specification (RFC 7519).
     * 
     * @return an {@link Optional} containing the {@link OffsetDateTime} representation of the "Not Before" time
     *         if the claim is present, or an empty Optional if not
     */
    public Optional<OffsetDateTime> getNotBeforeTime() {
        Long notBeforeTime = jsonWebToken.getClaim("nbf");
        if (notBeforeTime == null) {
            return Optional.empty();
        }
        return Optional.of(OffsetDateTime
                .ofInstant(Instant.ofEpochSecond(notBeforeTime), ZoneId.systemDefault()));
    }
}

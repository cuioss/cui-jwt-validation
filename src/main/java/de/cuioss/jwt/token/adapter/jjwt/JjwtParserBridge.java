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
package de.cuioss.jwt.token.adapter.jjwt;

import de.cuioss.jwt.token.JwtParser;
import de.cuioss.jwt.token.ParsedAccessToken;
import de.cuioss.jwt.token.ParsedIdToken;
import de.cuioss.jwt.token.ParsedRefreshToken;
import de.cuioss.jwt.token.adapter.JsonWebToken;
import de.cuioss.jwt.token.jwks.key.KeyInfo;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.util.Optional;

/**
 * JJWT-specific implementation of {@link JwtParser}.
 * Acts as a bridge between the old JJWT-specific parser and the new domain model.
 */
@RequiredArgsConstructor
public class JjwtParserBridge implements JwtParser {

    private final JwtParser delegate;

    @Override
    public Optional<Jws<Claims>> parseToken(String token) throws JwtException {
        return delegate.parseToken(token);
    }

    @Override
    public Optional<JsonWebToken> parse(String token) throws JwtException {
        return delegate.parse(token);
    }

    @Override
    public Optional<ParsedAccessToken> createAccessToken(@NonNull String tokenString, @NonNull KeyInfo keyInfo) {
        return delegate.parse(tokenString)
                .map(jwt -> new ParsedAccessToken(jwt, null));
    }

    @Override
    public Optional<ParsedAccessToken> createAccessToken(@NonNull String tokenString, @NonNull KeyInfo keyInfo, String email) {
        return delegate.parse(tokenString)
                .map(jwt -> new ParsedAccessToken(jwt, email));
    }

    @Override
    public Optional<ParsedIdToken> createIdToken(@NonNull String tokenString, @NonNull KeyInfo keyInfo) {
        return delegate.parse(tokenString)
                .map(ParsedIdToken::new);
    }

    @Override
    public Optional<ParsedRefreshToken> createRefreshToken(@NonNull String tokenString, KeyInfo keyInfo) {
        return delegate.parse(tokenString)
                .map(jwt -> new ParsedRefreshToken(tokenString, jwt))
                .or(() -> Optional.of(new ParsedRefreshToken(tokenString)));
    }

    @Override
    public boolean supportsIssuer(String issuer) {
        return delegate.supportsIssuer(issuer);
    }

    @Override
    public String getIssuer() {
        return delegate.getIssuer();
    }
}
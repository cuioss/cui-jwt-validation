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

import de.cuioss.test.generator.Generators;
import io.smallrye.jwt.auth.principal.DefaultJWTParser;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTParser;
import io.smallrye.jwt.auth.principal.ParseException;
import io.smallrye.jwt.build.Jwt;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneId;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class TestTokenProducer {

    public static final String ISSUER = "Token-Test-testIssuer";

    public static final String BASE_PATH = "src/test/resources/token/";

    public static final String PRIVATE_KEY = BASE_PATH + "test-private-key.pkcs8";

    public static final String PUBLIC_KEY = BASE_PATH + "test-public-key.pub";

    public static final String PUBLIC_KEY_OTHER = BASE_PATH + "other-public-key.pub";

    public static final String SOME_SCOPES = BASE_PATH + "some-scopes.json";

    public static final String REFRESH_TOKEN = BASE_PATH + "refresh-token.json";

    public static final String SOME_ROLES = BASE_PATH + "some-roles.json";

    public static final String SOME_NAME = BASE_PATH + "some-name.json";

    public static final String SOME_ID_TOKEN = BASE_PATH + "some-id-token.json";

    public static final String WRONG_ISSUER = Generators.nonBlankStrings().next();

    public static final JWTAuthContextInfo TEST_AUTH_CONTEXT_INFO = new JWTAuthContextInfo(PUBLIC_KEY, ISSUER);

    public static final JWTAuthContextInfo TEST_AUTH_CONTEXT_INFO_WRONG_PUBLIC_KEY = new JWTAuthContextInfo(
            PUBLIC_KEY_OTHER, ISSUER);

    public static final JWTAuthContextInfo TEST_AUTH_CONTEXT_INFO_WRONG_ISSUER = new JWTAuthContextInfo(PUBLIC_KEY,
            WRONG_ISSUER);

    public static final JWTParser DEFAULT_TOKEN_PARSER = new DefaultJWTParser(TEST_AUTH_CONTEXT_INFO);

    public static final JWTParser WRONG_ISSUER_TOKEN_PARSER = new DefaultJWTParser(TEST_AUTH_CONTEXT_INFO_WRONG_ISSUER);


    public static final JWTParser WRONG_SIGNATURE_TOKEN_PARSER = new DefaultJWTParser(
            TEST_AUTH_CONTEXT_INFO_WRONG_PUBLIC_KEY);

    public static final String SUBJECT = Generators.letterStrings(10, 12).next();

    public static String validSignedJWTWithClaims(String claims) {
        return Jwt.claims(claims).issuer(ISSUER).subject(SUBJECT).sign(PRIVATE_KEY);
    }

    public static String validSignedEmptyJWT() {
        return Jwt.claims().issuer(ISSUER).subject(SUBJECT).sign(PRIVATE_KEY);
    }

    public static String validSignedJWTWithClaims(String claims, String subject) {
        return Jwt.claims(claims).issuer(ISSUER).subject(subject).sign(PRIVATE_KEY);
    }

    public static String validSignedJWTExpireAt(Instant expireAt) {
        return Jwt.claims(SOME_SCOPES).issuer(ISSUER)
                .issuedAt(OffsetDateTime.ofInstant(expireAt, ZoneId.systemDefault()).minusMinutes(5).toInstant())
                .subject(SUBJECT).expiresAt(expireAt).sign(PRIVATE_KEY);
    }

    /**
     * Creates a valid signed JWT with a "Not Before" (nbf) claim
     *
     * @param notBefore the instant representing the "Not Before" time
     * @return a signed JWT token string with the nbf claim set
     */
    public static String validSignedJWTWithNotBefore(Instant notBefore) {
        return Jwt.claims(SOME_SCOPES).issuer(ISSUER)
                .issuedAt(OffsetDateTime.ofInstant(notBefore, ZoneId.systemDefault()).minusMinutes(5).toInstant())
                .subject(SUBJECT)
                .expiresAt(OffsetDateTime.ofInstant(notBefore, ZoneId.systemDefault()).plusMinutes(10).toInstant())
                .claim("nbf", notBefore.getEpochSecond())
                .sign(PRIVATE_KEY);
    }

    @Test
    void shouldCreateScopesAndClaims() throws ParseException {
        String token = validSignedJWTWithClaims(SOME_SCOPES);
        assertNotNull(token);

        DefaultJWTParser parser = new DefaultJWTParser(TEST_AUTH_CONTEXT_INFO);

        JsonWebToken parsedToken = parser.parse(token);
        assertNotNull(parsedToken);
    }
}

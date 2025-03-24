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
package de.cuioss.jwt.token.adapter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Adapter class that implements the JsonWebToken interface using JJWT's Jws&lt;Claims&gt;.
 * This allows the existing ParsedToken and derived classes to continue working with the new
 * JJWT implementation without changes to their API.
 * <p>
 * The adapter maps between the JsonWebToken interface methods and the corresponding
 * methods in JJWT's Jws&lt;Claims&gt; class.
 *
 * @author Oliver Wolff
 */
@ToString
@EqualsAndHashCode
@RequiredArgsConstructor
public class JwtAdapter implements JsonWebToken {

    private final Jws<Claims> jws;

    @Getter
    private final String rawToken;

    @Override
    public Optional<String> getName() {
        return Optional.ofNullable(getClaim("name"));
    }

    @Override
    public Set<String> getClaimNames() {
        return jws.getBody().keySet();
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T> T getClaim(String claimName) {
        return (T) jws.getBody().get(claimName);
    }

    @Override
    public String getIssuer() {
        return jws.getBody().getIssuer();
    }

    @Override
    public String getSubject() {
        return jws.getBody().getSubject();
    }

    @Override
    public Optional<Set<String>> getAudience() {
        Object audience = jws.getBody().get(de.cuioss.jwt.token.adapter.Claims.AUDIENCE);
        if (audience == null) {
            return Optional.empty();
        }
        if (audience instanceof List<?> list) {
            Set<String> result = list.stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .collect(Collectors.toSet());
            return Optional.of(result);
        }
        if (audience instanceof String string) {
            return Optional.of(Set.of(string));
        }
        return Optional.empty();
    }

    @Override
    public OffsetDateTime getExpirationTime() {
        if (jws.getBody().getExpiration() == null) {
            // Return epoch start as a fallback for missing expiration
            return OffsetDateTime.ofInstant(Instant.EPOCH, ZoneId.systemDefault());
        }
        return OffsetDateTime.ofInstant(
                Instant.ofEpochMilli(jws.getBody().getExpiration().getTime()),
                ZoneId.systemDefault());
    }

    @Override
    public OffsetDateTime getIssuedAtTime() {
        if (jws.getBody().getIssuedAt() == null) {
            // Return epoch start as a fallback for missing issuedAt
            return OffsetDateTime.ofInstant(Instant.EPOCH, ZoneId.systemDefault());
        }
        return OffsetDateTime.ofInstant(
                Instant.ofEpochMilli(jws.getBody().getIssuedAt().getTime()),
                ZoneId.systemDefault());
    }

    @Override
    public Optional<OffsetDateTime> getNotBeforeTime() {
        Object nbf = jws.getBody().get(de.cuioss.jwt.token.adapter.Claims.NOT_BEFORE);
        if (nbf == null) {
            return Optional.empty();
        }

        long epochSecond;
        if (nbf instanceof Long longValue) {
            epochSecond = longValue;
        } else if (nbf instanceof Integer integerValue) {
            epochSecond = integerValue.longValue();
        } else if (nbf instanceof Number number) {
            epochSecond = number.longValue();
        } else if (nbf instanceof java.util.Date date) {
            return Optional.of(OffsetDateTime.ofInstant(date.toInstant(), ZoneId.systemDefault()));
        } else {
            return Optional.empty();
        }

        return Optional.of(OffsetDateTime.ofInstant(Instant.ofEpochSecond(epochSecond), ZoneId.systemDefault()));
    }

    @Override
    public Optional<String> getTokenID() {
        return Optional.ofNullable(jws.getBody().getId());
    }


    /**
     * Gets a claim as an Optional.
     * This method is used by ParsedToken and derived classes.
     *
     * @param name the name of the claim
     * @param <T> the type of the claim
     * @return an Optional containing the claim value, or empty if the claim is not present
     */
    public <T> Optional<T> claim(String name) {
        T value = getClaim(name);
        return Optional.ofNullable(value);
    }
}

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

import de.cuioss.jwt.token.adapter.JsonWebToken;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.io.Serial;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Adapter for JJWT's Jws&lt;Claims&gt; type that implements JsonWebToken.
 * Encapsulates JJWT implementation details and provides a consistent interface.
 */
@ToString
@EqualsAndHashCode
public class JjwtAdapter implements JsonWebToken {

    @Serial
    private static final long serialVersionUID = 1L;

    @Getter
    private final Jws<Claims> jws;

    @Getter
    private final String rawToken;

    /**
     * Creates a new JjwtAdapter.
     *
     * @param jws the JJWT Claims object
     * @param rawToken the original token string
     */
    public JjwtAdapter(Jws<Claims> jws, String rawToken) {
        this.jws = jws;
        this.rawToken = rawToken;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Optional<String> getName() {
        return claim("name");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Set<String> getClaimNames() {
        Set<String> claimNames = new HashSet<>(jws.getPayload().keySet());
        return claimNames;
    }

    /**
     * {@inheritDoc}
     */
    @SuppressWarnings("unchecked")
    @Override
    public <T> T getClaim(String claimName) {
        return (T) jws.getPayload().get(claimName);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getIssuer() {
        return jws.getPayload().getIssuer();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getSubject() {
        return jws.getPayload().getSubject();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @SuppressWarnings("unchecked")
    public Optional<Set<String>> getAudience() {
        Object aud = jws.getPayload().getAudience();
        if (aud == null) {
            return Optional.empty();
        }
        if (aud instanceof String string) {
            return Optional.of(Set.of(string));
        }
        if (aud instanceof List) {
            try {
                Set<String> audience = ((List<String>) aud).stream()
                        .collect(Collectors.toSet());
                return Optional.of(audience);
            } catch (ClassCastException e) {
                return Optional.empty();
            }
        }
        return Optional.empty();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public OffsetDateTime getExpirationTime() {
        Date expDate = jws.getPayload().getExpiration();
        return convertDateToOffsetDateTime(expDate);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public OffsetDateTime getIssuedAtTime() {
        Date issuedAt = jws.getPayload().getIssuedAt();
        return convertDateToOffsetDateTime(issuedAt);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Optional<OffsetDateTime> getNotBeforeTime() {
        Date notBefore = jws.getPayload().getNotBefore();
        return Optional.ofNullable(notBefore)
                .map(this::convertDateToOffsetDateTime);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Optional<String> getTokenID() {
        return Optional.ofNullable(jws.getPayload().getId());
    }

    /**
     * Converts a Date to an OffsetDateTime.
     *
     * @param date the Date to convert
     * @return the equivalent OffsetDateTime
     */
    private OffsetDateTime convertDateToOffsetDateTime(Date date) {
        if (date == null) {
            return OffsetDateTime.now(); // Default to now if null
        }
        Instant instant = date.toInstant();
        return OffsetDateTime.ofInstant(instant, ZoneId.systemDefault());
    }
}
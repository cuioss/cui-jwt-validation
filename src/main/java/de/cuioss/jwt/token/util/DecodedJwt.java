package de.cuioss.jwt.token.util;

import de.cuioss.jwt.token.adapter.Claims;
import jakarta.json.JsonObject;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.util.Optional;

/**
 * Class representing a decoded JWT token.
 * Contains the decoded header, body, signature, issuer, and kid-header.
 * <em>Caution: </em> This class is not guaranteed to be validated.
 * It is usually created by {@link NonValidatingJwtParser}.
 */
@ToString
@EqualsAndHashCode
public class DecodedJwt {
    private final JsonObject header;
    private final JsonObject body;
    private final String signature;
    private final String issuer;
    private final String kid;
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
    DecodedJwt(JsonObject header, JsonObject body, String signature, String[] parts, String rawToken) {
        this.header = header;
        this.body = body;
        this.signature = signature;
        this.parts = parts;
        this.rawToken = rawToken;

        // Extract issuer from body if present
        this.issuer = body != null && body.containsKey(Claims.ISSUER) ? body.getString(Claims.ISSUER) : null;

        // Extract kid from header if present
        this.kid = header != null && header.containsKey("kid") ? header.getString("kid") : null;
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
}

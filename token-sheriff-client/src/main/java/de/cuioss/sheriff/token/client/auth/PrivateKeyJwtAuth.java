/*
 * Copyright © 2025-present CUI-OpenSource-Software (info@cuioss.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.sheriff.token.client.auth;

import de.cuioss.sheriff.token.client.config.ClientAuthMethod;
import de.cuioss.sheriff.token.client.internal.JsonEscaper;
import de.cuioss.sheriff.token.validation.security.JwsAlgorithm;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PSSParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * {@code private_key_jwt} client authentication (RFC 7523 / RFC 7521): the client authenticates with
 * a short-lived JWT assertion signed by its private key, so no shared secret ever leaves the client.
 * <p>
 * The assertion is signed with a JDK {@link Signature} — the engine adds no cryptographic library of
 * its own. The supported JOSE signing algorithms are the RSA PKCS#1 v1.5 family
 * ({@code RS256} / {@code RS384} / {@code RS512}), the RSASSA-PSS family
 * ({@code PS256} / {@code PS384} / {@code PS512}), and the ECDSA family
 * ({@code ES256} / {@code ES384} / {@code ES512}, emitted in the JOSE-required IEEE P1363
 * {@code R||S} format). The signing key must match the chosen algorithm family.
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7523">RFC 7523 - JWT Client Authentication</a>
 */
public class PrivateKeyJwtAuth implements ClientAuthentication {

    private static final String PARAM_CLIENT_ASSERTION_TYPE = "client_assertion_type";
    private static final String PARAM_CLIENT_ASSERTION = "client_assertion";
    private static final String ASSERTION_TYPE_JWT_BEARER =
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private static final long ASSERTION_LIFETIME_SECONDS = 60L;
    private static final Base64.Encoder BASE64_URL = Base64.getUrlEncoder().withoutPadding();

    /**
     * The {@link JwsAlgorithm} subset this authentication method accepts — the RSA and ECDSA
     * families. The subset is declared here rather than inherited from the catalog wholesale
     * because {@code EdDSA} is deliberately not offered for {@code private_key_jwt}.
     */
    static final Set<JwsAlgorithm> SUPPORTED_ALGORITHMS = EnumSet.of(
            JwsAlgorithm.RS256, JwsAlgorithm.RS384, JwsAlgorithm.RS512,
            JwsAlgorithm.PS256, JwsAlgorithm.PS384, JwsAlgorithm.PS512,
            JwsAlgorithm.ES256, JwsAlgorithm.ES384, JwsAlgorithm.ES512);

    private final String clientId;
    private final String audience;
    private final PrivateKey privateKey;
    private final String keyId;
    private final JwsAlgorithm algorithm;
    private final String jcaAlgorithm;

    /**
     * @param clientId   the OAuth 2.0 client id (used as the assertion {@code iss} and {@code sub});
     *                   must not be {@code null}
     * @param audience   the assertion {@code aud} — the token endpoint (or issuer) URL; must not be
     *                   {@code null}
     * @param privateKey the client's signing private key; must not be {@code null}
     * @param keyId      the {@code kid} identifying the public key at the AS; must not be {@code null}
     * @param algorithm  the JWT signing algorithm — one of {@code RS256}/{@code RS384}/{@code RS512},
     *                   {@code PS256}/{@code PS384}/{@code PS512}, or {@code ES256}/{@code ES384}/{@code ES512}
     */
    public PrivateKeyJwtAuth(String clientId, String audience, PrivateKey privateKey, String keyId,
            String algorithm) {
        this.clientId = Objects.requireNonNull(clientId, "clientId must not be null");
        this.audience = Objects.requireNonNull(audience, "audience must not be null");
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey must not be null");
        this.keyId = Objects.requireNonNull(keyId, "keyId must not be null");
        Objects.requireNonNull(algorithm, "algorithm must not be null");
        this.algorithm = requireSupportedAlgorithm(algorithm);
        this.jcaAlgorithm = jcaSignatureAlgorithmOf(this.algorithm);
    }

    @Override
    public ClientAuthMethod method() {
        return ClientAuthMethod.PRIVATE_KEY_JWT;
    }

    @Override
    public void decorate(Map<String, String> formParameters, Map<String, String> requestHeaders) {
        formParameters.put(PARAM_CLIENT_ASSERTION_TYPE, ASSERTION_TYPE_JWT_BEARER);
        formParameters.put(PARAM_CLIENT_ASSERTION, buildAssertion());
    }

    private String buildAssertion() {
        long now = Instant.now().getEpochSecond();
        String header = "{\"alg\":\"" + algorithm.getJwaName() + "\",\"typ\":\"JWT\",\"kid\":\""
                + JsonEscaper.escape(keyId) + "\"}";
        // audience is sourced from the AS's own discovery metadata (token endpoint URL); escape
        // every JSON control character per RFC 8259, not only quote/backslash.
        String payload = "{\"iss\":\"" + JsonEscaper.escape(clientId) + "\",\"sub\":\""
                + JsonEscaper.escape(clientId) + "\",\"aud\":\"" + JsonEscaper.escape(audience)
                + "\",\"jti\":\"" + UUID.randomUUID() + "\",\"iat\":" + now
                + ",\"exp\":" + (now + ASSERTION_LIFETIME_SECONDS) + "}";

        String signingInput = encode(header) + "." + encode(payload);
        return signingInput + "." + sign(signingInput);
    }

    private String sign(String signingInput) {
        try {
            Signature signature = Signature.getInstance(jcaAlgorithm);
            Optional<PSSParameterSpec> pssParameters = algorithm.getPssParameters();
            if (pssParameters.isPresent()) {
                // RSASSA-PSS requires explicit parameters: MGF1 over the same hash and a salt length
                // equal to the digest length, per RFC 7518 §3.5.
                signature.setParameter(pssParameters.get());
            }
            signature.initSign(privateKey);
            signature.update(signingInput.getBytes(StandardCharsets.UTF_8));
            return BASE64_URL.encodeToString(signature.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to sign private_key_jwt client assertion", e);
        }
    }

    private static String encode(String json) {
        return BASE64_URL.encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Resolves a JWA {@code alg} name against the shared catalog and refuses anything outside
     * {@link #SUPPORTED_ALGORITHMS} — the catalog also carries {@code EdDSA}, which this
     * authentication method does not offer.
     *
     * @param algorithm the requested JWT signing algorithm
     * @return the catalog entry for the algorithm
     * @throws IllegalArgumentException if the algorithm is unknown to the catalog or outside the
     *         supported subset
     */
    private static JwsAlgorithm requireSupportedAlgorithm(String algorithm) {
        return JwsAlgorithm.fromJwaName(algorithm)
                .filter(SUPPORTED_ALGORITHMS::contains)
                .orElseThrow(() -> new IllegalArgumentException(
                        "unsupported private_key_jwt signing algorithm: " + algorithm));
    }

    /**
     * Resolves the JCA signature-algorithm name to instantiate for a catalog entry. The catalog
     * leaves the EC family's name open because JCA spells the same algorithm two ways; JOSE ECDSA
     * signatures are the raw {@code R||S} concatenation (RFC 7518 §3.4), so this call site composes
     * the in-P1363-format spelling.
     *
     * @param algorithm the catalog entry to resolve
     * @return the JCA signature-algorithm name
     */
    private static String jcaSignatureAlgorithmOf(JwsAlgorithm algorithm) {
        return algorithm.getJcaSignatureAlgorithm().orElseGet(
                () -> algorithm.getDigest().orElseThrow().replace("-", "") + "withECDSAinP1363Format");
    }
}

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
package de.cuioss.sheriff.token.integration.client;

import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.discovery.ProviderMetadata;
import de.cuioss.sheriff.token.client.flow.CredentialRejectedException;
import de.cuioss.sheriff.token.client.flow.RedeemedRefreshFailure;
import de.cuioss.sheriff.token.client.flow.RefreshFailureClassification;
import de.cuioss.sheriff.token.client.flow.RefreshFlow;
import de.cuioss.sheriff.token.client.token.RotationResult;
import de.cuioss.sheriff.token.client.token.TokenValidationBridge;
import de.cuioss.sheriff.token.commons.error.TransportException;
import de.cuioss.sheriff.token.integration.BaseIntegrationTest;
import de.cuioss.sheriff.token.integration.TestRealm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Drives the production {@link RefreshFlow} against an authorization server that enforces
 * <em>single-use</em> refresh tokens.
 *
 * <h2>Deployment premise</h2>
 * The {@code single-use-refresh} realm sets {@code revokeRefreshToken=true} with
 * {@code refreshTokenMaxReuse=0}, so Keycloak revokes a refresh token the moment it is redeemed and
 * refuses any later presentation of it. Both are <em>realm</em> settings in Keycloak, which is why this
 * needs a realm of its own rather than another client in the {@code client-engine} realm: enabling them
 * there would silently change the posture every other client-engine spec depends on — notably
 * {@link RefreshErrorPathSpecIT}, which records the opposite property.
 * <p>
 * This is the posture the OAuth 2.0 Security BCP recommends, and the one the other refresh specs do
 * <strong>not</strong> run under. Without this spec the engine is only ever observed against a permissive
 * server.
 *
 * <h2>What the reuse attempt proves</h2>
 * The authorization server refuses the second presentation with HTTP 400 {@code invalid_grant}. That
 * refusal is raised by {@code TokenEndpointClient} at the {@code requestToken} call, i.e. on a
 * non-success status, which is <em>before</em> the flow has any redemption state to attach. Per
 * {@link RedeemedRefreshFailure}'s own contract, a failure raised before the server processed the
 * request deliberately does not implement that interface, so nothing is redeemed here and there is no
 * successor to revoke.
 * <p>
 * Nothing redeemed is nonetheless not the same as nothing wrong. {@link RefreshFlow#classify(Throwable)}
 * reports this refusal as {@link RefreshFailureClassification.Kind#CREDENTIAL_REJECTED} — the
 * authorization server looked at the presented refresh token and declared it invalid, which no retry
 * will revive — and it is carried by the {@link CredentialRejectedException} subtype of
 * {@code TransportException}. That is what separates it from
 * {@link RefreshFailureClassification.Kind#PRE_REDEMPTION}, where a connection failure, a DNS failure
 * or a {@code 5xx} leaves the presented token untouched and the session must be kept.
 * <p>
 * {@link RedeemedRefreshFailure} is reachable only <em>after</em> a {@code 2xx} — the
 * {@code RedeemedValidationRefusalException}, {@code RedeemedScopeRefusalException} and
 * {@code RedeemedResponseException} paths — which this path never reaches, which is why the
 * classification carries no redemption.
 *
 * <h2>Family-wide revocation on reuse detection</h2>
 * Detecting the reuse of an already-redeemed refresh token revokes the <em>whole</em> refresh-token
 * family, not only the credential that was replayed: the rotated replacement is refused as well, so the
 * session is gone. That is the response RFC 6749 section 10.4 prescribes when a server detects refresh
 * token replay, and the rule the OAuth 2.0 Security BCP section 4.14.2 states for rotation with reuse
 * detection.
 * <p>
 * The first real run of this spec against the live {@code single-use-refresh} realm falsified the
 * opposite premise it previously asserted — that the rotated replacement stayed usable once the
 * superseded one had been refused. Keycloak refused the rotated replacement with HTTP 400 as well
 * (q-gate finding 3a0c92, recorded alongside plan finding e3a91e below).
 * <p>
 * <strong>Closed exposure (plan finding e3a91e, q-gate finding 3a0c92).</strong> This spec originally
 * recorded an exposure rather than a defence: the engine collapsed "the server burned this credential"
 * and "a transient fault" into one non-redemption verdict, so a caller that kept the session alive was
 * holding a dead credential. ADR-0010 closed that by splitting the pre-redemption region in two, and
 * the assertions below now pin the credential-rejected verdict this realm produces. The fail-safe
 * direction is unchanged: only the single RFC 6749 §5.2 code {@code invalid_grant} on a {@code 4xx}
 * reaches the new verdict, so a network blip still cannot destroy a working session.
 */
@DisplayName("RefreshFlow against a single-use-enforcing Keycloak realm")
class RefreshSingleUseSpecIT extends BaseIntegrationTest {

    private ClientConfiguration configuration;
    private RefreshFlow refreshFlow;
    private ProviderMetadata metadata;

    @BeforeEach
    void assembleEngine() {
        configuration = RefreshEngineSupport.singleUseClientConfiguration(
                RefreshEngineSupport.SINGLE_USE_CLIENT_ID, RefreshEngineSupport.SINGLE_USE_CLIENT_SECRET);
        TokenValidationBridge accessBridge =
                RefreshEngineSupport.accessTokenBridge(RefreshEngineSupport.singleUseTokenValidator());
        refreshFlow = RefreshEngineSupport.refreshFlow(configuration, accessBridge);
        metadata = RefreshEngineSupport.singleUseProviderMetadata();
    }

    @Test
    @DisplayName("Should rotate on the first redemption and refuse the already-redeemed token")
    void shouldRefuseAnAlreadyRedeemedRefreshToken() {
        String initialRefreshToken =
                TestRealm.createSingleUseRefreshRealm().obtainValidToken().refreshToken();
        assertNotNull(initialRefreshToken, "the single-use realm must issue an initial refresh token");

        RotationResult rotation = refreshFlow.refresh(metadata, initialRefreshToken);
        assertAll("the first redemption is an ordinary rotation",
                () -> assertTrue(rotation.rotated(), "the first redemption must rotate the refresh token"),
                () -> assertNotEquals(initialRefreshToken, rotation.refreshToken(),
                        "the rotated refresh token must differ from the redeemed one"),
                () -> assertTrue(rotation.accessToken().getSubject().isPresent(),
                        "the validated access token must be subject bound"),
                () -> assertEquals(RefreshEngineSupport.SINGLE_USE_ISSUER,
                        rotation.accessToken().getIssuer(),
                        "the validated access token must carry the single-use realm's issuer identity"));

        // Re-presenting the token the AS has already redeemed. A realm that had NOT taken the single-use
        // posture would rotate again here, exactly as RefreshErrorPathSpecIT records for the permissive
        // realm — so this assertThrows is what proves the posture actually took effect.
        TransportException refusal = assertThrows(TransportException.class,
                () -> refreshFlow.refresh(metadata, initialRefreshToken),
                "a single-use realm must refuse a refresh token it has already redeemed");

        RefreshFailureClassification classification = RefreshFlow.classify(refusal);
        assertAll("the refusal redeemed nothing, yet is reported as a dead credential",
                () -> assertTrue(refusal.getMessage().contains("400"),
                        "the refusal must report the authorization server's 400 status, was: "
                                + refusal.getMessage()),
                () -> assertInstanceOf(CredentialRejectedException.class, refusal,
                        "a 400 whose RFC 6749 §5.2 body names invalid_grant is the credential-rejected "
                                + "carrier, not a plain transport failure"),
                () -> assertFalse(refusal instanceof RedeemedRefreshFailure,
                        "a non-success HTTP status is raised before any redemption state exists, so it "
                                + "must not implement RedeemedRefreshFailure"),
                () -> assertEquals(RefreshFailureClassification.Kind.CREDENTIAL_REJECTED,
                        classification.kind(),
                        "classify must separate a credential the server declared dead from a transient "
                                + "fault (plan finding e3a91e, closed by ADR-0010)"),
                () -> assertNull(classification.redemption(),
                        "nothing was redeemed, so no successor exists to revoke"),
                () -> assertTrue(RefreshEngineSupport.productionFrame(refusal).isPresent(),
                        "the refusal must be raised from a " + RefreshEngineSupport.PRODUCTION_PACKAGE
                                + "* frame, not from transport code outside the engine"));
    }

    @Test
    void shouldRevokeTheWholeFamilyOnReuseDetection() {
        String initialRefreshToken =
                TestRealm.createSingleUseRefreshRealm().obtainValidToken().refreshToken();
        assertNotNull(initialRefreshToken, "the single-use realm must issue an initial refresh token");

        String rotatedRefreshToken = refreshFlow.refresh(metadata, initialRefreshToken).refreshToken();

        TransportException reuseRefusal = assertThrows(TransportException.class,
                () -> refreshFlow.refresh(metadata, initialRefreshToken),
                "the superseded token must be refused");
        TransportException familyRefusal = assertThrows(TransportException.class,
                () -> refreshFlow.refresh(metadata, rotatedRefreshToken),
                "reuse detection must revoke the whole refresh-token family, so the rotated "
                        + "replacement must be refused too rather than continuing the chain");

        assertAll("no member of the revoked family redeems, so the session is gone",
                () -> assertTrue(reuseRefusal.getMessage().contains("400"),
                        "the reuse refusal must report the authorization server's 400 status, was: "
                                + reuseRefusal.getMessage()),
                () -> assertTrue(familyRefusal.getMessage().contains("400"),
                        "the family-wide revocation must report the authorization server's 400 status, "
                                + "was: " + familyRefusal.getMessage()));
    }
}

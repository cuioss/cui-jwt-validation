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
import de.cuioss.sheriff.token.client.flow.RedeemedRefreshFailure;
import de.cuioss.sheriff.token.client.flow.RefreshFlow;
import de.cuioss.sheriff.token.client.token.RotationResult;
import de.cuioss.sheriff.token.client.token.TokenValidationBridge;
import de.cuioss.sheriff.token.commons.error.TransportException;
import de.cuioss.sheriff.token.integration.BaseIntegrationTest;
import de.cuioss.sheriff.token.integration.TestRealm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

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
 * <h2>What the reuse attempt proves — and the exposure it records</h2>
 * The authorization server refuses the second presentation with HTTP 400 {@code invalid_grant}. That
 * refusal is raised by {@code TokenEndpointClient} at the {@code requestToken} call, i.e. on a
 * non-success status, which is <em>before</em> the flow has any redemption state to attach. Per
 * {@link RedeemedRefreshFailure}'s own contract, a failure raised before the server processed the
 * request — a connection failure, a DNS failure, an SSRF-blocked target, or a non-success HTTP status —
 * deliberately does not implement that interface, and {@link RefreshFlow#refresh} says the same at that
 * call site. {@link RefreshFlow#redemptionOf(Throwable)} therefore returns {@link Optional#empty()} and
 * the engine leaves the presented token in use rather than quarantining the session.
 * <p>
 * {@link RedeemedRefreshFailure} is reachable only <em>after</em> a {@code 2xx} — the
 * {@code RedeemedValidationRefusalException}, {@code RedeemedScopeRefusalException} and
 * {@code RedeemedResponseException} paths — which this path never reaches.
 * <p>
 * <strong>Recorded exposure (plan finding e3a91e, against {@code token-sheriff-client}).</strong> The
 * consequence is that on this path the engine cannot distinguish a credential the server has burned from
 * a transient fault: both surface as a non-redemption failure, and a caller that keeps the session alive
 * is holding a dead credential. That absence is a deliberate design choice — it is what stops a network
 * blip from destroying a working session — but under a single-use server it errs the other way. This
 * spec pins the behaviour as it stands and records the exposure; it changes no production code under
 * {@code token-sheriff-client/}.
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

        assertAll("the refusal is a pre-redemption failure, and is reported as one",
                () -> assertTrue(refusal.getMessage().contains("400"),
                        "the refusal must report the authorization server's 400 status, was: "
                                + refusal.getMessage()),
                () -> assertFalse(refusal instanceof RedeemedRefreshFailure,
                        "a non-success HTTP status is raised before any redemption state exists, so it "
                                + "must not implement RedeemedRefreshFailure"),
                () -> assertEquals(Optional.empty(), RefreshFlow.redemptionOf(refusal),
                        "redemptionOf must classify the refusal as predating redemption — the engine "
                                + "cannot tell a burned credential from a transient fault here "
                                + "(plan finding e3a91e)"),
                () -> assertTrue(RefreshEngineSupport.productionFrame(refusal).isPresent(),
                        "the refusal must be raised from a " + RefreshEngineSupport.PRODUCTION_PACKAGE
                                + "* frame, not from transport code outside the engine"));
    }

    @Test
    @DisplayName("Should keep the rotated token usable after the superseded one was refused")
    void shouldLeaveTheRotatedTokenUsableAfterTheRefusal() {
        String initialRefreshToken =
                TestRealm.createSingleUseRefreshRealm().obtainValidToken().refreshToken();
        assertNotNull(initialRefreshToken, "the single-use realm must issue an initial refresh token");

        String rotatedRefreshToken = refreshFlow.refresh(metadata, initialRefreshToken).refreshToken();
        assertThrows(TransportException.class,
                () -> refreshFlow.refresh(metadata, initialRefreshToken),
                "the superseded token must be refused");

        // The refusal above concerns only the superseded credential. If it had disturbed the session,
        // the rotated token would be dead too — which is the failure mode this asserts against.
        RotationResult second = assertDoesNotThrow(
                () -> refreshFlow.refresh(metadata, rotatedRefreshToken),
                "refusing the superseded token must not invalidate the credential that replaced it");

        assertAll("the rotation chain continues past the refusal",
                () -> assertTrue(second.rotated(), "the rotated token must itself redeem and rotate"),
                () -> assertNotEquals(rotatedRefreshToken, second.refreshToken(),
                        "each redemption must yield a further, distinct refresh token"),
                () -> assertFalse(second.accessToken().getRawToken().isBlank(),
                        "the continued rotation must carry a validated access token"));
    }
}

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
import de.cuioss.sheriff.token.client.flow.RefreshFlow;
import de.cuioss.sheriff.token.client.token.RotationResult;
import de.cuioss.sheriff.token.client.token.TokenValidationBridge;
import de.cuioss.sheriff.token.integration.BaseIntegrationTest;
import de.cuioss.sheriff.token.integration.TestRealm;
import de.cuioss.tools.logging.CuiLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Drives <em>two simultaneous</em> {@link RefreshFlow#refresh} calls for one session against the real
 * Keycloak container, with no single-flight guard anywhere in the path.
 *
 * <h2>How this differs from the two neighbouring specs</h2>
 * All three touch "concurrent refresh", and they are deliberately not duplicates — each pins a
 * different layer:
 * <ul>
 *   <li>{@link RefreshSingleFlightSpecIT} drives {@code TokenLifecycleManager.refresh} and asserts the
 *       <em>collapse</em>: two callers share one in-flight rotation, so the refresh token is redeemed
 *       exactly once. Its subject is the coordinator's per-session {@code CompletableFuture}.</li>
 *   <li>{@code RefreshConcurrencyTest} (unit, {@code token-sheriff-client}) races sixteen threads
 *       through {@code RefreshTokenFamily.rotate} on fabricated token strings. Its subject is the
 *       family's in-memory rotation bookkeeping; it never reaches an authorization server.</li>
 *   <li><strong>This spec</strong> removes both of those guards. It calls {@link RefreshFlow#refresh}
 *       directly — the bare 2a surface, which holds no rotation-family bookkeeping and no single-flight
 *       future — from two threads released together, against a live AS. Nothing here collapses the two
 *       calls, so both genuinely reach the token endpoint with the same refresh token.</li>
 * </ul>
 * What is therefore under test is the engine's <em>observable behaviour under a real race</em>, not a
 * guarantee about how many redemptions occur: with no client-side serialization the outcome is the
 * authorization server's to decide.
 *
 * <h2>Why the assertions are shaped this way</h2>
 * This realm sets neither {@code revokeRefreshToken} nor {@code refreshTokenMaxReuse}, so it may well
 * accept both redemptions — {@link RefreshErrorPathSpecIT} records that same property for the
 * sequential replay. Asserting "exactly one wins" would therefore pin realm configuration and turn a
 * fixture change into a false engine regression. What the engine genuinely owes under a race is
 * asserted instead: every call <em>terminates</em> (bounded wait — a hang fails the test), each outcome
 * is either a well-formed {@link RotationResult} or a typed refusal raised from a production frame, no
 * successful rotation carries a corrupted or duplicated credential, and every returned access token is
 * validated and subject bound.
 */
@DisplayName("Concurrent RefreshFlow redemption of one session against real Keycloak")
class RefreshConcurrentRedemptionSpecIT extends BaseIntegrationTest {

    private static final CuiLogger LOGGER = new CuiLogger(RefreshConcurrentRedemptionSpecIT.class);

    private static final String FAST_CLIENT_ID = "refresh-fast-client";
    private static final String FAST_CLIENT_SECRET = "refresh-fast-secret";

    /** Number of callers released simultaneously onto the same refresh token. */
    private static final int CALLERS = 2;

    /**
     * Bounded wait for both callers to finish. Generous enough for two round trips plus container and
     * CI jitter; the point is that it is <em>bounded</em> — a caller that never returns fails the spec
     * rather than hanging the build.
     */
    private static final Duration COMPLETION_BUDGET = Duration.ofSeconds(60);

    @Test
    @DisplayName("Should terminate both concurrent redemptions with either a rotation or a typed refusal")
    void shouldTerminateBothConcurrentRedemptions() throws Exception {
        TestRealm.TokenResponse acquired = TestRealm.createClientEngineFastRefreshRealm().obtainValidToken();
        String refreshToken = acquired.refreshToken();
        assertNotNull(refreshToken, "the fast-expiry client must issue a refresh token");

        ClientConfiguration configuration =
                RefreshEngineSupport.clientConfiguration(FAST_CLIENT_ID, FAST_CLIENT_SECRET);
        TokenValidationBridge accessBridge =
                RefreshEngineSupport.accessTokenBridge(RefreshEngineSupport.tokenValidator());
        RefreshFlow refreshFlow = RefreshEngineSupport.refreshFlow(configuration, accessBridge);
        ProviderMetadata metadata = RefreshEngineSupport.discoveredProviderMetadata();

        List<Outcome> outcomes = redeemConcurrently(refreshFlow, metadata, refreshToken);

        assertEquals(CALLERS, outcomes.size(), "every caller must have produced an outcome");
        assertAll("engine behaviour under a real concurrent redemption",
                () -> assertAll("each outcome is well formed",
                        outcomes.stream().map(outcome -> () -> assertWellFormed(outcome))),
                () -> assertDistinctRotatedTokens(outcomes, refreshToken));
    }

    /**
     * Releases {@link #CALLERS} threads onto {@code refreshFlow.refresh(metadata, refreshToken)} at the
     * same instant and collects what each one produced.
     * <p>
     * The start gate is what makes the race real: submitting the tasks alone would let the first finish
     * before the second begins, and the redemptions would be sequential — the case
     * {@link RefreshErrorPathSpecIT} already covers.
     *
     * @param refreshFlow  the production flow, shared by both callers
     * @param metadata     the discovery-resolved provider metadata
     * @param refreshToken the single refresh token both callers present
     * @return one outcome per caller
     * @throws InterruptedException if the test thread is interrupted while awaiting completion
     */
    private static List<Outcome> redeemConcurrently(RefreshFlow refreshFlow, ProviderMetadata metadata,
            String refreshToken) throws InterruptedException {
        CountDownLatch startGate = new CountDownLatch(1);
        ExecutorService callers = Executors.newFixedThreadPool(CALLERS);
        try {
            List<Future<Outcome>> futures = new ArrayList<>();
            for (int caller = 0; caller < CALLERS; caller++) {
                futures.add(callers.submit(() -> {
                    startGate.await();
                    return attemptRefresh(refreshFlow, metadata, refreshToken);
                }));
            }
            startGate.countDown();
            return collect(futures);
        } finally {
            callers.shutdownNow();
        }
    }

    /**
     * Runs one redemption, converting an engine failure into a recorded outcome rather than letting it
     * escape. A refusal is a legitimate result of this race, so it is data to assert on, not an error.
     */
    // cui-rewrite:disable InvalidExceptionUsageRecipe
    // The catch is deliberately broad: this spec exists to observe what the engine does under a race
    // whose failure mode is not known in advance. Narrowing it would let an unanticipated engine
    // exception escape as an opaque executor failure instead of being asserted as a typed refusal.
    private static Outcome attemptRefresh(RefreshFlow refreshFlow, ProviderMetadata metadata,
            String refreshToken) {
        try {
            return new Outcome(refreshFlow.refresh(metadata, refreshToken), null);
        } catch (RuntimeException failure) {
            LOGGER.debug(failure, "Concurrent redemption refused by the engine");
            return new Outcome(null, failure);
        }
    }

    /**
     * Awaits every caller under {@link #COMPLETION_BUDGET}. A caller that has not returned inside the
     * budget fails the spec here — the "never a hang" half of the contract.
     */
    private static List<Outcome> collect(List<Future<Outcome>> futures) throws InterruptedException {
        List<Outcome> outcomes = new ArrayList<>();
        for (Future<Outcome> future : futures) {
            try {
                outcomes.add(future.get(COMPLETION_BUDGET.toSeconds(), TimeUnit.SECONDS));
            } catch (java.util.concurrent.TimeoutException e) {
                throw new AssertionError("a concurrent redemption never terminated within "
                        + COMPLETION_BUDGET, e);
            } catch (java.util.concurrent.ExecutionException e) {
                throw new AssertionError("a concurrent redemption failed outside the engine", e.getCause());
            }
        }
        return outcomes;
    }

    /**
     * Asserts one caller's outcome is one of the two the engine is allowed to produce: a fully formed
     * rotation, or a refusal raised from inside the production engine.
     */
    private static void assertWellFormed(Outcome outcome) {
        if (outcome.failure() != null) {
            Optional<String> frame = RefreshEngineSupport.productionFrame(outcome.failure());
            assertTrue(frame.isPresent(),
                    "a refused redemption must be raised from a " + RefreshEngineSupport.PRODUCTION_PACKAGE
                            + "* frame, not from transport code outside the engine; was: "
                            + outcome.failure());
            return;
        }
        RotationResult rotation = outcome.rotation();
        assertAll("a successful concurrent rotation is complete",
                () -> assertNotNull(rotation.refreshToken(), "a rotation must carry a refresh token"),
                () -> assertFalse(rotation.accessToken().getRawToken().isBlank(),
                        "a rotation must carry a non-blank, validated access token"),
                () -> assertTrue(rotation.accessToken().getSubject().isPresent(),
                        "the validated access token must be subject bound"),
                () -> assertEquals(RefreshEngineSupport.ISSUER, rotation.accessToken().getIssuer(),
                        "the validated access token must carry the realm's issuer identity"));
    }

    /**
     * Asserts no successful rotation handed back the credential that was redeemed, and that two
     * successful rotations never handed back the <em>same</em> new credential — either would mean two
     * callers left believing they hold the session's current refresh token.
     */
    private static void assertDistinctRotatedTokens(List<Outcome> outcomes, String redeemedToken) {
        List<String> rotated = outcomes.stream()
                .filter(outcome -> outcome.failure() == null)
                .map(outcome -> outcome.rotation().refreshToken())
                .toList();
        LOGGER.debug("concurrent redemption produced %s rotation(s) of %s caller(s)",
                rotated.size(), outcomes.size());

        assertAll("rotated credentials are distinct",
                () -> assertFalse(rotated.contains(redeemedToken),
                        "no rotation may hand back the refresh token that was just redeemed"),
                () -> assertEquals(rotated.size(), Set.copyOf(rotated).size(),
                        "two concurrent rotations must not yield the same refresh token, was: " + rotated));
    }

    /**
     * One caller's result: exactly one of the two fields is non-null.
     *
     * @param rotation the rotation produced, or {@code null} when the engine refused
     * @param failure  the refusal raised, or {@code null} when the redemption succeeded
     */
    private record Outcome(RotationResult rotation, RuntimeException failure) {
    }
}

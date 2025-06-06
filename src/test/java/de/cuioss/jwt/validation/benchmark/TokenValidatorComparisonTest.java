/**
 * Copyright © 2025 CUI-OpenSource-Software (info@cuioss.de)
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
package de.cuioss.jwt.validation.benchmark;

import de.cuioss.jwt.validation.IssuerConfig;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.jwt.validation.domain.token.AccessTokenContent;
import de.cuioss.jwt.validation.domain.token.IdTokenContent;
import de.cuioss.jwt.validation.domain.token.RefreshTokenContent;
import de.cuioss.jwt.validation.exception.TokenValidationException;
import de.cuioss.jwt.validation.jwks.http.HttpJwksLoaderConfig;
import de.cuioss.jwt.validation.test.TestTokenHolder;
import de.cuioss.jwt.validation.test.generator.TestTokenGenerators;
import de.cuioss.test.keycloakit.KeycloakITBase;
import de.cuioss.test.keycloakit.TestRealm;
import de.cuioss.tools.logging.CuiLogger;
import io.restassured.RestAssured;
import io.restassured.config.SSLConfig;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * This benchmark compares the performance of validating in-memory generated tokens
 * versus real tokens from Keycloak. It helps validate that the in-memory token
 * generators used in benchmarks accurately represent real-world tokens.
 * <p>
 * Note: This benchmark requires a running Keycloak instance via testcontainers,
 * which makes it slower than standard benchmarks. It's intended for comparison
 * analysis rather than regular performance testing.
 */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Fork(value = 1, warmups = 1)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@SuppressWarnings("java:S2187") // owolff: There are no
public class TokenValidatorComparisonTest extends KeycloakITBase {

    private static final CuiLogger LOGGER = new CuiLogger(TokenValidatorComparisonTest.class);
    public static final String SCOPES = "openid email profile";

    // Token type constants for Keycloak response paths
    private static class TokenTypes {
        public static final String ACCESS = "access_token";
        public static final String ID_TOKEN = "id_token";
        public static final String REFRESH = "refresh_token";
    }

    // In-memory token related fields
    private TokenValidator inMemoryTokenValidator;
    private String inMemoryAccessToken;
    private String inMemoryIdToken;
    private String inMemoryRefreshToken;

    // Keycloak token related fields
    private TokenValidator keycloakTokenValidator;
    private String keycloakAccessToken;
    private String keycloakIdToken;
    private String keycloakRefreshToken;
    private static SSLConfig restAssuredSslConfig;
    private static SSLContext keycloakSslContext;

    /**
     * Creates an SSLContext that trusts all certificates for testing purposes.
     */
    private static SSLContext createKeycloakSSLContext() throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // Trust all client certificates for testing
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // Trust all server certificates for testing
                    }
                }
        };

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAllCerts, new SecureRandom());
        return sslContext;
    }

    @Setup(Level.Trial)
    public void setup() throws Exception {
        // Setup SSL configuration for RestAssured
        restAssuredSslConfig = SSLConfig.sslConfig().trustStore(TestRealm.ProvidedKeyStore.KEYSTORE_PATH, TestRealm.ProvidedKeyStore.PASSWORD);
        RestAssured.config = RestAssured.config().sslConfig(restAssuredSslConfig);
        keycloakSslContext = createKeycloakSSLContext();

        // Setup auth server URL
        String issuerString = getIssuer();
        if (issuerString == null) {
            throw new IllegalStateException("getIssuer() returned null, cannot derive authServerUrlString");
        }
        int realmsIndex = issuerString.indexOf("/realms/");
        String authServerUrlString;
        if (realmsIndex != -1) {
            authServerUrlString = issuerString.substring(0, realmsIndex);
        } else {
            LOGGER.warn("'/realms/' not found in issuer string '{}', authServerUrlString may be incorrect.", issuerString);
            authServerUrlString = issuerString;
        }
        LOGGER.info("Derived authServerUrlString: {}", authServerUrlString);

        // Setup in-memory tokens
        setupInMemoryTokens();

        // Setup Keycloak tokens
        setupKeycloakTokens();

        LOGGER.info("Benchmark setup complete with both in-memory and Keycloak tokens");
    }

    private void setupInMemoryTokens() {
        // Create token holders using TestTokenGenerators
        TestTokenHolder accessTokenHolder = TestTokenGenerators.accessTokens().next();
        TestTokenHolder idTokenHolder = TestTokenGenerators.idTokens().next();
        TestTokenHolder refreshTokenHolder = TestTokenGenerators.refreshTokens().next();

        // Get the issuer config from the access token holder
        IssuerConfig issuerConfig = accessTokenHolder.getIssuerConfig();

        // Create a token validator with the issuer config
        inMemoryTokenValidator = new TokenValidator(issuerConfig);

        // Get the raw tokens
        inMemoryAccessToken = accessTokenHolder.getRawToken();
        inMemoryIdToken = idTokenHolder.getRawToken();
        inMemoryRefreshToken = refreshTokenHolder.getRawToken();

        LOGGER.info("In-memory tokens setup complete");
    }

    private void setupKeycloakTokens() {
        // Create a JwksLoader with the secure SSLContext that uses Keycloak's keystore
        HttpJwksLoaderConfig httpJwksConfig = HttpJwksLoaderConfig.builder()
                .url(getJWKSUrl()) // Direct JWKS URL from Keycloak container
                .refreshIntervalSeconds(100)
                .sslContext(keycloakSslContext) // Use the secure SSL context with Keycloak's keystore
                .build();

        // Create an IssuerConfig
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuer(getIssuer()) // Direct Issuer URL from Keycloak container
                .expectedAudience("test_client") // Using the correct client ID from TestRealm
                .httpJwksLoaderConfig(httpJwksConfig)
                .build();

        // Create the validation factory
        keycloakTokenValidator = new TokenValidator(issuerConfig);

        // Request tokens from Keycloak
        keycloakAccessToken = requestToken(parameterForScopedToken(SCOPES), TokenTypes.ACCESS);
        keycloakIdToken = requestToken(parameterForScopedToken(SCOPES), TokenTypes.ID_TOKEN);
        keycloakRefreshToken = requestToken(parameterForScopedToken(SCOPES), TokenTypes.REFRESH);

        LOGGER.info("Keycloak tokens setup complete");
    }

    private String requestToken(Map<String, String> parameter, String tokenType) {
        String tokenString = RestAssured.given().config(RestAssured.config().sslConfig(restAssuredSslConfig))
                .contentType("application/x-www-form-urlencoded")
                .formParams(parameter)
                .post(getTokenUrl()).then().assertThat().statusCode(200)
                .extract().path(tokenType);
        LOGGER.info(() -> "Received %s: %s".formatted(tokenType, tokenString));
        return tokenString;
    }

    // Benchmark methods for in-memory tokens

    @Benchmark
    public AccessTokenContent validateInMemoryAccessToken() {
        try {
            return inMemoryTokenValidator.createAccessToken(inMemoryAccessToken);
        } catch (TokenValidationException e) {
            throw new RuntimeException("In-memory access token validation failed in benchmark", e);
        }
    }

    @Benchmark
    public IdTokenContent validateInMemoryIdToken() {
        try {
            return inMemoryTokenValidator.createIdToken(inMemoryIdToken);
        } catch (TokenValidationException e) {
            throw new RuntimeException("In-memory ID token validation failed in benchmark", e);
        }
    }

    @Benchmark
    public RefreshTokenContent validateInMemoryRefreshToken() {
        return inMemoryTokenValidator.createRefreshToken(inMemoryRefreshToken);
    }

    // Benchmark methods for Keycloak tokens

    @Benchmark
    public AccessTokenContent validateKeycloakAccessToken() {
        try {
            return keycloakTokenValidator.createAccessToken(keycloakAccessToken);
        } catch (TokenValidationException e) {
            throw new RuntimeException("Keycloak access token validation failed in benchmark", e);
        }
    }

    @Benchmark
    public IdTokenContent validateKeycloakIdToken() {
        try {
            return keycloakTokenValidator.createIdToken(keycloakIdToken);
        } catch (TokenValidationException e) {
            throw new RuntimeException("Keycloak ID token validation failed in benchmark", e);
        }
    }

    @Benchmark
    public RefreshTokenContent validateKeycloakRefreshToken() {
        return keycloakTokenValidator.createRefreshToken(keycloakRefreshToken);
    }

    // Blackhole consumption methods for more accurate measurement

    @Benchmark
    public void validateInMemoryAccessTokenWithBlackhole(Blackhole bh) {
        try {
            bh.consume(inMemoryTokenValidator.createAccessToken(inMemoryAccessToken));
        } catch (TokenValidationException e) {
            bh.consume(e);
        }
    }

    @Benchmark
    public void validateKeycloakAccessTokenWithBlackhole(Blackhole bh) {
        try {
            bh.consume(keycloakTokenValidator.createAccessToken(keycloakAccessToken));
        } catch (TokenValidationException e) {
            bh.consume(e);
        }
    }

    /**
     * Main method to run the benchmark directly.
     * This is useful for running the benchmark without the Maven plugin.
     */
    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(TokenValidatorComparisonTest.class.getSimpleName())
                .resultFormat(ResultFormatType.JSON)
                .result("token-comparison-benchmark-results.json")
                .build();
        new Runner(opt).run();
    }
}

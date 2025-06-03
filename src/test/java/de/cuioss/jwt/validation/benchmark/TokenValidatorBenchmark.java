package de.cuioss.jwt.validation.benchmark;

import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

import de.cuioss.jwt.validation.IssuerConfig;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.jwt.validation.domain.token.AccessTokenContent;
import de.cuioss.jwt.validation.domain.token.IdTokenContent;
import de.cuioss.jwt.validation.domain.token.RefreshTokenContent;
import de.cuioss.jwt.validation.exception.TokenValidationException;
import de.cuioss.jwt.validation.test.TestTokenHolder;
import de.cuioss.jwt.validation.test.generator.TestTokenGenerators;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Fork(value = 1, warmups = 1)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 5, time = 1)
public class TokenValidatorBenchmark {

    private TokenValidator tokenValidator;
    private String accessToken;
    private String idToken;
    private String refreshToken;

    @Setup
    public void setup() {
        // Create token holders using TestTokenGenerators
        TestTokenHolder accessTokenHolder = TestTokenGenerators.accessTokens().next();
        TestTokenHolder idTokenHolder = TestTokenGenerators.idTokens().next();
        TestTokenHolder refreshTokenHolder = TestTokenGenerators.refreshTokens().next();
        
        // Get the issuer config from the access token holder
        IssuerConfig issuerConfig = accessTokenHolder.getIssuerConfig();
        
        // Create a token validator with the issuer config
        tokenValidator = new TokenValidator(issuerConfig);
        
        // Get the raw tokens
        accessToken = accessTokenHolder.getRawToken();
        idToken = idTokenHolder.getRawToken();
        refreshToken = refreshTokenHolder.getRawToken();
    }

    @Benchmark
    public AccessTokenContent validateAccessToken() {
        try {
            return tokenValidator.createAccessToken(accessToken);
        } catch (TokenValidationException e) {
            // This should ideally not happen in a performance benchmark for valid tokens
            // If it does, the setup or token generation needs correction.
            // For now, rethrow to make it visible in benchmark results if it occurs.
            throw new RuntimeException("Access token validation failed in benchmark", e);
        }
    }

    @Benchmark
    public IdTokenContent validateIdToken() {
        try {
            return tokenValidator.createIdToken(idToken);
        } catch (TokenValidationException e) {
            throw new RuntimeException("ID token validation failed in benchmark", e);
        }
    }

    @Benchmark
    public RefreshTokenContent validateRefreshToken() {
        // Refresh token validation is often lighter and might not throw exceptions
        // for certain "invalid" conditions if it's just parsing.
        // The createRefreshToken method in TokenValidator seems to try to parse claims
        // but ignore validation exceptions.
        return tokenValidator.createRefreshToken(refreshToken);
    }

    // Example of how to consume with Blackhole if methods don't return or to ensure computation
    @Benchmark
    public void validateAccessTokenAndConsume(Blackhole bh) {
        try {
            bh.consume(tokenValidator.createAccessToken(accessToken));
        } catch (TokenValidationException e) {
            bh.consume(e); // Consume exception if it's part of what's measured
        }
    }
}
package de.cuioss.jwt.validation.benchmark;

import de.cuioss.jwt.validation.IssuerConfig;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.jwt.validation.domain.token.AccessTokenContent;
import de.cuioss.jwt.validation.exception.TokenValidationException;
import de.cuioss.jwt.validation.test.TestTokenHolder;
import de.cuioss.jwt.validation.test.generator.TestTokenGenerators;
import org.openjdk.jmh.annotations.*;

import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark) // Shared state for all benchmark threads
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Fork(value = 1, warmups = 1)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 5, time = 1)
public class ConcurrentTokenValidationBenchmark {

    private TokenValidator tokenValidator;
    private String validAccessToken;

    @Setup(Level.Trial) // Setup once for all benchmark threads
    public void setup() {
        // Create a token holder using TestTokenGenerators
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        
        // Get the issuer config from the token holder
        IssuerConfig issuerConfig = tokenHolder.getIssuerConfig();
        
        // Create a token validator with the issuer config
        tokenValidator = new TokenValidator(issuerConfig);
        
        // Get the raw token
        validAccessToken = tokenHolder.getRawToken();
    }

    @Benchmark
    @Threads(Threads.MAX) // Use maximum available threads for this benchmark method
    public AccessTokenContent validateAccessTokenConcurrently() {
        try {
            return tokenValidator.createAccessToken(validAccessToken);
        } catch (TokenValidationException e) {
            // This should not happen with a valid token and correct setup
            throw new RuntimeException("Unexpected TokenValidationException during concurrent benchmark", e);
        }
    }

    // To test with specific thread counts as per the @Param suggestion in the prompt,
    // one would typically create separate @Benchmark methods each with its own @Threads(N) annotation,
    // or pass thread counts via JMH command-line options.
    // For example:
    // @Benchmark @Threads(1) public AccessTokenContent validateWith1Thread() { return validate(); }
    // @Benchmark @Threads(2) public AccessTokenContent validateWith2Threads() { return validate(); }
    // @Benchmark @Threads(4) public AccessTokenContent validateWith4Threads() { return validate(); }
    // etc.
    // For simplicity, this implementation uses Threads.MAX as per the doc example for B5.
    private AccessTokenContent validate() { // Helper if multiple methods were used
        try {
            return tokenValidator.createAccessToken(validAccessToken);
        } catch (TokenValidationException e) {
            throw new RuntimeException("Unexpected TokenValidationException during concurrent benchmark", e);
        }
    }
}
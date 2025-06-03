package de.cuioss.jwt.validation.benchmark;

import de.cuioss.jwt.validation.IssuerConfig;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.jwt.validation.domain.token.AccessTokenContent;
import de.cuioss.jwt.validation.exception.TokenValidationException;
import de.cuioss.jwt.validation.test.InMemoryJWKSFactory;
import de.cuioss.jwt.validation.test.InMemoryKeyMaterialHandler;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.openjdk.jmh.annotations.*;

import java.security.PrivateKey;
import java.util.Date;
import java.util.Map;
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
        PrivateKey signingKey = InMemoryKeyMaterialHandler.getDefaultPrivateKey(InMemoryKeyMaterialHandler.Algorithm.RS256);
        String keyId = InMemoryKeyMaterialHandler.DEFAULT_KEY_ID;

        String jwksContent = InMemoryJWKSFactory.createDefaultJwks();
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuer("Benchmark-testIssuer")
                .expectedAudience("benchmark-client")
                .expectedClientId("benchmark-client") // Though not strictly needed for access token by default
                .jwksContent(jwksContent)
                .build();
        tokenValidator = new TokenValidator(issuerConfig);

        long currentTimeMillis = System.currentTimeMillis();
        long futureExpTimeMillis = currentTimeMillis + 3600 * 1000; // 1 hour from now

        validAccessToken = Jwts.builder()
                .header().add(Map.of("kid", keyId)).and()
                .issuer("Benchmark-testIssuer")
                .audience().add("benchmark-client").and()
                .subject("concurrent-test-subject")
                .issuedAt(new Date(currentTimeMillis))
                .expiration(new Date(futureExpTimeMillis))
                .signWith(signingKey, SignatureAlgorithm.RS256)
                .compact();
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

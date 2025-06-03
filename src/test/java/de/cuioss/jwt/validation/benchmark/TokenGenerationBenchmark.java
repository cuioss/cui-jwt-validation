package de.cuioss.jwt.validation.benchmark;

import de.cuioss.jwt.validation.domain.claim.ClaimName;
import de.cuioss.jwt.validation.domain.claim.ClaimValue;
import de.cuioss.jwt.validation.test.InMemoryKeyMaterialHandler;
import de.cuioss.jwt.validation.test.TestTokenHolder;
import de.cuioss.jwt.validation.test.generator.TestTokenGenerators;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Fork(value = 1, warmups = 1)
@Warmup(iterations = 2, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS)
public class TokenGenerationBenchmark {

    // TestTokenHolder instance for default token generation
    private TestTokenHolder defaultTokenHolder;

    // TestTokenHolder instance for custom token generation
    private TestTokenHolder customTokenHolder;

    @Setup(Level.Iteration) // Re-setup for each iteration to get fresh TestTokenHolder instances
    public void setup() {
        defaultTokenHolder = TestTokenGenerators.accessTokens().next();

        customTokenHolder = TestTokenGenerators.accessTokens().next();
        // Pre-configure customTokenHolder here if the configuration itself isn't part of the benchmark
        // For this benchmark, we want to measure the getRawToken() after configuration.
        customTokenHolder.withClaim(ClaimName.ISSUER.getName(), ClaimValue.forPlainString("benchmark-issuer"));
        customTokenHolder.withClaim(ClaimName.SUBJECT.getName(), ClaimValue.forPlainString("benchmark-subject"));
        customTokenHolder.withKeyId("benchmark-kid"); // Assuming this kid exists in InMemoryKeyMaterialHandler default keys
                                                 // or that InMemoryKeyMaterialHandler can handle arbitrary kids by default.
                                                 // TestTokenHolder by default uses InMemoryKeyMaterialHandler.DEFAULT_KEY_ID
                                                 // and RS256. For "benchmark-kid" to work, it must be a known kid
                                                 // or TestTokenHolder needs to be initialized with specific key material for it.
                                                 // For simplicity, let's use the default kid that TestTokenHolder is set up with.
        customTokenHolder.withKeyId(InMemoryKeyMaterialHandler.DEFAULT_KEY_ID); // Use a known kid
        customTokenHolder.withSigningAlgorithm(InMemoryKeyMaterialHandler.Algorithm.RS256);
    }

    @Benchmark
    public String benchmarkTestTokenHolderDefault(Blackhole bh) {
        String rawToken = defaultTokenHolder.getRawToken();
        bh.consume(rawToken);
        return rawToken;
    }

    @Benchmark
    public String benchmarkTestTokenHolderCustom(Blackhole bh) {
        // The customization is now done in setup to ensure we're benchmarking getRawToken()
        String rawToken = customTokenHolder.getRawToken();
        bh.consume(rawToken);
        return rawToken;
    }

    @Benchmark
    public String benchmarkTestTokenHolderCustomPerInvocation(Blackhole bh) {
        // This version measures the customization + getRawToken()
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        tokenHolder.withClaim(ClaimName.ISSUER.getName(), ClaimValue.forPlainString("benchmark-issuer-invoc"));
        tokenHolder.withClaim(ClaimName.SUBJECT.getName(), ClaimValue.forPlainString("benchmark-subject-invoc"));
        tokenHolder.withKeyId(InMemoryKeyMaterialHandler.DEFAULT_KEY_ID); // Use a known kid
        tokenHolder.withSigningAlgorithm(InMemoryKeyMaterialHandler.Algorithm.RS256);
        String rawToken = tokenHolder.getRawToken();
        bh.consume(rawToken);
        return rawToken;
    }

    @Benchmark
    public String benchmarkJwksGeneration(Blackhole bh) {
        // Assuming InMemoryKeyMaterialHandler.DEFAULT_KEY_ID is a valid kid setup in the handler
        String jwks = InMemoryKeyMaterialHandler.createJwks(InMemoryKeyMaterialHandler.Algorithm.RS256,
                InMemoryKeyMaterialHandler.DEFAULT_KEY_ID);
        bh.consume(jwks);
        return jwks;
    }
}

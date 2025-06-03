package de.cuioss.jwt.validation.benchmark;

import de.cuioss.jwt.validation.IssuerConfig;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.jwt.validation.domain.claim.ClaimName;
import de.cuioss.jwt.validation.domain.claim.ClaimValue;
import de.cuioss.jwt.validation.domain.token.AccessTokenContent;
import de.cuioss.jwt.validation.exception.TokenValidationException;
import de.cuioss.jwt.validation.test.InMemoryKeyMaterialHandler;
import de.cuioss.jwt.validation.test.TestTokenHolder;
import de.cuioss.jwt.validation.test.generator.TestTokenGenerators;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Fork(value = 1, warmups = 1)
@Warmup(iterations = 2, time = 5)
@Measurement(iterations = 5, time = 5)
public class MultiIssuerValidatorBenchmark {

    private TokenValidator validator;
    private List<IssuerConfig> issuerConfigsList; // Changed name to avoid confusion
    private String tokenToValidate;
    private IssuerConfig firstIssuerConfig;

    @Param({"1", "5", "10"})
    private int issuerCount;

    @Setup(Level.Trial)
    public void setup() {
        issuerConfigsList = new ArrayList<>();
        for (int i = 0; i < issuerCount; i++) {
            String issuerUri = "issuer" + i;
            String kid = "kid" + i; // Unique kid for each issuer

            // Generate JWKS content using InMemoryKeyMaterialHandler for this kid
            // This assumes InMemoryKeyMaterialHandler can provide keys for "kid0", "kid1", etc.
            // If not, all issuers might need to use InMemoryKeyMaterialHandler.DEFAULT_KEY_ID
            String jwksContent = InMemoryKeyMaterialHandler.createJwks(InMemoryKeyMaterialHandler.Algorithm.RS256, kid);

            IssuerConfig config = IssuerConfig.builder()
                .issuer(issuerUri)
                .jwksContent(jwksContent)
                .build();
            issuerConfigsList.add(config);
        }

        validator = new TokenValidator(issuerConfigsList.toArray(new IssuerConfig[0]));

        if (!issuerConfigsList.isEmpty()) {
            firstIssuerConfig = issuerConfigsList.get(0);
            String firstIssuerKid = "kid0"; // Kid used for the first issuer's JWKS

            try {
                TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
                tokenHolder.withClaim(ClaimName.ISSUER.getName(), ClaimValue.forPlainString(firstIssuerConfig.getIssuer()));
                tokenHolder.withKeyId(firstIssuerKid); // Ensure token is signed with the key corresponding to kid0
                tokenHolder.withSigningAlgorithm(InMemoryKeyMaterialHandler.Algorithm.RS256); // Match JWKS alg

                tokenToValidate = tokenHolder.getRawToken();

            } catch (Exception e) {
                System.err.println("Failed to generate token for benchmark: " + e.getMessage());
                e.printStackTrace();
                tokenToValidate = "dummy.token.string.for.error";
            }
        } else {
            tokenToValidate = "dummy.token.string.no.issuers";
        }
    }

    @Benchmark
    public void validateTokenFromFirstIssuer(Blackhole bh) {
        if (tokenToValidate.startsWith("dummy.token.string")) {
            return;
        }
        try {
            Optional<AccessTokenContent> result = Optional.of(validator.createAccessToken(tokenToValidate));
            bh.consume(result);
        } catch (TokenValidationException e) {
            bh.consume(e);
        }
    }
}

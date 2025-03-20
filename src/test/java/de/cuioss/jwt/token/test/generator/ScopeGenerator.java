package de.cuioss.jwt.token.test.generator;

import de.cuioss.test.generator.TypedGenerator;
import de.cuioss.test.generator.Generators;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Generator for OAuth/OIDC scopes.
 * Generates a string with space-separated scopes, where "openid" is always included.
 */
public class ScopeGenerator implements TypedGenerator<String> {

    private static final String OPENID_SCOPE = "openid";
    private static final List<String> COMMON_SCOPES = List.of(
            "email", "profile", "offline_access", "address", "phone"
    );

    private final int minAdditionalScopes;
    private final int maxAdditionalScopes;

    /**
     * Constructor with default min and max additional scopes (0-3).
     */
    public ScopeGenerator() {
        this(0, 3);
    }

    /**
     * Constructor with custom min and max additional scopes.
     *
     * @param minAdditionalScopes minimum number of additional scopes (besides "openid")
     * @param maxAdditionalScopes maximum number of additional scopes (besides "openid")
     */
    public ScopeGenerator(int minAdditionalScopes, int maxAdditionalScopes) {
        if (minAdditionalScopes < 0) {
            throw new IllegalArgumentException("minAdditionalScopes must be >= 0");
        }
        if (maxAdditionalScopes < minAdditionalScopes) {
            throw new IllegalArgumentException("maxAdditionalScopes must be >= minAdditionalScopes");
        }
        this.minAdditionalScopes = minAdditionalScopes;
        this.maxAdditionalScopes = maxAdditionalScopes;
    }

    @Override
    public String next() {
        List<String> scopes = new ArrayList<>();
        // Always include "openid"
        scopes.add(OPENID_SCOPE);

        // Add random number of additional scopes
        int additionalScopesCount = Generators.integers(minAdditionalScopes, maxAdditionalScopes).next();
        if (additionalScopesCount > 0) {
            // Shuffle and take a subset of common scopes
            List<String> shuffledScopes = new ArrayList<>(COMMON_SCOPES);
            java.util.Collections.shuffle(shuffledScopes);
            int count = Math.min(additionalScopesCount, shuffledScopes.size());
            scopes.addAll(shuffledScopes.subList(0, count));

            // If we need more scopes than the common ones, generate random ones
            if (additionalScopesCount > count) {
                for (int i = 0; i < additionalScopesCount - count; i++) {
                    scopes.add(Generators.letterStrings(3, 10).next());
                }
            }
        }

        // Join scopes with spaces
        return scopes.stream().collect(Collectors.joining(" "));
    }
}
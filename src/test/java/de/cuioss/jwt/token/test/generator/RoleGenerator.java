package de.cuioss.jwt.token.test.generator;

import de.cuioss.test.generator.TypedGenerator;
import de.cuioss.test.generator.Generators;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Generator for OAuth/OIDC roles.
 * Generates a Set of role strings.
 */
public class RoleGenerator implements TypedGenerator<Set<String>> {

    private static final List<String> COMMON_ROLES = List.of(
            "reader", "writer", "admin", "user", "manager", "editor", "viewer", "gambler"
    );

    private final int minRoles;
    private final int maxRoles;

    /**
     * Constructor with default min and max roles (1-3).
     */
    public RoleGenerator() {
        this(1, 3);
    }

    /**
     * Constructor with custom min and max roles.
     *
     * @param minRoles minimum number of roles
     * @param maxRoles maximum number of roles
     */
    public RoleGenerator(int minRoles, int maxRoles) {
        if (minRoles < 0) {
            throw new IllegalArgumentException("minRoles must be >= 0");
        }
        if (maxRoles < minRoles) {
            throw new IllegalArgumentException("maxRoles must be >= minRoles");
        }
        this.minRoles = minRoles;
        this.maxRoles = maxRoles;
    }

    @Override
    public Set<String> next() {
        Set<String> roles = new HashSet<>();

        // Determine how many roles to generate
        int roleCount = Generators.integers(minRoles, maxRoles).next();
        if (roleCount == 0) {
            return roles;
        }

        // Shuffle and take a subset of common roles
        List<String> shuffledRoles = new ArrayList<>(COMMON_ROLES);
        java.util.Collections.shuffle(shuffledRoles);
        int count = Math.min(roleCount, shuffledRoles.size());
        roles.addAll(shuffledRoles.subList(0, count));

        // If we need more roles than the common ones, generate random ones
        if (roleCount > count) {
            for (int i = 0; i < roleCount - count; i++) {
                roles.add(Generators.letterStrings(3, 10).next());
            }
        }

        return roles;
    }
}
package de.cuioss.jwt.token.test.generator;

import de.cuioss.test.generator.TypedGenerator;
import de.cuioss.test.generator.Generators;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Generator for OAuth/OIDC groups.
 * Generates a Set of group strings.
 */
public class GroupGenerator implements TypedGenerator<Set<String>> {

    private static final List<String> COMMON_GROUPS = List.of(
            "employees", "contractors", "admins", "developers", "testers", "managers", 
            "support", "sales", "marketing", "finance", "hr", "it"
    );

    private final int minGroups;
    private final int maxGroups;

    /**
     * Constructor with default min and max groups (1-3).
     */
    public GroupGenerator() {
        this(1, 3);
    }

    /**
     * Constructor with custom min and max groups.
     *
     * @param minGroups minimum number of groups
     * @param maxGroups maximum number of groups
     */
    public GroupGenerator(int minGroups, int maxGroups) {
        if (minGroups < 0) {
            throw new IllegalArgumentException("minGroups must be >= 0");
        }
        if (maxGroups < minGroups) {
            throw new IllegalArgumentException("maxGroups must be >= minGroups");
        }
        this.minGroups = minGroups;
        this.maxGroups = maxGroups;
    }

    @Override
    public Set<String> next() {
        Set<String> groups = new HashSet<>();

        // Determine how many groups to generate
        int groupCount = Generators.integers(minGroups, maxGroups).next();
        if (groupCount == 0) {
            return groups;
        }

        // Shuffle and take a subset of common groups
        List<String> shuffledGroups = new ArrayList<>(COMMON_GROUPS);
        java.util.Collections.shuffle(shuffledGroups);
        int count = Math.min(groupCount, shuffledGroups.size());
        groups.addAll(shuffledGroups.subList(0, count));

        // If we need more groups than the common ones, generate random ones
        if (groupCount > count) {
            for (int i = 0; i < groupCount - count; i++) {
                groups.add(Generators.letterStrings(3, 10).next());
            }
        }

        return groups;
    }
}
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
package de.cuioss.sheriff.token.architecture;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Keeps every documented package / ArchUnit pattern copy-pasteable.
 * <p>
 * A pattern written with the Unicode ellipsis character renders as one glyph where an ArchUnit
 * rule needs two literal periods, so a reader who copies it out of the documentation gets a
 * pattern that silently matches nothing. This test fails the build when such a pattern appears
 * anywhere in the repository's documentation or sources.
 * <p>
 * The glyph itself is not banned - it is legitimate prose punctuation. Only its use <em>as a
 * package-pattern prefix</em> is a violation, which is what {@link #isElidedPackagePattern(String)}
 * discriminates.
 * <p>
 * This file never contains the glyph as a character. It is derived from its code point
 * ({@code U+2026}) and composed into the control data instead. That is load-bearing rather than
 * stylistic: the sweep below scans {@code .java} files, so a control written with the literal
 * character would make this test report itself as a violation.
 *
 * @see CommonsLayeringTest the rules whose {@code ..commons..} / {@code ..validation..} form is
 * the authority for how a documented pattern must be written
 */
class DocumentedPackagePatternTest {

    private static final char ELLIPSIS = (char) 0x2026;

    private static final String GLYPH = String.valueOf(ELLIPSIS);

    private static final Set<String> SCANNED_EXTENSIONS = Set.of(".adoc", ".md", ".svg", ".xml", ".java");

    private static final Set<String> EXCLUDED_DIRECTORIES = Set.of("target", ".git", ".plan", "node_modules");

    /**
     * Reports whether a single line of text uses the ellipsis glyph as a package-pattern prefix.
     * <p>
     * A glyph occurrence violates when it is immediately followed by {@code ..}, or immediately
     * followed by an identifier that is itself followed by a {@code .}, or immediately preceded
     * by {@code ..}. Every other occurrence is ordinary prose punctuation and is clean.
     *
     * @param line the line to inspect
     * @return {@code true} when the line carries at least one elided package pattern
     */
    static boolean isElidedPackagePattern(String line) {
        for (int index = line.indexOf(ELLIPSIS); index >= 0; index = line.indexOf(ELLIPSIS, index + 1)) {
            if (violatesAt(line, index)) {
                return true;
            }
        }
        return false;
    }

    private static boolean violatesAt(String line, int index) {
        if (index >= 2 && line.charAt(index - 1) == '.' && line.charAt(index - 2) == '.') {
            return true;
        }
        int afterGlyph = index + 1;
        if (afterGlyph + 1 < line.length()
                && line.charAt(afterGlyph) == '.' && line.charAt(afterGlyph + 1) == '.') {
            return true;
        }
        int identifierEnd = afterGlyph;
        while (identifierEnd < line.length() && Character.isJavaIdentifierPart(line.charAt(identifierEnd))) {
            identifierEnd++;
        }
        return identifierEnd > afterGlyph
                && identifierEnd < line.length()
                && line.charAt(identifierEnd) == '.';
    }

    @Test
    @DisplayName("The predicate flags elided package patterns and leaves prose ellipses alone")
    void predicateDiscriminatesPackagePatternsFromProse() {
        assertAll("elided package patterns are violations",
                () -> assertTrue(isElidedPackagePattern(GLYPH + "commons.."),
                        "a glyph standing in for the commons package prefix is a violation"),
                () -> assertTrue(isElidedPackagePattern(GLYPH + "validation.."),
                        "a glyph standing in for the validation package prefix is a violation"),
                () -> assertTrue(isElidedPackagePattern(GLYPH + "flow.Refresh*"),
                        "a glyph standing in for a class-pattern package prefix is a violation"),
                () -> assertTrue(isElidedPackagePattern(GLYPH + "sheriff.token.validation"),
                        "a glyph eliding a leading package segment is a violation"));

        assertAll("literal patterns and prose ellipses are clean",
                () -> assertFalse(isElidedPackagePattern("..commons.."),
                        "the literal two-period ArchUnit form is the target, not a violation"),
                () -> assertFalse(isElidedPackagePattern("..validation.."),
                        "the literal two-period ArchUnit form is the target, not a violation"),
                () -> assertFalse(isElidedPackagePattern("..flow.Refresh*"),
                        "the literal two-period class pattern is the target, not a violation"),
                () -> assertFalse(isElidedPackagePattern("Q-1 " + GLYPH + " Q-13"),
                        "an ellipsis eliding a range in prose is punctuation, not a package pattern"),
                () -> assertFalse(isElidedPackagePattern("urn:" + GLYPH + ":token-exchange"),
                        "an ellipsis inside a URN is punctuation, not a package pattern"),
                () -> assertFalse(isElidedPackagePattern("ftp/file/javascript/" + GLYPH),
                        "a trailing ellipsis closing a list is punctuation, not a package pattern"));
    }

    @Test
    @DisplayName("No documented package pattern in the repository uses the ellipsis glyph")
    void repositoryCarriesNoElidedPackagePatterns() throws IOException {
        Path repositoryRoot = resolveRepositoryRoot();
        assertTrue(Files.isRegularFile(repositoryRoot.resolve("pom.xml")),
                "Repository root did not resolve to a Maven project root (resolved to " + repositoryRoot
                        + "). Refusing to report success: the sweep never ran, so a passing result here "
                        + "would be vacuous rather than evidence that no pattern uses the glyph.");

        List<String> violations = sweep(repositoryRoot);

        assertTrue(violations.isEmpty(),
                () -> "Documented package patterns must use literal periods, never the Unicode ellipsis "
                        + "(U+2026) - a glyph renders as one character where an ArchUnit rule needs two "
                        + "periods, so the documented pattern matches nothing when copied. "
                        + violations.size() + " violation(s) found:"
                        + System.lineSeparator()
                        + String.join(System.lineSeparator(), violations));
    }

    private static Path resolveRepositoryRoot() {
        Path moduleBase = Paths.get(System.getProperty("basedir", System.getProperty("user.dir")))
                .toAbsolutePath()
                .normalize();
        Path parent = moduleBase.getParent();
        return parent != null ? parent : moduleBase;
    }

    private static List<String> sweep(Path repositoryRoot) throws IOException {
        List<String> violations = new ArrayList<>();
        Files.walkFileTree(repositoryRoot, new SimpleFileVisitor<Path>() {

            @Override
            public FileVisitResult preVisitDirectory(Path directory, BasicFileAttributes attributes) {
                Path name = directory.getFileName();
                return name != null && EXCLUDED_DIRECTORIES.contains(name.toString())
                        ? FileVisitResult.SKIP_SUBTREE
                        : FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) {
                if (isScanned(file)) {
                    collectViolations(repositoryRoot, file, violations);
                }
                return FileVisitResult.CONTINUE;
            }
        });
        return violations;
    }

    private static boolean isScanned(Path file) {
        String name = file.getFileName().toString();
        return SCANNED_EXTENSIONS.stream().anyMatch(name::endsWith);
    }

    private static void collectViolations(Path repositoryRoot, Path file, List<String> sink) {
        String content;
        try {
            content = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read " + file
                    + " during the documented-pattern sweep; skipping it would leave the file unchecked", e);
        }
        String[] lines = content.split("\n", -1);
        for (int lineIndex = 0; lineIndex < lines.length; lineIndex++) {
            String line = lines[lineIndex];
            if (isElidedPackagePattern(line)) {
                sink.add(repositoryRoot.relativize(file) + ":" + (lineIndex + 1) + " -> " + line.strip());
            }
        }
    }
}

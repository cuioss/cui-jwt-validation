/*
 * Copyright 2025 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.jwt.validation.test.util;

import lombok.Getter;
import lombok.Setter;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Utility class for tracking and reporting performance statistics in tests.
 * <p>
 * This class provides methods for recording access times, tracking success/failure counts,
 * and generating detailed performance reports including distribution visualizations.
 * <p>
 * The class is thread-safe and can be used in concurrent test scenarios.
 */
@Getter
@Setter
public class PerformanceStatistics {
    // Constants for time ranges
    private static final double LOW_TIME_THRESHOLD_MS = 50.0;
    private static final double HIGH_TIME_THRESHOLD_MS = 150.0;
    private static final int MAX_BAR_LENGTH = 50;

    private final AtomicInteger successCount = new AtomicInteger(0);

    private final AtomicInteger failureCount = new AtomicInteger(0);

    private final AtomicInteger emptyResultCount = new AtomicInteger(0);

    private final List<Throwable> exceptions = new ArrayList<>();

    private final LongSummaryStatistics accessTimeStats = new LongSummaryStatistics();
    private final AtomicLong totalAccessCount = new AtomicLong(0);
    private final Map<Long, AtomicInteger> accessTimeDistribution = new HashMap<>();

    private long totalTimeMs;

    private boolean completed;

    private boolean terminated;

    private int serverCallCount;

    private int totalRequests;

    /**
     * Records an access time and updates the distribution.
     *
     * @param accessTimeNanos the access time in nanoseconds
     */
    public synchronized void recordAccessTime(long accessTimeNanos) {
        // Convert nanoseconds to milliseconds with one decimal place precision
        double accessTimeMs = accessTimeNanos / 1_000_000.0;

        // Store the raw value in stats
        accessTimeStats.accept(Math.round(accessTimeMs));
        totalAccessCount.incrementAndGet();

        // For distribution, use 0.1ms precision for times < 1ms
        // and round to nearest 5ms for larger values
        double bucketValue;
        if (accessTimeMs < 1.0) {
            // For very fast operations (< 1ms), use 0.1ms precision
            bucketValue = Math.round(accessTimeMs * 10) / 10.0;
        } else {
            // For normal operations, round to nearest 5ms
            bucketValue = Math.round(accessTimeMs / 5.0) * 5;
        }

        // Convert to long for map key
        long bucket = (long) (bucketValue * 10); // Store with one decimal precision
        accessTimeDistribution.computeIfAbsent(bucket, k -> new AtomicInteger()).incrementAndGet();
    }

    /**
     * Increments the success counter.
     */
    public void incrementSuccess() {
        successCount.incrementAndGet();
    }

    /**
     * Increments the failure counter.
     */
    public void incrementFailure() {
        failureCount.incrementAndGet();
    }

    /**
     * Increments the empty result counter.
     */
    public void incrementEmptyResult() {
        emptyResultCount.incrementAndGet();
    }

    /**
     * Adds an exception to the list.
     *
     * @param e the exception to add
     */
    public synchronized void addException(Throwable e) {
        exceptions.add(e);
    }

    /**
     * Gets the success count.
     *
     * @return the success count
     */
    public int getSuccessCount() {
        return successCount.get();
    }

    /**
     * Gets the failure count.
     *
     * @return the failure count
     */
    public int getFailureCount() {
        return failureCount.get();
    }

    /**
     * Gets the empty result count.
     *
     * @return the empty result count
     */
    public int getEmptyResultCount() {
        return emptyResultCount.get();
    }

    /**
     * Gets the list of exceptions.
     *
     * @return the list of exceptions
     */
    public List<Throwable> getExceptions() {
        return exceptions;
    }

    /**
     * Gets the total number of requests.
     *
     * @return the total number of requests
     */
    public int getTotalRequests() {
        return totalRequests;
    }

    /**
     * Creates a bar string of the specified length using the given character.
     *
     * @param length the length of the bar
     * @return a string representing the bar
     */
    private String createBar(int length) {
        return "█".repeat(Math.max(0, length));
    }

    /**
     * Returns a string representation of the statistics.
     *
     * @return a string representation of the statistics
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("%n----------- Performance Statistics ---------\n");

        // Test completion status
        sb.append("Test completed: %s, Executor terminated: %s%n".formatted(
                completed, terminated));

        // Performance results
        sb.append("Performance results - Successful: %d, Failed: %d, Empty: %d, Exceptions: %d%n".formatted(
                successCount.get(), failureCount.get(), emptyResultCount.get(), exceptions.size()));

        // Performance statistics
        double avgTimePerRequest = totalRequests > 0 ? totalTimeMs / (double) totalRequests : 0.0;
        double successRate = totalRequests > 0 ? (double) (successCount.get() + emptyResultCount.get()) / totalRequests * 100 : 0.0;
        sb.append("Performance statistics - Total time: %d ms, Average time: %.2f ms, Success rate: %.2f%%%n".formatted(
                totalTimeMs, avgTimePerRequest, successRate));

        // Access statistics
        sb.append("%nKeyInfo access statistics - Total: %d, Average time: %.1f ms, Fastest: %.1f ms, Slowest: %.1f ms%n".formatted(
                totalAccessCount.get(), accessTimeStats.getAverage(),
                (double) accessTimeStats.getMin(), (double) accessTimeStats.getMax()));

        // Access time distribution - create three specific ranges: < 50 ms, 50-150 ms, > 150 ms
        sb.append("Access time distribution (ms):\n");

        // Create a list of all access times with their counts
        List<Map.Entry<Double, Integer>> sortedTimes = new ArrayList<>();
        for (Long bucket : accessTimeDistribution.keySet()) {
            double timeMs = bucket / 10.0;
            int count = accessTimeDistribution.get(bucket).get();
            sortedTimes.add(Map.entry(timeMs, count));
        }

        // Sort by time
        sortedTimes.sort(Map.Entry.comparingByKey());

        // Calculate total count
        int totalCount = sortedTimes.stream().mapToInt(Map.Entry::getValue).sum();

        // Create three specific ranges based on LOW_TIME_THRESHOLD_MS and HIGH_TIME_THRESHOLD_MS
        int lessThan50Count = 0;  // Count of items < LOW_TIME_THRESHOLD_MS
        int between50And150Count = 0;  // Count of items between LOW_TIME_THRESHOLD_MS and HIGH_TIME_THRESHOLD_MS
        int greaterThan150Count = 0;  // Count of items > HIGH_TIME_THRESHOLD_MS

        // Count items in each range
        for (Map.Entry<Double, Integer> entry : sortedTimes) {
            double time = entry.getKey();
            int count = entry.getValue();

            if (time < LOW_TIME_THRESHOLD_MS) {
                lessThan50Count += count;
            } else if (time <= HIGH_TIME_THRESHOLD_MS) {
                between50And150Count += count;
            } else {
                greaterThan150Count += count;
            }
        }

        // Calculate percentages for each range
        double lessThan50Percent = totalCount > 0 ? (double) lessThan50Count / totalCount * 100 : 0.0;
        double between50And150Percent = totalCount > 0 ? (double) between50And150Count / totalCount * 100 : 0.0;
        double greaterThan150Percent = totalCount > 0 ? (double) greaterThan150Count / totalCount * 100 : 0.0;

        // Display the ranges with highlighting for high access times
        sb.append("  %-15s: %6d (%5.2f%%)%n".formatted(
                "< %.1f ms".formatted(LOW_TIME_THRESHOLD_MS),
                lessThan50Count,
                lessThan50Percent));

        // Highlight the mid range if it contains items
        String midRangeDisplay = "%.1f-%.1f ms".formatted(LOW_TIME_THRESHOLD_MS, HIGH_TIME_THRESHOLD_MS);
        if (between50And150Count > 0) {
            sb.append("  %-15s: %6d (%5.2f%%) %s%n".formatted(
                    midRangeDisplay,
                    between50And150Count,
                    between50And150Percent,
                    "- High derivation detected"));
        } else {
            sb.append("  %-15s: %6d (%5.2f%%)%n".formatted(midRangeDisplay, between50And150Count, between50And150Percent));
        }

        // Highlight the high range if it contains items
        String highRangeDisplay = "> %.1f ms".formatted(HIGH_TIME_THRESHOLD_MS);
        if (greaterThan150Count > 0) {
            sb.append("  %-15s: %6d (%5.2f%%) %s%n".formatted(
                    highRangeDisplay,
                    greaterThan150Count,
                    greaterThan150Percent,
                    "- High derivation detected"));
        } else {
            sb.append("  %-15s: %6d (%5.2f%%)%n".formatted(highRangeDisplay, greaterThan150Count, greaterThan150Percent));
        }

        // Add a note about the spread
        if (between50And150Count > 0 || greaterThan150Count > 0) {
            sb.append("\nNote: High derivation in runtime detected. Access times vary significantly.\n");
        }

        // Add ASCII art visualization of the distribution
        sb.append("\nDistribution visualization:\n");

        // Define the format strings for the bar chart
        final String barFormatString = "  %%s : [%%-%ds] %%5.2f%%%%%n".formatted(MAX_BAR_LENGTH);

        // Calculate bar lengths based on percentages
        int lessThan50Bar = (int) Math.round(lessThan50Percent * MAX_BAR_LENGTH / 100);
        int between50And150Bar = (int) Math.round(between50And150Percent * MAX_BAR_LENGTH / 100);
        int greaterThan150Bar = (int) Math.round(greaterThan150Percent * MAX_BAR_LENGTH / 100);

        // Display the bars with labels
        sb.append(barFormatString.formatted(
                "< %.1f ms   ".formatted(LOW_TIME_THRESHOLD_MS),
                createBar(lessThan50Bar),
                lessThan50Percent));

        sb.append(barFormatString.formatted(
                "%.1f-%.1f ms".formatted(LOW_TIME_THRESHOLD_MS, HIGH_TIME_THRESHOLD_MS),
                createBar(between50And150Bar),
                between50And150Percent));

        sb.append(barFormatString.formatted(
                "> %.1f ms   ".formatted(HIGH_TIME_THRESHOLD_MS),
                createBar(greaterThan150Bar),
                greaterThan150Percent));

        // Server calls
        sb.append("%nServer was called %d times".formatted(serverCallCount));

        return sb.toString();
    }
}

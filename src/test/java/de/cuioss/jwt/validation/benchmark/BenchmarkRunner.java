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
package de.cuioss.jwt.validation.benchmark;

import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.openjdk.jmh.runner.options.TimeValue;

/**
 * Main class for running all benchmarks.
 * <p>
 * This class collects and runs all benchmark classes in the package.
 * It configures JMH with standard settings and produces a combined JSON report.
 */
public class BenchmarkRunner {

    /**
     * Main method to run all benchmarks.
     *
     * @param args command line arguments (not used)
     * @throws Exception if an error occurs during benchmark execution
     */
    public static void main(String[] args) throws Exception {

        // Configure JMH options
        Options options = new OptionsBuilder()
                // Include all benchmark classes in this package
                .include("de\\.cuioss\\.jwt\\.validation\\.benchmark\\..+Benchmark")
                // Set number of forks
                .forks(Integer.getInteger("jmh.forks", 1))
                // Set warmup iterations
                .warmupIterations(Integer.getInteger("jmh.warmupIterations", 3))
                // Set measurement iterations
                .measurementIterations(Integer.getInteger("jmh.iterations", 5))
                // Set measurement time
                .measurementTime(TimeValue.seconds(1))
                // Set warmup time
                .warmupTime(TimeValue.seconds(1))
                // Set number of threads
                .threads(Integer.getInteger("jmh.threads", 2))
                // Set benchmark mode (average time)
                .mode(Mode.AverageTime)
                // Configure result output - create a combined report for all benchmarks
                .resultFormat(ResultFormatType.JSON)
                .result("jmh-results.json")
                // Add JVM argument to configure logging for forked JVM instances
                .jvmArgsAppend("-Djava.util.logging.config.file=src/test/resources/benchmark-logging.properties")
                .build();

        // Run the benchmarks
        new Runner(options).run();
    }
}

/*
 * Copyright 2023 the original author or authors.
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
package de.cuioss.jwt.validation.benchmark.util;

import lombok.experimental.UtilityClass;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

/**
 * Utility class for running JMH benchmarks with standard configuration.
 * <p>
 * This class provides a simple way to run JMH benchmarks with a standard set of options,
 * including number of forks, warmup iterations, and measurement iterations.
 * <p>
 * Example usage:
 * <pre>
 * public static void main(String[] args) throws Exception {
 *     BenchmarkRunner.run(MyBenchmark.class);
 * }
 * </pre>
 */
@UtilityClass
public class BenchmarkRunner {

    /**
     * Runs a JMH benchmark with standard configuration.
     *
     * @param benchmarkClass the benchmark class to run
     * @throws Exception if an error occurs during benchmark execution
     */
    public static void run(Class<?> benchmarkClass) throws Exception {
        Options opt = new OptionsBuilder()
                .include(benchmarkClass.getSimpleName())
                .forks(1)
                .warmupIterations(5)
                .measurementIterations(5)
                .build();

        new Runner(opt).run();
    }
}

package de.cuioss.jwt.validation.benchmark.util;

import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

public class BenchmarkRunner {

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

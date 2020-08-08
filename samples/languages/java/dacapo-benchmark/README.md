Running the Java DaCapo benchmark suite with SGX-LKL
====================================================

**Note that this is work-in-progress.**

1. Build a Docker container with the DaCapo benchmark jar:
```
$ docker build -t java-dacapo .
```

2. Convert the container to an SGX-LKL root file system image:
```
$ sgx-lkl-disk create --docker=java-dacapo --size=500M java-dacapo.img
```

3. Edit `java-dacapo-enclave_config.json` to choose which benchmark to run. The full list of benchmarks is:
```
avrora batik eclipse fop h2 jython luindex lusearch lusearch-fix pmd sunflow tomcat tradebeans tradesoap xalan
```

By default, the benchmark `avrora` is run. The enclave size is 2 GiB.

4. Run the benchmark with SGX-LKL:
```
$ sgx-lkl-run-oe --hw-debug --host-config=java-dacapo-host_config.json --enclave-config=java-dacapo-enclave_config.json
```

Notes
-----

- Currently the following benchmarks are passing/failing:

  - PASSING: avrora fop h2 [sw only] luindex pmd sunflow xalan
  - FAILING: batik [OpenJDK unsupported] eclipse [OpenJDK unsupported] jython [illegal instruction] lusearch-fix [segfault] tomcat [networking issue] tradebeans [networking issue] tradesoap [networking issue]

Some of the benchmarks are affected by the fact that, with SGX1, signal handling support inside SGX enclaves is limited, as documented [here](https://github.com/lsds/sgx-lkl/blob/oe_port/docs/Incompatibilities.md).

- When running multiple benchmarks in sequence, ensure that the root file system image has not been corrupted after a failed benchmark run.

- You can add `-verbose:gc` to the java parameters to output GC activity. Other verbose JVM Hotspot options are:
```
    "-verbose:class",
    "-verbose:jni",
    "-verbose:gc",
    "-XX:+PrintCompilation",
    "-XX:+PrintGCDetails",
    "-Xcomp"
```

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

By default, the benchmark `avrora` is run. The enclave size is chosen to be a generous 8 GiB.

4. Run the benchmark with SGX-LKL:
```
$ SGXLKL_MMAP_FILES=Shared sgx-lkl-run-oe --sw-debug --host-config=java-dacapo-host_config.json --enclave-config=java-dacapo-enclave_config.json 
```

Notes
-----

- Currently the follwing benchmarks are passing/failing:

  - PASSING: avrora fop h2 (sw only) luindex (sw only) pmd (sw only) sunflow xalan (sw only)
  - FAILING: batik (headless JRE?) eclipse (headless JRE?) jython lusearch-fix tomcat (networking issue) tradebeans (networking issue) tradesoap (networking issue)

- When running multiple benchmarks in sequence, ensure that the root file system image has not been corrupted after a failed benchmark runs.

- You can add `-verbose:gc` to the java parameters to output GC activity.

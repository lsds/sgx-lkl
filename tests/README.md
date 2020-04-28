# How to Create a Test?

1. Create a new directory in tests and switch to your new directory.
2. Create a test in C / Python script / any other preferred method.

    A test failure can be reported via:

    - non-zero exit code
    - STDOUT/STDERR of the program contains one or more failure identifiers from $SGXLKL_ROOT/.azure-pipelines/other/failure_identifiers.txt(case sensitive).

    Tests should return a non-zero exit code in the case of failure.

3. Create a Makefile

    The Makefile must have targets for:

    - clean
    - run-hw
    - run-sw

    Optional targets are:

    - gettimeout

# How Automation Framework Works?

1.  It iterates through test directory recursively and identifies all the Makefile instances.
2.  Then, for each $SGXLKL_ROOT/.azure-pipelines/scripts/run_test.sh is executed.
3.  Switch back to $SGXLKL_ROOT directory.

See $SGXLKL_ROOT/.azure-pipelines/scripts/test_runner.sh and $SGXLKL_ROOT/.azure-pipelines/scripts/test_run.sh for full details.

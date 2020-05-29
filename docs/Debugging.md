Debugging
=========

SGX-LKL provides a wrapper around gdb called `sgx-lkl-gdb`.
This wrapper is compatible with IDEs and can be used instead of `gdb`.
`sgx-lkl-gdb` automatically loads the SGX-LKL gdb plugin which
ensures that debug symbols (if available) are loaded correctly. 
When running in hardware mode, `sgx-lkl-gdb` uses the corresponding SGX debug
instructions to read from and write to enclave memory.

## Prerequisites

### Open Enclave

`sgx-lkl-gdb` relies on the Open Enclave gdb plugin.
[Install Open Enclave](https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/install_oe_sdk-Ubuntu_18.04.md) if necessary before continuing.

The instructions below assume that Open Enclave was installed in the default directory `/opt/openenclave`.
If you used a different directory, run `. <OE_PREFIX>/share/openenclave/openenclaverc` first.

### Build mode

Debugging enclave code (SGX-LKL as well as the application code) is only possible in debug and non-release builds of SGX-LKL.

### Encrypted disks

TODO add note on how to handle situations when disk keys are retrieved from a remote service  (either re-create disks unencrypted, re-create disks encrypted but with debug-enabled key release policy (closest to production), or hard-code key in app config)

### Application type

Debugging of non-native applications like Python, Java or .NET applications is currently not possible.

### Docker deployment container

The instructions below assume that disk images and configuration are available outside of a Docker deployment container. Debugging of such deployment containers is not supported currently as they do not contain the necessary debugging tools.

## Option A: Debugging with an SGX-LKL installation

The instructions below assume that SGX-LKL was installed in `/opt/sgx-lkl`.

To debug an application, prefix the regular `sgx-lkl-run-oe` command with `sgx-lkl-gdb --args`, for example:
```
/opt/sgx-lkl/bin/sgx-lkl-gdb --args /opt/sgx-lkl/bin/sgx-lkl-run-oe --hw-debug root_disk.img /app
```
See `sgx-lkl-run-oe --help` for how to run using host and app config files.

## Option B: Debugging with an SGX-LKL source build

This assumes you want to debug SGX-LKL directly from the source tree without installing it.

To debug an application, prefix the regular `sgx-lkl-run-oe` command with `sgx-lkl-gdb --args`, for example:
```
tools/gdb/sgx-lkl-gdb --args build/sgx-lkl-run-oe --hw-debug root_disk.img /app
```
See `sgx-lkl-run-oe --help` for how to run using host and app config files.

## Debugging advice

### Visual Studio Code

Visual Studio Code allows to use a custom `gdb` command for debugging.
To use `sgx-lkl-gdb`, add `"miDebuggerPath": "/opt/sgx-lkl/bin/sgx-lkl-gdb"` (change path if necessary) in your `.vscode/launch.json` file.
Tip: Use the "Visual Studio Code Remote - SSH" extension to debug on a remote VM with SGX support.

### Run mode

When using `--sw-debug` then SGX hardware is simulated. However, not all aspects are simulated, for example, certain CPU instructions are invalid within SGX, but would execute fine in simulation mode.
If possible, debugging should be done in hardware mode to be as close to a production environment as possible.

### Ignore SIGILL

In some cases `sgx-lkl-gdb` still incorrectly stops at illegal instructions that are emulated inside the enclave (see e.g. https://github.com/lsds/sgx-lkl/issues/167). To avoid that, run `handle SIGILL pass nostop noprint` as first command in the active `gdb` session.

### Optimized code

In general, debugging optimized code is not recommended.
For an optimal debugging experience, SGX-LKL should be built in debug mode.
If the application code should be debugged as well and it is native code,
then the application should be built without optimizations and with debug symbols.

### Logging

In some situations it is useful to raise SGX-LKL's logging level to diagnose issues.
Set the environment variable `SGXLKL_VERBOSE` to `1` to enable verbose logging.
See `sgx-lkl-run-oe --help-config` for additional logging-related variables.

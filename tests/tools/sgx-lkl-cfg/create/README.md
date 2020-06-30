This test validates the following for the `sgx-lkl-cfg` tool:
- `sgx-lkl-cfg create` generates host/enclave config files that work in SGX-LKL.
- `sgx-lkl-cfg create` generates host/enclave config files that pass schema validation by `sgx-lkl-cfg validate`.
- `sgx-lkl-cfg create` generates an enclave config file that matches the reference file.
- `sgx-lkl-cfg create` converts the Docker image metadata (`ENV`, `WORKDIR`, `ENTRYPOINT`, `CMD`) produced by `sgx-lkl-disk` into relevant fields in the enclave config.

It currently **does not** test:
- `sgx-lkl-cfg create` converts the `.roothash`/`.hashoffset` files produced by `sgx-lkl-disk` into relevant fields in the enclave config.

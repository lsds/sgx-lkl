Running an Encrypted and Integrity Protected Confidential Container with SGX-LKL-OE
===================================================================================

The following example uses `dm-crypt` to encrypt the container image and `dm-verity` to add a (read-only) 
Merkle hash tree for integrity protection. It also supports `dm-integrity` for read-write block level
integrity protection.

1. Build the encrypted and integrity-protected confidential container images:

```
make
```

The encryption key used to encrypt the confidential container image is stored in 
`sgxlkl-alpine-crypt-verity.img.key` and `sgxlkl-alpine-crypt-integrity.img.key`, respectively. The 
root hash for `dm-verity` is stored in `sgxlkl-alpine-crypt-verity.img.roothash`.

2. Run a Python sample application from the confidential container with `dm-verity`:

```
make run-hw-verity 
```
or 
```
make run-sw-verity
```

The encryption key and the root hash are passed in using environment variables for demonstration purposes. For a 
secure deployment, they would be obtained externally after attestation.

3. Run a Python sample application from the confidential container with `dm-integrity`:

```
make run-hw-integrity
```
or 
```
make run-sw-integrity
```

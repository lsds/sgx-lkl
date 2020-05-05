FROM scratch
COPY . /

# Note: WORKDIR also creates the directory.
WORKDIR /tmp
ENV TMPDIR=/tmp

# See https://github.com/microsoft/Azure-DCAP-Client.
ENV AZDCAP_CACHE=

ENTRYPOINT ["/opt/sgx-lkl-debug/bin/sgx-lkl-run-oe", "--host-config=/host-cfg.json", "--app-config=/app-cfg.json"]
CMD ["--hw-debug"]

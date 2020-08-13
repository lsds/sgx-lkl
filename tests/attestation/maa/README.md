Test Scenario: Remote Attestation with MAA
==========================================
In this test scenario we have two enclaves: sgxlkl-enclave and oe-enclave.
sgxlkl-enclave app attests oe-enclave app via MAA (Microsoft Azure Attestation service) 

Here is the test flow:
1) oe-enclave is the tls server and runs and waits for tls client to connect
2) sgxlkl-enclave starts and connects to oe-enclave via TLS trusted connection
3) sgxlkl-enclave gets report of oe-enclave at TLS connection
3) sgxlkl-enclave gets authentication token from AAD (Azure Active Directory) in order to access MAA
4) sgxlkl-enclave calls MAA remote attestation service for JWT token and gets, parses and verifies

This scenario test depends on passed environment variables for credentials and urls in order to access MAA service.
These environment variables passed to sgx-lkl enclave in maa/sgx-lkl-enclave/enclave-config.json 
These are injected by ADO in pipeline:
- MAA_CLIENT_ID // Client ID needed for accessing AAD to get authentication token
- MAA_CLIENT_SECRET // Client Secret needed for accessing AAD to get authentication token
- MAA_APP_ID // Application ID needed for accessing AAD to get authentication token   
- MAA_ADDR_APP // This is the URL of AAD to get authentication bearer token to use accessing MAA
- MAA_ADDR // This is the URL of MAA attestation service endpoint
- MAA_TEST1_OE_ENCLAVE_MRSIGNER // This is created by run_scenrio.sh with 'oesign dump' command. This is the MRSIGNER of oe-enclave that will be verified by sgx-lkl-enclave

Why attestation/common/host_verify/ needed:
For attestation, sgx-lkl-enclave needs to extract the report of oe-enclave from certificate. Unfortunately OE SDK doesn't support this feature yet. Until it is supported natively by OE SDK, we need these files to extract and verify report from certificate.  

Why we need predefined certificate fo sgx-lkl-enclave:
sgx-lkl doesn't support auto self generated certificates yet. Until this is supported by sgx-lkl we need to use predefined certificate for trusted TLS connection to oe-enclave.

This test scenario has two enclaves whereas most of the tests has only one enclave. The sgx-lkl test framework looks for Makefiles under tests/ folder to detecet tests to run. To overcome this logic, makefile (starting with lowercase) is used for each enclave's folder and Makefile (with uppercase) is used for the actual test to be detected by test framework as expected. 

Also oe-enclave runs as background process and it waits for tls client to connect to sgxlkl-enclave to start and connect via TLS trusted conenction and to get report, then it exits. sgxlkl-enclave runs as foreground process and it manages the getting report from oe-enclave and doing remote attestation against MAA and verifying expected values and deciding if test passed or failed.

The actual test run logic is in run_scenario.sh that called by Makefile for run-sw and run-hw test run modes. OE SDK is also installed for this test since needed by oe-enclave app to run.


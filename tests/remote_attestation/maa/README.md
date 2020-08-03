Test Scenario: Remote Attestation with MAA
==========================================
In this test scenario we have two enclaves: sgxlkl-enclave and oe-enclave.
sgxlkl-enclave app attests oe-enclave app via MAA (Microsoft Azure Attestation service) 

Here is the test flow:
1) oe-enclave is the tls server and runs and sleeps 45 seconds and exits
2) sgxlkl-enclave starts and connects to oe-enclave via TLS trusted connection
3) sgxlkl-enclave gets report of oe-enclave at TLS connection
3) sgxlkl-enclave gets authentication token from AAD (Azure Active Directory) in order to access MAA
4) sgxlkl-enclave calls MAA remote attestation service for JWT token and gets, parses and verifies

This scenario test depends on passed environment variables for credentials and urls accessing MAA service. 
These are injected by ADO in pipeline:
- MAA_CLIENT_ID,
- MAA_CLIENT_SECRET
- MAA_APP_ID
- MAA_ADDR
- MAA_ADDR_APP

This test scenario has two enclaves whereas most of the tests has only one enclave. The sgx-lkl test framework looks for Makefiles under tests/ folder to detecet tests to run. To overcome this logic, makefile (starting with lowercase) is used for each enclave's folder and Makefile (with uppercase) is used for the actual test to be detected by test framework as expected. 

Also oe-enclave runs as background process and it sleeps for 45 seconds to give enough time to sgxlkl-enclave to start and connect via TLS trusted conenction and to get report, then it exits. sgxlkl-enclave runs as foreground process and it manages the getting report from oe-enclave and doing remote attestation against MAA and verifying expected values and deciding if test passed or failed.

The actual test run logic is in run_scenario.sh that called by Makefile for run-sw and run-hw test run modes. OE SDK is also installed for this test since needed by oe-enclave app to run.


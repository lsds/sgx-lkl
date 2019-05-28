/*
Based on
https://github.com/cloud-security-research/sgx-ra-tls/blob/05ee68aad898e85ee1142ae257167666e501d977/nonsdk-ra-attester.c.
See copyright below.

Copyright 2017, Intel(R) Corporation (http://www.intel.com)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/* This code generates a quote without using the SGX SDK. We
   communicate directly with the architecture enclave (AE) over
   protocol buffers. */
/* Prepend my_ to prevent name clash with SGX SDK's declaration. Make
   the simplifying assumption of no revocation lists. */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <epid/common/types.h>
#include <internal/se_quote_internal.h>
#include <sgx_uae_service.h>
#include <sgx_report.h>

#include "aesm.h"
#include "attest.h"
#include "attest_ias.h"
#include "messages.pb-c.h"
#include "sgxlkl_util.h"

/* Each protobuf is preceeded by its length stored in a uint32_t. */
static uint32_t hdr_len = sizeof(uint32_t);

static
sgx_status_t my_sgx_calc_quote_size(const uint8_t *sig_rl, uint32_t sig_rl_size, uint32_t* p_quote_size)
{
    assert(p_quote_size);
    assert(sig_rl == NULL);
    assert(sig_rl_size == 0);

    uint64_t quote_size = 0;
    uint64_t sign_size = 0;

    sign_size = sizeof(EpidSignature) - sizeof(NrProof);
    quote_size = SE_QUOTE_LENGTH_WITHOUT_SIG + sign_size;
    assert(quote_size < (1ull << 32));

    *p_quote_size = (uint32_t)(quote_size);
    return SGX_SUCCESS;
}

static
void init_quote_request(int fd) {
    Aesm__Message__Request__InitQuoteRequest req = AESM__MESSAGE__REQUEST__INIT_QUOTE_REQUEST__INIT;
    Aesm__Message__Request msg = AESM__MESSAGE__REQUEST__INIT;
    msg.initquotereq = &req;

    uint32_t proto_len = aesm__message__request__get_packed_size(&msg);
    uint32_t len = hdr_len + proto_len;

    char* buf = malloc(len);

    memcpy(buf, (uint8_t*)&proto_len, hdr_len);
    aesm__message__request__pack(&msg, (uint8_t*) (buf + hdr_len));

    int rc = send(fd, buf, len, 0);
    assert((ssize_t) rc == len);
    free(buf);
}

static
void init_quote_response
(
    int fd,
    sgx_target_info_t* target_info,
    sgx_epid_group_id_t* group_id
)
{
    // 4 byte payload size
    uint32_t reply_len;
    int rc = recv(fd, &reply_len, sizeof(reply_len), 0);
    assert(rc == sizeof(uint32_t));

    // payload
    uint8_t* reply = malloc(reply_len);
    assert(reply != NULL);
    rc = recv(fd, reply, reply_len, 0);
    assert((ssize_t) rc == reply_len);

    // de-serialize protobuf
    Aesm__Message__Response* msg =
        aesm__message__response__unpack(NULL, reply_len, reply);

    assert(msg->initquoteres != NULL);
    Aesm__Message__Response__InitQuoteResponse* qr = msg->initquoteres;
    assert(qr->has_targetinfo);
    assert(qr->has_gid);

    assert(qr->targetinfo.len == sizeof(*target_info));
    assert(qr->gid.len == sizeof(*group_id));
    memcpy(target_info, qr->targetinfo.data, sizeof(*target_info));
    memcpy(group_id, qr->gid.data, sizeof(*group_id));

    free(reply); reply = NULL;
}

static
void get_quote_request(
    int fd,
    sgx_report_t* report,
    sgx_quote_sign_type_t quote_type,
    sgx_spid_t* spid,
    uint32_t quote_size
    )
{
    Aesm__Message__Request__GetQuoteRequest req = AESM__MESSAGE__REQUEST__GET_QUOTE_REQUEST__INIT;
    Aesm__Message__Request msg = AESM__MESSAGE__REQUEST__INIT;
    msg.getquotereq = &req;

    req.report.data = (uint8_t*) report;
    req.report.len = sizeof(*report);
    /* printf("len report= %lu\n", sizeof(*report)); */
    req.quote_type = quote_type;
    req.spid.data = (uint8_t*) spid;
    req.spid.len = sizeof(*spid);
    /* printf("len spid= %lu\n", sizeof(*spid)); */
    req.has_qe_report = 1;
    req.qe_report = 0;
    req.has_timeout = 1;
    req.timeout = 15000;
    req.buf_size = quote_size;

    uint32_t payload_len = aesm__message__request__get_packed_size(&msg);
    uint32_t total_len = hdr_len + payload_len;

    char* buf = malloc(total_len);
    assert(buf != NULL);

    memcpy(buf, (uint8_t*)&payload_len, hdr_len);
    aesm__message__request__pack(&msg, (uint8_t*) buf + hdr_len);

    int rc = send(fd, buf, total_len, 0);
    assert((ssize_t) rc == total_len);
    free(buf);
}

static
void get_quote_response(
    int fd,
    sgx_quote_t* quote,
    uint32_t quote_size
    )
{
    // header
    uint32_t payload_len;
    int rc = recv(fd, &payload_len, sizeof(payload_len), 0);
    assert(rc == sizeof(uint32_t));

    // payload
    uint8_t* payload = malloc(payload_len);
    assert(payload != NULL);
    rc = recv(fd, payload, payload_len, 0);
    assert(rc != -1);
    assert((ssize_t) rc == payload_len);

    Aesm__Message__Response* msg =
        aesm__message__response__unpack(NULL, payload_len, payload);
    assert(msg->getquoteres != NULL);
    Aesm__Message__Response__GetQuoteResponse* r = msg->getquoteres;
    assert(r->has_quote);
    assert(r->quote.len == quote_size);
    memcpy(quote, r->quote.data, r->quote.len);
}

static
int open_socket(char *socket_path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return fd;

    struct sockaddr_un saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sun_family = AF_UNIX;
    strncpy(saddr.sun_path, socket_path, sizeof(saddr.sun_path));

    int rc;
    if((rc = connect(fd, (struct sockaddr *)&saddr, sizeof(saddr))) != 0) {
        close(fd);
        return rc;
    }

    return fd;
}

sgx_quote_t* aesm_alloc_quote(uint32_t* sz) {
    my_sgx_calc_quote_size(NULL, 0, sz);
    void* b = malloc(*sz);
    return (sgx_quote_t*) b;
}

int aesm_init_quote
(
    sgx_target_info_t *target_info,
    sgx_epid_group_id_t *gid
)
{
    int fd = open_socket(AESM_SOCKET_PATH);
    if (fd == -1) {
        sgxlkl_warn("Failed to open AESM socket %s: %s\n", AESM_SOCKET_PATH, strerror(errno));
        return 1;
    }
    init_quote_request(fd);
    init_quote_response(fd, target_info, gid);
    close(fd);

    return 0;
}

int aesm_get_quote
(
    sgx_spid_t *spid, // in
    sgx_quote_sign_type_t quote_type, // in
    sgx_report_t* report, // in
    sgx_quote_t* quote, // out
    uint32_t quote_size
)
{
    int fd = open_socket(AESM_SOCKET_PATH);
    if (fd == -1) {
        sgxlkl_warn("Failed to open AESM socket %s: %s\n", AESM_SOCKET_PATH, strerror(errno));
        return 1;
    }
    get_quote_request(fd, report, quote_type, spid, quote_size);
    get_quote_response(fd, quote, quote_size);
    close(fd);

    return 0;
}

/*
 * Copyright 2016, 2017, 2018 Imperial College London (under GNU General Public License v3)
 * Copyright 2016, 2017 TU Dresden (under SCONE source code license)
 */

#include <stdlib.h>
#include <polarssl/sha256.h>
#include <polarssl/rsa.h>
#include "sgx.h"

void rsa_sign(rsa_context *ctx, rsa_sig_t sig,
        unsigned char *bytes, int len) {
    // generate hash for current sigstruct
    unsigned char hash[32];
    sha256(bytes, len, hash, 0);
    // make signature
    int ret = rsa_pkcs1_sign(ctx, NULL, NULL, RSA_PRIVATE,
            POLARSSL_MD_SHA256, 32, hash,
            (unsigned char *)sig);
    if (ret)
        printf("failed to sign\n");
}

void reverse(unsigned char *in, size_t bytes) {
    unsigned char temp;
    int i;
    int end;

    end = bytes - 1;
    for (i = 0; i < bytes / 2; i++) {
        temp    = in[i];
        in[i]   = in[end];
        in[end] = temp;
        end--;
    }
}

void load_bytes_from_str(uint8_t *key, char *bytes, size_t size) {
    if (bytes && (bytes[0] == '\n' || bytes[0] == '\0')) {
        return;
    }

    for (int i = 0; i < size; i++) {
        sscanf(bytes + i*2, "%02X", (unsigned int *)&key[i]);
    }
}

rsa_context *load_rsa_keys(char *conf, uint8_t *pubkey, uint8_t *seckey, int bits) {
    FILE *fp = fopen(conf, "r");
    if (!fp) {
        fprintf(stderr, "failed to locate %s\n", conf);
        exit(EXIT_FAILURE);
    }

    char *line = NULL;
    size_t len = 0;

    const int npubkey = strlen("PUBKEY: ");
    const int nseckey = strlen("SECKEY: ");
    const int np = strlen("P: ");
    const int nq = strlen("Q: ");
    const int ne = strlen("E: ");

    size_t bytes;
    bytes = bits >> 3;
    if ((bits & 0x7) > 0)
        bytes++;

    uint8_t *pk;
    uint8_t *sk;
    uint8_t *p;
    uint8_t *q;
    uint8_t *e;

    pk = malloc(bytes + 8);
    sk = malloc(bytes + 8);
    p = malloc(bytes + 8);
    q = malloc(bytes + 8);
    e = malloc(bytes + 8);

    while (getline(&line, &len, fp) != -1) {
        // skip comments
        if (len > 0 && line[0] == '#')
            continue;

        if (!strncmp(line, "PUBKEY: ", npubkey))
            load_bytes_from_str(pk, line + npubkey, bytes);
        else if (!strncmp(line, "SECKEY: ", nseckey))
            load_bytes_from_str(sk, line + nseckey, bytes);
        else if (!strncmp(line, "P: ", np))
            load_bytes_from_str(p, line + np, bytes);
        else if (!strncmp(line, "Q: ", nq))
            load_bytes_from_str(q, line + nq, bytes);
        else if (!strncmp(line, "E: ", ne))
            load_bytes_from_str(e, line + ne, bytes);
    }

    free(line);
    fclose(fp);

    // XXX: workaroud to avoid first three bytes in pubkey set to zero during
    //      file loading.
    memcpy(pubkey, pk, bytes);
    memcpy(seckey, sk, bytes);

    rsa_context *ctx = malloc(sizeof(rsa_context));
    if (!ctx)
        printf( "failed to allocate rsa ctx");

    rsa_init(ctx, RSA_PKCS_V15, 0);

    // setup ctx
    mpi_read_binary(&ctx->N, pubkey, bytes);
    mpi_read_binary(&ctx->D, seckey, bytes);
    mpi_read_binary(&ctx->P, p, bytes);
    mpi_read_binary(&ctx->Q, q, bytes);
    mpi_read_binary(&ctx->E, e, bytes);

    int ret;
    mpi P1, Q1, H;
    mpi_init(&P1);
    mpi_init(&Q1);
    mpi_init(&H);
    MPI_CHK(mpi_sub_int(&P1, &ctx->P, 1));
    MPI_CHK(mpi_sub_int(&Q1, &ctx->Q, 1));
    MPI_CHK(mpi_mul_mpi(&H, &P1, &Q1));
    MPI_CHK(mpi_inv_mod(&ctx->D , &ctx->E, &H));
    MPI_CHK(mpi_mod_mpi(&ctx->DP, &ctx->D, &P1));
    MPI_CHK(mpi_mod_mpi(&ctx->DQ, &ctx->D, &Q1));
    MPI_CHK(mpi_inv_mod(&ctx->QP, &ctx->Q, &ctx->P));

    ctx->len = mpi_size(&ctx->N);
cleanup:
    return ctx;
}

void cmd_sign(sigstruct_t* sigstruct, char *key) {
    rsa_sig_t sign;
    rsa_key_t pubkey;
    rsa_key_t seckey;
    rsa_context *ctx;

    sigstruct_t sig2;
    memcpy(&sig2, sigstruct, sizeof(*sigstruct));

    // Ignore fields don't need to sign
    memset(sigstruct->modulus, 0, 384);
    sigstruct->exponent = 0;
    memset(sigstruct->signature, 0, 384);
    memset(sigstruct->q1, 0, 384);
    memset(sigstruct->q2, 0, 384);

    ctx = load_rsa_keys(key, pubkey, seckey, KEY_LENGTH_BITS);

    memmove(&sig2.modulus, &sig2.miscselect, 128);

    // Generate rsa sign on sigstruct with private key
    rsa_sign(ctx, sign, (unsigned char *)&sig2, 256);

    // Compute q1, q2
    unsigned char *q1, *q2;
    q1 = malloc(384);
    q2 = malloc(384);
    memset(q1, 0, 384);
    memset(q2, 0, 384);

    mpi Q1, Q2, S, M, T1, T2, R;
    mpi_init(&Q1);
    mpi_init(&Q2);
    mpi_init(&S);
    mpi_init(&M);
    mpi_init(&T1);
    mpi_init(&T2);
    mpi_init(&R);

    // q1 = signature ^ 2 / modulus
    mpi_read_binary(&S, sign, 384);
    mpi_read_binary(&M, pubkey, 384);
    mpi_mul_mpi(&T1, &S, &S);
    mpi_div_mpi(&Q1, &R, &T1, &M);

    // q2 = (signature ^ 3 - q1 * signature * modulus) / modulus
    mpi_init(&R);
    mpi_mul_mpi(&T1, &T1, &S);
    mpi_mul_mpi(&T2, &Q1, &S);
    mpi_mul_mpi(&T2, &T2, &M);
    mpi_sub_mpi(&Q2, &T1, &T2);
    mpi_div_mpi(&Q2, &R, &Q2, &M);

    mpi_write_binary(&Q1, q1, 384);
    mpi_write_binary(&Q2, q2, 384);

    mpi_free(&Q1);
    mpi_free(&Q2);
    mpi_free(&S);
    mpi_free(&M);
    mpi_free(&T1);
    mpi_free(&T2);
    mpi_free(&R);

    memcpy(sigstruct, &sig2, sizeof(*sigstruct));

    sigstruct->exponent = 3;
    memcpy(sigstruct->modulus, pubkey, 384);
    memcpy(sigstruct->signature, sign, 384);
    memcpy(sigstruct->q1, q1, 384);
    memcpy(sigstruct->q2, q2, 384);

    reverse(sigstruct->modulus, 384);
    reverse(sigstruct->signature, 384);
    reverse(sigstruct->q1, 384);
    reverse(sigstruct->q2, 384);
}

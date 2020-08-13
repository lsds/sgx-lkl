#ifndef OE_HEADER_H
#define OE_HEADER_H

#include "oe_defs.h"

#define oe_memcpy_s(a,b,c,d) (memcpy((a),(c),(d)) ? OE_OK : OE_FAILURE)

/* Atomically increment **x** and return its new value */
OE_INLINE uint64_t oe_atomic_increment(volatile uint64_t* x)
{
#if defined(__GNUC__)
    return __sync_add_and_fetch(x, 1);
#elif defined(_MSC_VER)
    return _InterlockedIncrement64((__int64*)x);
#else
#error "unsupported"
#endif
}

/* Atomically decrement **x** and return its new value */
OE_INLINE uint64_t oe_atomic_decrement(volatile uint64_t* x)
{
#if defined(__GNUC__)
    return __sync_sub_and_fetch(x, 1);
#elif defined(_MSC_VER)
    return _InterlockedDecrement64((__int64*)x);
#else
#error "unsupported"
#endif
}

#define OE_CRL_MAGIC 0xf8cf8e04f4ed40f3
bool crl_is_valid(const crl_t* impl)
{
    return impl && (impl->magic == OE_CRL_MAGIC) && impl->crl;
}

OE_INLINE void oe_secure_zero_fill(volatile void* ptr, size_t size)
{
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    while (size--)
    {
        *p++ = 0;
    }
}    

OE_INLINE bool oe_is_rsa_key(const mbedtls_pk_context* pk)
{
    return (pk->pk_info == mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
}

bool oe_public_key_is_valid(const oe_public_key_t* public_key, uint64_t magic)
{
    return public_key && public_key->magic == magic;
}

oe_result_t oe_public_key_write_pem(
    const oe_public_key_t* public_key,
    uint8_t* pem_data,
    size_t* pem_size,
    uint64_t magic);

oe_result_t oe_ec_public_key_write_pem(
    const oe_ec_public_key_t* private_key,
    uint8_t* pem_data,
    size_t* pem_size)
{
    return oe_public_key_write_pem(
        (const oe_public_key_t*)private_key,
        pem_data,
        pem_size,
        _PUBLIC_KEY_MAGIC);
}

void oe_public_key_release(oe_public_key_t* public_key, uint64_t magic)
{
    if (oe_public_key_is_valid(public_key, magic))
    {
        mbedtls_pk_free(&public_key->pk);
        oe_secure_zero_fill(public_key, sizeof(oe_public_key_t));
    }
}

oe_result_t oe_public_key_free(oe_public_key_t* public_key, uint64_t magic);

oe_result_t oe_ec_public_key_free(oe_ec_public_key_t* public_key)
{
    return oe_public_key_free((oe_public_key_t*)public_key, _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_rsa_public_key_free(oe_rsa_public_key_t* public_key)
{
    return oe_public_key_free((oe_public_key_t*)public_key, _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_public_key_init(
    oe_public_key_t* public_key,
    const mbedtls_pk_context* pk,
    oe_copy_key copy_key,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!public_key || (pk && !copy_key) || (copy_key && !pk))
        OE_RAISE(OE_INVALID_PARAMETER);

    public_key->magic = 0;

    if (pk && copy_key)
        OE_CHECK(copy_key(&public_key->pk, pk, false));
    else
        mbedtls_pk_init(&public_key->pk);

    public_key->magic = magic;

    result = OE_OK;

done:
    return result;
}

static oe_result_t _copy_key(
    mbedtls_pk_context* dest,
    const mbedtls_pk_context* src,
    bool copy_private_fields)
{
    oe_result_t result = OE_UNEXPECTED;
    const mbedtls_pk_info_t* info;
    int rc = 0;

    if (dest)
        mbedtls_pk_init(dest);

    /* Check parameters */
    if (!dest || !src)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Lookup the info for this key type */
    if (!(info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)))
        OE_RAISE(OE_PUBLIC_KEY_NOT_FOUND);

    /* Setup the context for this key type */
    rc = mbedtls_pk_setup(dest, info);
    if (rc != 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "rc = 0x%x", rc);

    /* Copy all fields of the key structure */
    {
        mbedtls_ecp_keypair* ec_dest = mbedtls_pk_ec(*dest);
        const mbedtls_ecp_keypair* ec_src = mbedtls_pk_ec(*src);

        if (!ec_dest || !ec_src)
            OE_RAISE(OE_FAILURE);

        if (mbedtls_ecp_group_copy(&ec_dest->grp, &ec_src->grp) != 0)
            OE_RAISE(OE_CRYPTO_ERROR);

        if (copy_private_fields)
        {
            if (mbedtls_mpi_copy(&ec_dest->d, &ec_src->d) != 0)
                OE_RAISE(OE_CRYPTO_ERROR);
        }

        if (mbedtls_ecp_copy(&ec_dest->Q, &ec_src->Q) != 0)
            OE_RAISE(OE_CRYPTO_ERROR);
    }

    result = OE_OK;

done:

    if (result != OE_OK)
        mbedtls_pk_free(dest);

    return result;
}

oe_result_t oe_rsa_public_key_init(
    oe_rsa_public_key_t* public_key,
    const mbedtls_pk_context* pk)
{
    return oe_public_key_init(
        (oe_public_key_t*)public_key, pk, _copy_key, _PUBLIC_KEY_MAGIC);
}

OE_INLINE bool oe_is_ec_key(const mbedtls_pk_context* pk)
{
    return (pk->pk_info == mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
}

oe_result_t oe_rsa_public_key_write_pem(
    const oe_rsa_public_key_t* private_key,
    uint8_t* pem_data,
    size_t* pem_size)
{
    return oe_public_key_write_pem(
        (const oe_public_key_t*)private_key,
        pem_data,
        pem_size,
        _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_ec_public_key_init(
    oe_ec_public_key_t* public_key,
    const mbedtls_pk_context* pk)
{
    return oe_public_key_init(
        (oe_public_key_t*)public_key, pk, _copy_key, _PUBLIC_KEY_MAGIC);
}

#endif

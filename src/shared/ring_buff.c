/*******************************************************************************
 *
 * Copyright (c) 2012 Vladimir Maksovic
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * * Neither Vladimir Maksovic nor the names of this software contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL VLADIMIR MAKSOVIC
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shared/ring_buff.h"

#if 0
#define RING_BUFF_DBG_MSG
#endif

#define GET_RING_BUFF_OBJ(handle) ((ring_buff_obj_t*)handle)

typedef struct ring_buff_obj
{
    /** Buffer */
    uint8_t* write_buff;
    uint8_t* read_buff;
    /** Buffer size */
    uint32_t size;
    /** Read pointer (available data start) */
    unsigned int read;
    /** Write pointer (free memory start) */
    unsigned int write;
    /** Accumulation window pointer (it does not have info about the wrapped
     * data) */
    unsigned int acc;
    /**
     * End of Data pointer. Used in reading mode. It marks last byte available
     * for reading before write pointer wrapped to the buffer start.
     */
    int eod;
    /** Continuous data available */
    uint32_t acc_size;

    int isEmpty;
} ring_buff_obj_t;

int ring_buff_struct_size()
{
    return sizeof(ring_buff_obj_t);
}

void ring_buff_set_read_buff(ring_buff_handle_t handle, uint8_t* read_buff)
{
    ring_buff_obj_t* obj = GET_RING_BUFF_OBJ(handle);
    obj->read_buff = read_buff;
}

void ring_buff_set_write_buff(ring_buff_handle_t handle, uint8_t* write_buff)
{
    ring_buff_obj_t* obj = GET_RING_BUFF_OBJ(handle);
    obj->write_buff = write_buff;
}

ring_buff_err_t ring_buff_create(
    ring_buff_attr_t* attr,
    ring_buff_handle_t* handle)
{
    ring_buff_obj_t* obj = NULL;
    ring_buff_err_t err_code = RING_BUFF_ERR_BAD_ARG;

    if (attr == NULL || handle == NULL)
    {
        goto done;
    }
    if (attr->size == 0 || attr->buff == NULL)
    {
        goto done;
    }
    // MN: If given handle does not point to NULL, use it instead of allocating
    // memory
    if (*(handle) != NULL)
    {
        obj = (ring_buff_obj_t*)*handle;
    }
    else
    {
        obj = malloc(sizeof(ring_buff_obj_t));
    }
    if (obj == NULL)
    {
        err_code = RING_BUFF_ERR_NO_MEM;
        goto done;
    }
    memset(obj, 0, sizeof(ring_buff_obj_t));

    obj->write_buff = attr->buff;
    obj->read_buff = attr->buff;
    obj->size = attr->size;
    obj->read = 0;
    obj->write = 0;
    obj->acc = 0;
    obj->eod = -1;
    obj->acc_size = 0;
    obj->isEmpty = 0;
    err_code = RING_BUFF_ERR_OK;

done:
    if (handle != NULL)
    {
        *handle = obj;
    }
    return err_code;
}

ring_buff_err_t ring_buff_destroy(ring_buff_handle_t handle)
{
    ring_buff_obj_t* obj = GET_RING_BUFF_OBJ(handle);

    if (obj == NULL)
    {
        return RING_BUFF_ERR_GENERAL;
    }
    free(obj);

    return RING_BUFF_ERR_OK;
}

ring_buff_err_t ring_buff_reserve(
    ring_buff_handle_t handle,
    void** buff,
    uint32_t size)
{
    ring_buff_obj_t* obj = GET_RING_BUFF_OBJ(handle);

    if (handle == NULL || buff == NULL)
    {
        return RING_BUFF_ERR_BAD_ARG;
    }
    if (size > obj->size)
    {
        return RING_BUFF_ERR_SIZE;
    }
    /* simple situation, there is enough space left till the end of buffer */
    int read = __atomic_load_n(&(obj->read), __ATOMIC_RELAXED);
    if (size <= obj->size - obj->write)
    {
        // MN: bugfix in condition
        /* don't want to overwrite read buffer partition, wait for free chunk if
         * read is too close up-front */
        if ((obj->write < read && obj->write + size > read) ||
            (obj->write == read && obj->isEmpty > 0))
            return RING_BUFF_ERR_NO_MEM;

        *buff = obj->write_buff + obj->write;
        obj->write += size;
    }
    /* wrap around */
    else
    {
#ifdef RING_BUFF_DBG_MSG
        printf(
            "RESERVE: Wrap around %d (%p) RD %p ACC %p WR %p\n",
            size,
            obj->buff,
            obj->read,
            obj->acc,
            obj->write);
#endif
        /* try to get buffer from the beginning, and be sure that read is not
         * overwritten */
        if (read < size || read > obj->write ||
            (obj->write == read && obj->isEmpty > 0))
            return RING_BUFF_ERR_NO_MEM;

        /* reader must not exceed data available (current write) */
        obj->eod = obj->write;
        *buff = obj->write_buff;
        obj->write = size;
    }

    __atomic_fetch_add(&(obj->isEmpty), size, __ATOMIC_RELAXED);

    return RING_BUFF_ERR_OK;
}

ring_buff_err_t ring_buff_commit(
    ring_buff_handle_t handle,
    void* buff,
    uint32_t size)
{
    ring_buff_obj_t* obj = GET_RING_BUFF_OBJ(handle);

    if (handle == NULL || buff == NULL)
    {
        return RING_BUFF_ERR_BAD_ARG;
    }

    // For commit just modifiy acc_size to signal that data is available to be
    // read.
    __atomic_fetch_add(&(obj->acc_size), size, __ATOMIC_RELAXED);

    return RING_BUFF_ERR_OK;
}

ring_buff_err_t ring_buff_free(
    ring_buff_handle_t handle,
    void* buff,
    uint32_t size)
{
    ring_buff_obj_t* obj = GET_RING_BUFF_OBJ(handle);

    if (obj == NULL)
    {
        return RING_BUFF_ERR_BAD_ARG;
    }
    /* Free will just update read pointer. It is up to the user to call it in
     * proper order. */
    obj->read = ((uint64_t)buff - (uint64_t)obj->read_buff) + size;

    __atomic_fetch_sub(&(obj->isEmpty), size, __ATOMIC_RELAXED);

    return RING_BUFF_ERR_OK;
}

ring_buff_err_t ring_buff_read(
    ring_buff_handle_t handle,
    void** buff,
    uint32_t size,
    uint32_t* read)
{
    ring_buff_obj_t* obj = GET_RING_BUFF_OBJ(handle);
    ring_buff_err_t err = RING_BUFF_ERR_OK;

    if (handle == NULL || buff == NULL || size > obj->size || read == NULL)
    {
        return RING_BUFF_ERR_BAD_ARG;
    }
    int acc_size = __atomic_load_n(&(obj->acc_size), __ATOMIC_RELAXED);
    /* make sure that we have enough data available */
    if (size > acc_size)
        return RING_BUFF_ERR_NO_MEM;

    if (obj->acc + size > obj->size)
    {
        obj->acc = 0;
    }

    *buff = obj->read_buff + obj->acc;
    /* If writer wrapped, and we don't have enough data at the end, give as much
     * as we can */
    if (obj->eod != -1 && (obj->acc + size > obj->eod))
    {
        *read = obj->eod - obj->acc;

        /* just a wrap (no data) available -> wrap right away and give requested
         * size */
        if (*read == 0)
        {
            *read = size;
            *buff = obj->read_buff;
            obj->acc = *read;
        }
        else
        {
            obj->acc = 0;
        }
        __atomic_fetch_sub(&(obj->acc_size), *read, __ATOMIC_RELAXED);
        /* reset EOD */
        obj->eod = -1;
#ifdef RING_BUFF_DBG_MSG
        printf(
            "READ: Wrap around %u (%u) %p %p\n",
            *read,
            obj->acc_size,
            obj->read,
            obj->acc);
#endif
    }
    else
    {
        __atomic_fetch_sub(&(obj->acc_size), size, __ATOMIC_RELAXED);
        obj->acc += size;

        *read = size;
    }
#ifdef RING_BUFF_DBG_MSG
    if (*buff + size > obj->buff + obj->size)
    {
        printf(
            "ACC: %p\nSize: %d\nRead: %d\nEOD: %p\n",
            obj->acc,
            size,
            *read,
            obj->eod);
    }
#endif
    return err;
}

ring_buff_err_t ring_buff_write_msg(
    ring_buff_handle_t handle,
    void* data,
    uint32_t size)
{
    ring_buff_obj_t* obj = GET_RING_BUFF_OBJ(handle);

    if (handle == NULL || data == NULL || size == 0 ||
        size + sizeof(uint32_t) > obj->size)
    {
        return RING_BUFF_ERR_BAD_ARG;
    }

    // Allocate buffer space for message + message-length
    uint32_t* sizePointer;
    ring_buff_err_t err = ring_buff_reserve(
        handle, (void**)&sizePointer, size + sizeof(uint32_t));
    if (err != RING_BUFF_ERR_OK)
        return err;

    // Write size of message and then its contents
    *sizePointer = size;

    void* dataPointer = (void*)(sizePointer + 1);
    memcpy(dataPointer, data, size);

    err = ring_buff_commit(handle, sizePointer, size + sizeof(uint32_t));
    return err;
}

ring_buff_err_t ring_buff_read_msg(
    ring_buff_handle_t handle,
    void** data,
    uint32_t* messageSize)
{
    if (handle == NULL || data == NULL)
    {
        return RING_BUFF_ERR_BAD_ARG;
    }

    // First read message size written before payload
    void* dataPointer;
    uint32_t read = 0;
    ring_buff_err_t err =
        ring_buff_read(handle, &dataPointer, sizeof(uint32_t), &read);

    if (err != RING_BUFF_ERR_OK)
    {
        return err;
    }

    // Sucessful read but too few bytes?
    if (read != sizeof(uint32_t))
        return RING_BUFF_ERR_INTERNAL;

    *(messageSize) = *((uint32_t*)dataPointer);

    // Free bytes for message size. Payload has to be freed manually later.
    err = ring_buff_free(handle, dataPointer, read);
    if (err != RING_BUFF_ERR_OK)
    {
        return err;
    }

    // Now read as many bytes as described in message length.
    err = ring_buff_read(handle, data, *messageSize, &read);
    if (err != RING_BUFF_ERR_OK)
    {
        return err;
    }

    if (read != *messageSize)
        return RING_BUFF_ERR_INTERNAL;

    return err;
}

void ring_buff_print_err(ring_buff_err_t err)
{
    switch (err)
    {
        case RING_BUFF_ERR_GENERAL:
            fprintf(stderr, "General error happened.\n");
            break;
        case RING_BUFF_ERR_NO_MEM:
            fprintf(stderr, "Out of memory error.\n");
            break;
        case RING_BUFF_ERR_OVERRUN:
            fprintf(stderr, "Internal error - buffer overrun.\n");
            break;
        case RING_BUFF_ERR_SIZE:
            fprintf(stderr, "Data size requested wrong.\n");
            break;
        case RING_BUFF_ERR_INTERNAL:
            fprintf(stderr, "Internal general error.\n");
            break;
        case RING_BUFF_ERR_PERM:
            fprintf(stderr, "Operation not permited.\n");
            break;
        default:
            fprintf(stderr, "Unknown error code: %d.\n", err);
            break;
    }
}

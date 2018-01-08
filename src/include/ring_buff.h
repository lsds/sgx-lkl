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


#ifndef RING_BUFF_H_
#define RING_BUFF_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Error types.
 */
typedef enum ring_buff_err
{
	/** No error */
	RING_BUFF_ERR_OK = 0,
	/** No error */
	RING_BUFF_ERR_BAD_ARG = 1,
	/** General error */
	RING_BUFF_ERR_GENERAL = 2,
	/** Out of memory error */
	RING_BUFF_ERR_NO_MEM = 3,
	/** Buffer overrun error */
	RING_BUFF_ERR_OVERRUN = 4,
	/** Request size wrong error */
	RING_BUFF_ERR_SIZE = 5,
	/** Internal (system) error */
	RING_BUFF_ERR_INTERNAL = 6,
	/** Operation not permitted (e.g. reading after cancel is called) */
	RING_BUFF_ERR_PERM = 7
} ring_buff_err_t;

/** Ring buffer handle. */
typedef void* ring_buff_handle_t;

/**
 * Ring buffer attribute structure. It is used when ring buffer is created.
 */
typedef struct ring_buff_attr
{
	/** Memory used for ring buffer. */
	void* buff;
	/** Buffer size. */
	uint32_t size;
} ring_buff_attr_t;

/**
 * Returns the size of the ring buffer management structure. This should be used if the
 * memory for a ring buffer should be allocated at a specific location.
 */
int ring_buff_struct_size();

/**
 * Use this function as the consumer for this ring buffer. read_buff should point
 * to the beginning of the space allocated for the buffer.
 */
void ring_buff_set_read_buff(ring_buff_handle_t handle, uint8_t* read_buff);

/**
 * Use this function as the producer for this ring buffer. write_buff should point
 * to the beginning of the space allocated for the buffer.
 */
void ring_buff_set_write_buff(ring_buff_handle_t handle, uint8_t* write_buff);

/**
 * Creates ring buffer with attributes passed as argument. Handle returned must be saved
 * by ring buffer client, so that it can be used for operations on ring buffer.
 * @param attr Ring buffer attribute object.
 * @param handle Pointer to the handle. This argument must not be NULL. If function returns
 * without error, this pointer will point to ring buffer handle that is required for other
 * ring buffer operations.
 * @return RING_BUFF_ERR_OK if everything was OK, or error if there was some problem.
 */
ring_buff_err_t ring_buff_create(ring_buff_attr_t *attr, ring_buff_handle_t *handle);
/**
 * Ring buffer destructor function. This function must be called, so that all resources
 * allocated on ring buffer construction are freed.
 * @param handle Ring buffer handle.
 * @return RING_BUFF_ERR_OK if everything was OK, or error if there was some problem.
 */
ring_buff_err_t ring_buff_destroy(ring_buff_handle_t handle);
/**
 * Reserves chunk of memory from ring buffer. Chunk allocated is continuous memory that
 * is ready to be written with data.
 * @param handle Ring buffer handle.
 * @param buff Pointer to the reserved data. This is output value.
 * @param size Requested buffer size in bytes.
 * @return RING_BUFF_ERR_OK if everything was OK, or error if there was some problem.
 */
ring_buff_err_t ring_buff_reserve(ring_buff_handle_t handle, void **buff, uint32_t size);
/**
 * Commits written data. After this function is called, data is available for reading.
 * @param handle Ring buffer handle.
 * @param buff Pointer to data that should be committed. This pointer is retrieved with "ring_buff_reserve".
 * @param size Committed data size in bytes.
 * @return RING_BUFF_ERR_OK if everything was OK, or error if there was some problem.
 */
ring_buff_err_t ring_buff_commit(ring_buff_handle_t handle, void *buff, uint32_t size);
/**
 * Frees ring buffer chunk, so that it can be used for writing.
 * @param handle Ring buffer handle.
 * @param buff Pointer to data that should be freed.
 * @param size Chunk length that should be freed.
 * @return RING_BUFF_ERR_OK if everything was OK, or error if there was some problem.
 */
ring_buff_err_t ring_buff_free(ring_buff_handle_t handle, void *buff, uint32_t size);
/**
 * Reads out requested size of data. Data should be additionally freed with "ring_buff_free".
 * Read mechanism should NOT be used together with the notify mechanism.
 * @param handle Ring buffer handle.
 * @param buff Output argument that will contain pointer with read data.
 * @param size Data size that should be read.
 * @return RING_BUFF_ERR_OK if everything was OK, or error if there was some problem.
 */
ring_buff_err_t ring_buff_read(ring_buff_handle_t handle, void **buff, uint32_t size, uint32_t *read);
/**
 * Convenience function that prints out 'human readable' ring buffer error description.
 * @param err Error.
 */
void ring_buff_print_err(ring_buff_err_t err);
/**
 * This fuction writes a message into the buffer which can later be read without prior knowledge
 * of the message length.
 * @param handle Ring buffer handle.
 * @param data The address of the message payload to be written.
 * @param size The Size of the message payload.
 * @return RING_BUFF_ERR_OK if everything was OK, RING_BUFF_ERR_NO_MEM, if the buffer was full, or error if there was some problem.
 */
ring_buff_err_t ring_buff_write_msg(ring_buff_handle_t handle, void* data, uint32_t size);
/**
 * This function reads a previously written message.
 * @param handle Ring buffer handle.
 * @param data Output argument that will point to the message payload.
 * @param messageSize The size of the message payload.
 * @return RING_BUFF_ERR_OK if everything was OK, RING_BUFF_ERR_NO_MEM, if the buffer was empty, or error if there was some problem.
 */
ring_buff_err_t ring_buff_read_msg(ring_buff_handle_t handle, void** data, uint32_t* messageSize);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* RING_BUFF_H_ */

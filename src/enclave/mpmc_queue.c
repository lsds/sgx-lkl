/** Lock-free Multiple-Producer Multiple-consumer (MPMC) queue.
 *
 * Based on Dmitry Vyukov#s Bounded MPMC queue:
 *   http://www.1024cores.net/home/lock-free-algorithms/queues/bounded-mpmc-queue
 *
 *
 * @author Steffen Vogel <post@steffenvogel.de>
 * @copyright 2016 Steffen Vogel
 * @copyright 2017 Imperial College London
 * @license BSD 2-Clause License
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modiffication, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "enclave/mpmc_queue.h"
#include "enclave/enclave_util.h"
#include "openenclave/corelibc/oemalloc.h"

static void pause(void);
static void pause()
{
    __asm__ __volatile__("pause" : : : "memory");
}

/* user is responsible for freeing the queue buffer, but it's tied to the
   runtime of the enclave, so is not necessary in practice */
int newmpmcq(struct mpmcq* q, size_t buffer_size, void* buffer)
{
    size_t i;
    buffer_size /= sizeof(*q->buffer);
    q->buffer =
        buffer != 0 ? buffer : oe_calloc(sizeof(struct cell_t), buffer_size);
    q->buffer_mask = (buffer_size - 1);
    SGXLKL_ASSERT(
        (buffer_size >= 2) && ((buffer_size & (buffer_size - 1)) == 0));
    for (i = 0; i != buffer_size; i += 1)
    {
        __atomic_store_n(&q->buffer[i].seq, i, __ATOMIC_RELAXED);
    }
    __atomic_store_n(&q->enqueue_pos, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&q->dequeue_pos, 0, __ATOMIC_RELAXED);
    return 1;
}

int mpmc_enqueue(volatile struct mpmcq* q, void* data)
{
    struct cell_t* cell;
    size_t seq, exp;
    intptr_t dif;
    size_t pos = __atomic_load_n(&q->enqueue_pos, __ATOMIC_RELAXED);
    for (;;)
    {
        cell = &q->buffer[pos & q->buffer_mask];
        seq = __atomic_load_n(&cell->seq, __ATOMIC_ACQUIRE);
        dif = (intptr_t)seq - (intptr_t)pos;
        if (dif == 0)
        {
            exp = pos;
            if (__atomic_compare_exchange_n(
                    &q->enqueue_pos,
                    &exp,
                    pos + 1,
                    1,
                    __ATOMIC_RELAXED,
                    __ATOMIC_RELAXED))
            {
                break;
            }
        }
        else if (dif < 0)
        {
            return 0;
        }
        else
        {
            pos = __atomic_load_n(&q->enqueue_pos, __ATOMIC_RELAXED);
            pause();
        }
    }
    cell->data = data;
    __atomic_store_n(&cell->seq, pos + 1, __ATOMIC_RELEASE);
    return 1;
}

int mpmc_dequeue(volatile struct mpmcq* q, void** data)
{
    struct cell_t* cell;
    size_t seq;
    intptr_t dif;
    size_t pos = __atomic_load_n(&q->dequeue_pos, __ATOMIC_RELAXED);
    for (;;)
    {
        cell = &q->buffer[pos & q->buffer_mask];
        seq = __atomic_load_n(&cell->seq, __ATOMIC_ACQUIRE);
        dif = (intptr_t)seq - (intptr_t)(pos + 1);
        if (dif == 0)
        {
            size_t exp = pos;
            if (__atomic_compare_exchange_n(
                    &q->dequeue_pos,
                    &exp,
                    pos + 1,
                    1,
                    __ATOMIC_RELAXED,
                    __ATOMIC_RELAXED))
            {
                break;
            }
        }
        else if (dif < 0)
        {
            return 0;
        }
        else
        {
            pos = __atomic_load_n(&q->dequeue_pos, __ATOMIC_RELAXED);
            pause();
        }
    }
    *data = cell->data;
    __atomic_store_n(&cell->seq, pos + q->buffer_mask + 1, __ATOMIC_RELEASE);
    return 1;
}

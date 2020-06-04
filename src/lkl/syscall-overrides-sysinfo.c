#include "enclave/enclave_mem.h"

long syscall_sysinfo_override(struct sysinfo* info)
{
    size_t total, free;
    enclave_mem_info(&total, &free);
    info->totalram = total;
    info->freeram = free;
    info->totalswap = 0;
    info->freeswap = 0;
    info->procs = 1;     // TODO: report # of ethreads
    info->totalhigh = 0;
    info->freehigh = 0;
    info->mem_unit = 1;

    return 0;
}
#include <sys/sysinfo.h>

#include "enclave/enclave_mem.h"
#include "enclave/enclave_state.h"

long syscall_sysinfo_override(struct sysinfo* info)
{
    const sgxlkl_enclave_config_t* econf = sgxlkl_enclave_state.config;

    size_t total, free;
    enclave_mem_info(&total, &free);
    info->totalram = total;
    info->freeram = free;
    info->totalswap = 0;
    info->freeswap = 0;
    info->procs = econf->ethreads;
    info->totalhigh = 0;
    info->freehigh = 0;
    info->mem_unit = 1;

    return 0;
}

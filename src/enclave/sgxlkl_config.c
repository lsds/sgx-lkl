#include <string.h>

#include <lkl/lkl_util.h>
#include <shared/sgxlkl_config.h>
#include "openenclave/corelibc/oemalloc.h"

// Duplicate a string
static int strdupz(char** to, const char* from)
{
    if (!to)
        return 1;
    else if (!from)
    {
        *to = NULL;
        return 0;
    }
    else
    {
        size_t l = strlen(from);
        *to = oe_malloc(l + 1);
        if (!*to)
        {
            *to = NULL;
            return 1;
        }
        else
            memcpy(*to, from, l + 1);
    }
    return 0;
}

#define MALLOC_CHECKED(M, S) \
    M = oe_malloc(S);        \
    if (!M)                  \
        return 1;

#define STRDUPZ_CHECKED(T, F)                       \
    if ((r = strdupz((char**)&(T), (char*)F)) != 0) \
        return r;

// Copy an sgxlkl_config_t (mainly used to create a copy enclave memory as
// opposed to host memory)
int sgxlkl_copy_config(const sgxlkl_config_t* from, sgxlkl_config_t** to)
{
    int r = 1;
    if (!from || !to)
        return 1;

    MALLOC_CHECKED(*to, sizeof(sgxlkl_config_t));
    memset(*to, 0, sizeof(sgxlkl_config_t));
    sgxlkl_config_t* cfg = *to;

    // Catch modifications to sgxlkl_config_t early.
    _Static_assert(
        sizeof(sgxlkl_config_t) == 472, "sgxlkl_config_t size has changed");

    cfg->max_user_threads = from->max_user_threads;
    cfg->stacksize = from->stacksize;
    cfg->num_disks = from->num_disks;
    if (from->disks)
    {
        MALLOC_CHECKED(
            cfg->disks, sizeof(enclave_disk_config_t) * cfg->num_disks);
        memset(cfg->disks, 0, sizeof(enclave_disk_config_t) * cfg->num_disks);
    }
    for (size_t i = 0; i < cfg->num_disks; i++)
    {
        enclave_disk_config_t* dc = &(cfg->disks[i]);
        const enclave_disk_config_t* hdc = &from->disks[i];
        dc->fd = hdc->fd;
        dc->capacity = hdc->capacity;
        STRDUPZ_CHECKED(dc->mmap, hdc->mmap);
        dc->create = hdc->create;
        dc->size = hdc->size;
        dc->enc = hdc->enc;
        memcpy(dc->mnt, hdc->mnt, sizeof(dc->mnt));
        dc->ro = hdc->ro;
        if (hdc->key && hdc->key_len > 0)
        {
            MALLOC_CHECKED(dc->key, hdc->key_len);
            memcpy(dc->key, hdc->key, hdc->key_len);
        }
        else
        {
            dc->key = NULL;
            dc->key_len = 0;
        }
        dc->key_len = hdc->key_len;
        STRDUPZ_CHECKED(dc->roothash, hdc->roothash)
        dc->roothash_offset = hdc->roothash_offset;
        dc->mounted = hdc->mounted;

        dc->virtio_blk_dev_mem =
            hdc->virtio_blk_dev_mem; // This should move to shared memory
    }
    cfg->mmap_files = from->mmap_files;
    cfg->net_fd = from->net_fd;
    cfg->oe_heap_pagecount = from->oe_heap_pagecount;
    cfg->net_ip4 = from->net_ip4;
    cfg->net_gw4 = from->net_gw4;
    cfg->net_mask4 = from->net_mask4;

    strncpy(cfg->hostname, from->hostname, sizeof(cfg->hostname));
    cfg->hostnet = from->hostnet;
    cfg->tap_offload = from->tap_offload;
    cfg->tap_mtu = from->tap_mtu;
    cfg->wg.ip = from->wg.ip;
    cfg->wg.listen_port = from->wg.listen_port;
    STRDUPZ_CHECKED(cfg->wg.key, from->wg.key);
    cfg->wg.num_peers = from->wg.num_peers;
    if (from->wg.peers)
    {
        MALLOC_CHECKED(
            cfg->wg.peers,
            sizeof(enclave_wg_peer_config_t) * cfg->wg.num_peers);
        memset(
            cfg->wg.peers,
            0,
            sizeof(enclave_wg_peer_config_t) * cfg->wg.num_peers);
        for (size_t i = 0; i < cfg->wg.num_peers; i++)
        {
            STRDUPZ_CHECKED(cfg->wg.peers[i].key, from->wg.peers[i].key);
            STRDUPZ_CHECKED(
                cfg->wg.peers[i].allowed_ips, from->wg.peers[i].allowed_ips);
            STRDUPZ_CHECKED(
                cfg->wg.peers[i].endpoint, from->wg.peers[i].endpoint);
        }
    }
    size_t argv_sz = from->argc + 1;
    while (*(from->argv + argv_sz++) != NULL)
    {
        // Skip (find size of envp)
    };
    MALLOC_CHECKED(cfg->argv, sizeof(char*) * argv_sz + 1);
    for (size_t i = 0; i < argv_sz; i++)
        STRDUPZ_CHECKED(cfg->argv[i], from->argv[i]);
    cfg->argv[argv_sz] = NULL;
    cfg->argc = from->argc;
    cfg->auxv = NULL; // Necessary?
    STRDUPZ_CHECKED(cfg->cwd, from->cwd);

    cfg->exit_status = from->exit_status;

    cfg->espins = from->espins;
    cfg->esleep = from->esleep;
    cfg->sysconf_nproc_conf = from->sysconf_nproc_conf;
    cfg->sysconf_nproc_onln = from->sysconf_nproc_onln;
    memcpy(cfg->clock_res, from->clock_res, sizeof(cfg->clock_res));
    cfg->mode = from->mode;
    cfg->fsgsbase = from->fsgsbase;
    cfg->verbose = from->verbose;

    cfg->kernel_verbose = from->kernel_verbose;
    STRDUPZ_CHECKED(cfg->kernel_cmd, from->kernel_cmd);
    STRDUPZ_CHECKED(cfg->sysctl, from->sysctl);

    STRDUPZ_CHECKED(cfg->app_config_str, from->app_config_str);

    memcpy(
        &cfg->shared_memory, &from->shared_memory, sizeof(cfg->shared_memory));

    return 0;
}

// Free resources allocated during sgxlkl_copy_config.
int sgxlkl_free_config(sgxlkl_config_t* config)
{
    if (config)
    {
        for (size_t i = 0; i < config->num_disks; i++)
        {
            oe_free(config->disks[i].mmap);
            oe_free(config->disks[i].key);
            oe_free(config->disks[i].roothash);
        }
        oe_free(config->disks);

        for (size_t i = 0; i < config->argc; i++)
            oe_free(config->argv[i]);
        char** envp = &config->argv[config->argc + 1];
        while (*envp != NULL)
            oe_free(*envp++);
        oe_free(config->argv);

        oe_free(config->cwd);
        oe_free(config->wg.key);
        for (int i = 0; i < config->wg.num_peers; i++)
        {
            oe_free(config->wg.peers[i].key);
            oe_free(config->wg.peers[i].allowed_ips);
            oe_free(config->wg.peers[i].endpoint);
        }
        oe_free(config->wg.peers);
        oe_free(config->kernel_cmd);
        oe_free(config->sysctl);

        oe_free(config->app_config_str);

        oe_free(config);
    }

    return 0;
}

/*
 * Copyright 2016, 2017, 2018 Imperial College London (under GNU General Public License v3)
 * Copyright 2016, 2017 TU Dresden (under SCONE source code license)
 */

#define _LARGEFILE64_SOURCE     /* See feature_test_macros(7) */
#include <sys/types.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <limits.h>
#include "libsgx.h"
#include "elf.h"
#include <polarssl/sha256.h>
#include <polarssl/rsa.h>
#include <errno.h>
#include <setjmp.h>
#include "isgx_user.h"

#define STRING_EADD    0x0000000044444145
#define STRING_ECREATE 0x0045544145524345
#define STRING_EEXTEND 0x00444E4554584545

#define BASE_ADDR_UNDEFINED -1

//#ifdef DEBUG
//#define D
//#else
#define D for(;0;)
//#endif

void cmd_sign(sigstruct_t* sigstruct, char *key);
static uintptr_t get_symbol_address(char* elf, char* name);
static uintptr_t get_section_address(char* p, char* name);

typedef struct {
    uint64_t zero;
    void*    hash;
    void*    signer;
    void*    attributes;
    void*    token;
} gettoken_t;

/*
 * if changed, the same typedef must be updated accordingly in
 * sgx-lkl/src/include/enclave_config.h
 *
 * TODO: Don't define enclave_parms_t twice
 */
typedef struct {
    uint64_t base;
    uint64_t heap;
    uint64_t stack;
    uint64_t ossa;
    uint64_t tcsn;
    uint64_t heap_size;
    uint64_t exit_addr;
    uint64_t ursp;
    uint64_t urbp;
    uint64_t stack_size;
    uint64_t enclave_size;
    uint64_t tid;
    uint64_t tls_vaddr;
    uint64_t tls_filesz;
    uint64_t tls_memsz;
    uint64_t thread_state;
    uint64_t eh_tcs_addr;
    uint64_t eh_exit_addr;
    uint64_t eh_ursp;
    uint64_t eh_urbp;
    uint64_t eh_handling;
    jmp_buf  regs;
} enclave_parms_t;

static uintptr_t ubase = BASE_ADDR_UNDEFINED;
static int sgxfd = 0;
static size_t esize = 0;
static volatile size_t heap_size = 0;
static sha256_context ctx;

typedef struct {
    int   busy;
    void* addr;
} enclave_thread_t;

static enclave_thread_t* threads;
static int tcs_max  = 0;

#if DEBUG
unsigned long hw_exceptions = 0;
#endif /* DEBUG */

typedef int (*process_func_t)(uint64_t, uint64_t, uint64_t, const void* p);

void* get_tcs_addr(int id) {
    if (id >= tcs_max) return 0;
    return threads[id].addr;
}
int get_free_tcs_id() {
    for (int i = 0; i < tcs_max; i++)
        if (threads[i].busy == 0) {
            return i;
        }

    return -1;
}

int get_tcs_num() {
    return tcs_max;
}

static void exception() {
#if DEBUG
// Commented out for now as any additional computation in this function seems
// to lead to deadlocks while running under gdb in HW mode and potentially
// under other circumstances as well.
//    __sync_fetch_and_add(&hw_exceptions, 1);
#endif /* DEBUG */
    asm(
            ".byte 0x0f \n"
            ".byte 0x01 \n"
            ".byte 0xd7 \n"
            : : :);
}

char _binary_libsgx_le_bin_start;
int  _binary_libsgx_le_bin_size;

static char* get_init_token(sigstruct_t* sig) {
    init_sgx();
    char* p = &_binary_libsgx_le_bin_start;
    uint64_t size = (uint64_t)&_binary_libsgx_le_bin_size;
    size_t offset = 1808;
    uintptr_t u = ecreate(0x100, 1, p, ECREATE_NO_FIXED_ADDR);
    uintptr_t tcsaddr = 0;
    while (offset < size) {
        uint64_t pageoffset = *(int*)(p+offset);
        offset += 4;
        int prot = *(int*)(p+offset);
        offset += 4;
        if (add_page(u, pageoffset, prot, p+offset)) {
            D fprintf(stderr, "Add page failed (base: %p, offset: %lu) \n", (void*)u, pageoffset);
            D perror("error");
            return 0;
        }
        if ((prot & PAGE_TCS) == PAGE_TCS) tcsaddr = u + pageoffset;

        offset += PAGE_SIZE;
    }

    int ret = einit(u, p, 0);
    if (ret != 0) {
        destroy_enclave(u);
        return 0;
    }
    uint64_t rdi = 0xffffffff;
    uint64_t rsi_val = 0x0e9fffff;
    uint64_t rsi = (uint64_t)&rsi_val;
    eenter(tcsaddr, &rdi, &rsi);
    gettoken_t req;
    memset(&req, 0, sizeof(gettoken_t));
    req.hash   = sig->enclaveHash;
    req.signer = malloc(32);
    req.token  = malloc(304);
    req.attributes = &sig->attributes;

    sha256(sig->modulus, 384, req.signer, 0);
    rdi = 0;
    rsi = (uint64_t)&req;
    eenter(tcsaddr, &rdi, &rsi);

    destroy_enclave(u);
    free(req.signer);
    return req.token;
}

static void update_init_token(char* enclave, einittoken_t* token) {
    uintptr_t token_section = get_section_address((char*)enclave, ".note.token");
    memcpy((void*)token_section, token, sizeof(einittoken_t));
}

int einit(uintptr_t base, void* sigstruct, void* einittoken) {
    int res = 0;
    void* new_token = 0;
    sigstruct_t* sig = (sigstruct_t*)sigstruct;

    einittoken_t token = {0};
    if (sig->vendor == 0x8086) {
        einittoken = &token;
    }

    struct sgx_enclave_init parm = {0};
    parm.addr = base;
    parm.sigstruct = (__u64)sigstruct;
    parm.einittoken = (__u64)einittoken;
    /* attempt to initialize the enclave with the provided launch token
     * if we don't succeed, get a new token */
    res = ioctl(sgxfd, SGX_IOC_ENCLAVE_INIT, &parm);
    if (res == 0) return res;
    printf("EINIT ERROR: %d\n", res);
    if (res == ERR_SGX_INVALID_EINIT_TOKEN || res == ERR_SGX_INVALID_CPUSVN || res == ERR_SGX_INVALID_ISVSVN) {
        new_token = get_init_token(sigstruct);
        /* now we patch the executable with the new launch token */
        update_init_token(0, new_token);
        parm.einittoken = (__u64)new_token;
    }

    res = ioctl(sgxfd, SGX_IOC_ENCLAVE_INIT, &parm);
    return res;
}

int add_page(uint64_t base, uint64_t offset, uint64_t prot, const void* p) {
    int ret = 0;
    uint64_t laddr = base + offset;
    struct sgx_enclave_add_page parm = {0};
    parm.addr = laddr;
    parm.src = (uint64_t)p;
    parm.mrmask = 0xffff;

    struct isgx_secinfo secinfo = {0};
    if ((prot & PAGE_TCS) == PAGE_TCS) {
        secinfo.flags |= SGX_SECINFO_TCS;
    }
    else {
        secinfo.flags |= SGX_SECINFO_REG;
        if ((prot & PAGE_READ)  == PAGE_READ)  secinfo.flags |= SGX_SECINFO_R;
        if ((prot & PAGE_WRITE) == PAGE_WRITE) secinfo.flags |= SGX_SECINFO_W;
        if ((prot & PAGE_EXEC)  == PAGE_EXEC)  secinfo.flags |= SGX_SECINFO_X;
    }
    if ((prot & PAGE_NOEXTEND) == PAGE_NOEXTEND) parm.mrmask = 0;
    parm.secinfo = (__u64)&secinfo;
    ret = ioctl(sgxfd, SGX_IOC_ENCLAVE_ADD_PAGE, &parm);
    return ret;
}

static size_t get_next_power2(size_t size) {
    if (__builtin_popcountl(size) == 1)
        return size;

    size_t power = 2;
    while (size >>= 1) power <<= 1;
    size = power;
    return size;
}

uint64_t ecreate(size_t npages, int ssaSize, const void* sigstruct, void* baseaddr) {
    void* base;
    sigstruct_t* sig = (sigstruct_t*)sigstruct;
    secs_t secs;
    memset(&secs, 0, sizeof(secs_t));
    secs.ssaFrameSize = ssaSize;
    secs.size         = get_next_power2(npages * PAGE_SIZE);

    /* Allow enclave to be mapped at address 0x0. We need this non-PIE Linux binaries by default expect their
       .text segments to be mapped at address 0x40000. SGX requires the base address to be naturally aligned
       to the enclave size. Therefore, we cannot use 0x400000 as base address in cases where the enclave is
       larger than 4 MB (0x400000 bytes). Instead, we allow mappings to address 0x0 to adhere to the alignment
       requirement.
       */
    if(baseaddr == ECREATE_NO_FIXED_ADDR) {
        base = mmap(0x0, secs.size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED, sgxfd, 0);
    } else {
        base = mmap(baseaddr, secs.size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED | MAP_FIXED, sgxfd, 0);
    }

    if (base == MAP_FAILED) {
        fprintf(stderr, "Could not allocate memory for enclave.\n");
        if(baseaddr == 0x0) {
            fprintf(stderr, "This might have been caused by the host not permitting allocations at address 0. Run 'sysctl -w vm.mmap_min_addr=\"0\"' to fix this.\n");
        }
        exit(-1);
    }
    secs.baseAddr = (uint64_t)base;

    memcpy(&secs.attributes, &sig->attributes, sizeof(attributes_t));
    memcpy(&secs.miscselect, &sig->miscselect, 4);
    memcpy(&secs.isvprodID,  &sig->isvProdID, 2);
    memcpy(&secs.isvsvn,     &sig->isvSvn, 2);
    memcpy(secs.mrEnclave,   sig->enclaveHash, 32);
    unsigned char mrSigner[32];
    sha256(sig->modulus, 384, mrSigner, 0);
    memcpy(secs.mrSigner, mrSigner, 32);
    secs.attributes.xfrm = 0x7;

    struct sgx_enclave_create parms;
    parms.src = (__u64)&secs;
    int ret = ioctl(sgxfd, SGX_IOC_ENCLAVE_CREATE, &parms);
    if (ret) {
        perror("Error while creating enclave");
        exit(EXIT_FAILURE);
    }
    esize = secs.size;
    return secs.baseAddr;
}

int init_sgx() {
    if (sgxfd != 0) return 0;
    if ((sgxfd = open("/dev/isgx", O_RDWR)) < 0) {
        perror("error opening sgx device");
        exit(EXIT_FAILURE);
    }
    return 0;
}

static int
measure_page(uint64_t base, uint64_t offset, uint64_t prot, const void* page) {
    secinfo_t secinfo={};
    memset(&secinfo, 0, sizeof(secinfo));

    if ((prot & PAGE_TCS) == PAGE_TCS) {
        secinfo.flags.page_type = PT_TCS;
        secinfo.flags.r = 0;
        secinfo.flags.w = 0;
        secinfo.flags.x = 0;
    }
    else {
        secinfo.flags.page_type = PT_REG;
        secinfo.flags.r = ((prot & PAGE_READ)  == PAGE_READ)  ? 1 : 0;
        secinfo.flags.w = ((prot & PAGE_WRITE) == PAGE_WRITE) ? 1 : 0;
        secinfo.flags.x = ((prot & PAGE_EXEC)  == PAGE_EXEC)  ? 1 : 0;
    }

    uint64_t tmp_update_field[8];
    memset(&tmp_update_field[0], 0, 64);
    tmp_update_field[0] = STRING_EADD;
    tmp_update_field[1] = offset;
    memcpy(&tmp_update_field[2], &secinfo, 48);
    sha256_update(&ctx, (unsigned char *)tmp_update_field, 64);

    if ((prot & PAGE_NOEXTEND) == PAGE_NOEXTEND)
        return 0;

    for (int i = 0; i < 16; i++) {
        memset(&tmp_update_field[0], 0, 64);
        tmp_update_field[0] = STRING_EEXTEND;
        tmp_update_field[1] = offset + 256*i;
        sha256_update(&ctx, (unsigned char *)tmp_update_field, 64);

        unsigned char *cast_page = (unsigned char *)page + i * 256;
        sha256_update(&ctx, (unsigned char *)(&cast_page[0]),   64);
        sha256_update(&ctx, (unsigned char *)(&cast_page[64]),  64);
        sha256_update(&ctx, (unsigned char *)(&cast_page[128]), 64);
        sha256_update(&ctx, (unsigned char *)(&cast_page[192]), 64);
    }

    return 0;
}

static uintptr_t get_section_address(char* p, char* name) {
    Elf_Ehdr *ehdr = (Elf_Ehdr*)p;
    Elf_Shdr *shdr = (Elf_Shdr*)(p + ehdr->e_shoff);
    int shnum = ehdr->e_shnum;

    Elf_Shdr *sh_strtab = &shdr[ehdr->e_shstrndx];
    const char *const sh_strtab_p = p + sh_strtab->sh_offset;

    uintptr_t offset = 0;
    for (int i = 0; i < shnum; ++i) {
        if (strcmp(sh_strtab_p + shdr[i].sh_name, name) == 0) {
            offset = (uintptr_t)(shdr[i].sh_offset + p);
            return offset;
        }
    }

    return 0;
}

static int get_tls_info(char* elf, size_t* vaddr, size_t* fsize, size_t* vsize) {
    Elf_Ehdr *ehdr = (Elf_Ehdr*)elf;
    Elf_Phdr *phdr = (Elf_Phdr*)(ehdr->e_phoff + elf);

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_TLS) {
            *vaddr = phdr[i].p_vaddr;
            *vsize = phdr[i].p_memsz;
            *fsize = phdr[i].p_filesz;
        }
    }

    return 0;
}

void eresume(uint64_t tcs_id)  {
    asm volatile(
            ".byte 0x0f \n"
            ".byte 0x01 \n"
            ".byte 0xd7 \n"
            :
            : "a"(0x3), "b"((uint64_t)threads[tcs_id].addr), "c"(&exception)
            :
            );
}

/*
 * IN:  rdi - call id, rsi - call arg
 * OUT: rdi - exit reason, rsi - exit code
 */
__attribute__((noinline))
    void eenter(uint64_t tcs, uint64_t* rdi, uint64_t* rsi)  {
        asm volatile(
                ".byte 0x0f \n"
                ".byte 0x01 \n"
                ".byte 0xd7 \n"
                : "+D"(*rdi), "+S"(*rsi)
                : "a"(0x2), "b"(tcs), "c"(&exception)
                : "%rdx", "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15", "memory"
                );
    }

void enter_enclave(int tcs_id, uint64_t call_id, void* arg, uint64_t* ret) {
    if (tcs_id < 0 || tcs_id > tcs_max) {
        fprintf(stderr, "Incorrect TCS id %d\n", tcs_id);
        exit(EXIT_FAILURE);
    }
    /*
       if (threads[tcs_id].busy) {
       fprintf(stderr, "Attempted to reuse TCS \n");
       exit(EXIT_FAILURE);
       }
       */
    threads[tcs_id].busy = 1;
    ret[0] = call_id;
    ret[1] = (uint64_t)arg;

    eenter((uint64_t)threads[tcs_id].addr, &ret[0], &ret[1]);
    threads[tcs_id].busy = 0;
}

static int get_loadable_size(char* elf) {
    Elf_Ehdr *ehdr = (Elf_Ehdr*)elf;
    Elf_Phdr *phdr = (Elf_Phdr*)(ehdr->e_phoff + elf);

    int max_addr = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD && phdr[i].p_type != PT_PHDR)
            continue;

        int top = phdr[i].p_vaddr + phdr[i].p_memsz;
        if (top > max_addr)
            max_addr = top;
    }

    max_addr += PAGE_SIZE-1;
    max_addr &= -PAGE_SIZE;

    return max_addr / PAGE_SIZE;
}

static uintptr_t get_symbol_address(char* elf, char* name) {
    Elf_Ehdr *ehdr = (Elf_Ehdr*)elf;
    Elf_Shdr *shdr = (Elf_Shdr*)(elf + ehdr->e_shoff);
    int shnum = ehdr->e_shnum;

    int addr = 0;
    int num  = 0;
    int entsize  = 0;
    char* strtab = 0;
    char* dynsym = 0;
    for (int i = 0; i < shnum; ++i) {
        if (shdr[i].sh_type == SHT_STRTAB) {
            strtab = shdr[i].sh_offset + elf;
        }
        if (shdr[i].sh_type == SHT_DYNSYM) {
            dynsym = shdr[i].sh_offset + elf;
            num = shdr[i].sh_size / shdr[i].sh_entsize;
            entsize = shdr[i].sh_entsize;
        }

        if (strtab != 0 && dynsym != 0)
            break;
    }

    for (int s = 0; s < num; s++) {
        Elf_Sym *sym = (Elf_Sym*)(dynsym + entsize * s);
        if (strcmp(sym->st_name + strtab, name) == 0) {
            addr = sym->st_value;
            return addr;
        }
    }

    fprintf(stderr, "cannot find symbol %s\n", name);
    exit(EXIT_FAILURE);
}

static size_t get_enclave_size(size_t heap, size_t stack, int tcsp, int ssaFrameSize, int nssa, int code, int tls) {
    return heap + tcsp * (1 + stack + ssaFrameSize * nssa + tls) + code;
}

static void process_pages(char* p, uint64_t ubase, size_t heap, size_t stack, int tcsp, int nssa, process_func_t process_page) {
    size_t pageoffset = 0;
    int prot = 0;
    char page[PAGE_SIZE] = {};
    char* srcpge;

    prot = PAGE_READ|PAGE_WRITE|PAGE_EXEC|PAGE_NOEXTEND;
    uint64_t heap_offset = pageoffset;
    D printf("heap: %lx, size: %lu\n", pageoffset, heap);
    for (size_t i = 0; i < heap; i++) {
        process_page(ubase, pageoffset, prot, page);
        pageoffset += PAGE_SIZE;
    }

    Elf_Ehdr *ehdr = (Elf_Ehdr*)p;
    Elf_Phdr *phdr = (Elf_Phdr*)(ehdr->e_phoff + p);

    uint64_t libbase = pageoffset;
    prot = 0;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD)
            continue;

        /* segment might start from not a page-aligned address */
        pageoffset = phdr[i].p_vaddr & 0xfffffffffffff000;
        int npages = (phdr[i].p_vaddr - pageoffset + phdr[i].p_filesz) / PAGE_SIZE;

        uint64_t segoffset = (uint64_t)(phdr[i].p_offset + p);
        uint64_t file_read = 0;
        uint64_t mem_read  = 0;

        if ((phdr[i].p_flags & 0x4)  != 0)  prot |= PAGE_READ;
        if ((phdr[i].p_flags & 0x2)  != 0)  prot |= PAGE_WRITE;
        if ((phdr[i].p_flags & 0x1)  != 0)  prot |= PAGE_EXEC;

        for (int k = 0; k < npages; k++) {
            /* check if segment starts not on a page boundary */
            /* note that this assumes that two loadable segments cannot share a page */
            if (k == 0 && pageoffset != phdr[i].p_vaddr) {
                int diff = phdr[i].p_vaddr - pageoffset;
                memset(page, 0, PAGE_SIZE);
                memcpy(page + diff, (void*)segoffset, PAGE_SIZE - diff);

                srcpge = page;
                segoffset += PAGE_SIZE - diff;
                file_read += PAGE_SIZE - diff;
            } else {
                srcpge = (void*)segoffset;
                segoffset += PAGE_SIZE;
                file_read += PAGE_SIZE;
            }
            process_page(ubase, libbase + pageoffset, prot, srcpge);
            pageoffset += PAGE_SIZE;
        }

        if ((phdr[i].p_filesz - file_read) > 0) {
            memset(page, 0, PAGE_SIZE);
            int diff = 0;
            if (npages == 0 && pageoffset != phdr[i].p_vaddr) {
                diff = phdr[i].p_vaddr - pageoffset;
            }

            srcpge = page;
            memcpy(page + diff, (void*)segoffset, phdr[i].p_filesz - file_read);
            process_page(ubase, libbase + pageoffset, prot, srcpge);

            pageoffset += PAGE_SIZE;
            npages++;
            /* we should be done reading from file by now */
            mem_read += PAGE_SIZE - (phdr[i].p_filesz - file_read);
            file_read = phdr[i].p_filesz;
        }

        memset(page, 0, PAGE_SIZE);

        int rest = phdr[i].p_memsz - file_read - mem_read;
        if (rest > 0) {
            for (int n = 0; n < rest / PAGE_SIZE; n++) {
                process_page(ubase, libbase + pageoffset, prot, page);
                pageoffset += PAGE_SIZE;
            }
        }

        if (rest % PAGE_SIZE > 0) {
            process_page(ubase, libbase + pageoffset, prot, page);
            pageoffset += PAGE_SIZE;
        }
    }

    uint64_t enclave_size = get_enclave_size(heap, stack, tcsp, 1, nssa, pageoffset / PAGE_SIZE, 1);

    pageoffset = libbase + pageoffset;

    prot = PAGE_READ|PAGE_WRITE;
    memset(page, 0, PAGE_SIZE);

    threads = malloc(sizeof(enclave_thread_t) * tcsp);
    tcs_max  = tcsp;

    uint64_t tls_vaddr = 0, tls_filesz = 0, tls_memsz = 0;
    get_tls_info(p, &tls_vaddr, &tls_filesz, &tls_memsz);

    uint64_t* tls_start = (uint64_t*)get_section_address(p, ".tdata");
    uint64_t* start = 0;
    uint64_t enclave_parms_offset = 0;
    for (int i = 0; i < tls_filesz / 8; i++) {
        if (tls_start[i] == 0xBAADF00DDEADBABE) {
            start = &tls_start[i];
            enclave_parms_offset = 8*i;
            break;
        }
    }

    if (start == 0) {
        fprintf(stderr, "could not find enclave parms in .tdata \n");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < tcsp; i++) {
        D printf("stack(%d): %lx\n", i, pageoffset);
        uint64_t stack_start = pageoffset;
        for (int i = 0; i < stack; i++) {
            process_page(ubase, pageoffset, PAGE_READ|PAGE_WRITE, page);
            pageoffset += PAGE_SIZE;
        }

        uint64_t ossa = pageoffset;
        D printf("ossa: %lx\n", ossa);
        for (int i = 0; i < nssa; i++) {
            process_page(ubase, pageoffset, prot, page);
            pageoffset += PAGE_SIZE;
        }

        //tls
        uint64_t tls = pageoffset;
        uint64_t* ptr = (uint64_t*)page;
        size_t tls_offset = 48;
        ptr[0] = tls + tls_offset + sizeof(enclave_parms_t); //pointer to the actual tls
        ptr[1] = pageoffset + PAGE_SIZE; //offset of tls from the base
        ptr[2] = tls + tls_offset + enclave_parms_offset; //pointer(offset) to enclave parms

        //memcpy(page + 24, tls_start, tls_size);
        enclave_parms_t* enc = (enclave_parms_t*)(page + tls_offset + enclave_parms_offset);
        enc->base  = 0;
        enc->heap  = heap_offset;
        enc->stack = stack_start + stack * PAGE_SIZE - 8;
        enc->ossa  = ossa;
        enc->tcsn  = tcsp;
        enc->tid   = pageoffset;
        enc->heap_size    = heap * PAGE_SIZE;
        enc->enclave_size = enclave_size;
        enc->tls_vaddr  = tls_vaddr;
        enc->tls_filesz = tls_filesz;
        enc->tls_memsz  = tls_memsz;
        process_page(ubase, pageoffset, prot, page);
        pageoffset += PAGE_SIZE;

        memset(page, 0, PAGE_SIZE);

        tcs_t* tcs  = (tcs_t*)page;
        tcs->ossa   = ossa;
        tcs->nssa   = 2;
        tcs->oentry = libbase + get_symbol_address(p, "entry");
        tcs->flags.dbgoptin = 0;
        tcs->ofsbasgx = tls;
        tcs->ogsbasgx = tls;
        tcs->fslimit  = 0x0fff;
        tcs->gslimit  = 0x0fff;
        process_page(ubase, pageoffset, PAGE_TCS, page);
        threads[i].addr = (void*)(pageoffset + ubase);
        threads[i].busy = 0;
        D printf("tcs(%d): %lx\n", i, pageoffset);
        pageoffset += PAGE_SIZE;
    }
}


void debug_write(uint64_t addr, uint64_t val) {
#if 0
    encls(ENCLS_EDBGWR_IOCTL, tcsaddr_kernel + 8, (void*)val, 0);
#endif
}

/* from Intel's ptrace */
int se_write_process_mem(void* base_addr, void* buffer, size_t size, size_t* write_nr) {
    char filename[64];
    int fd = -1;
    int ret = -1;
    ssize_t len = 0;
    off64_t offset = (off64_t)(size_t)base_addr;

    snprintf (filename, 64, "/proc/%d/mem", getpid());
    fd = open(filename, O_RDWR | O_LARGEFILE);
    if(fd == -1)
        return -1;

    if(lseek64(fd, offset, SEEK_SET) == -1)
    {
        goto out;
    }
    if((len = write(fd, buffer, size)) < 0)
    {
        goto out;
    }
    else if(write_nr)
        *write_nr = (size_t)len; /* len is a non-negative number */

    ret = 0;
out:
    close (fd);
    return ret;
}

void __gdb_hook_init_done(void);

static
enclave_parms_t* get_enclave_parms(void *p) {
    uint64_t* start = (uint64_t*)get_section_address(p, ".tdata");
    /* TODO: check we don't get out of section */
    while (*start != 0xBAADF00DDEADBABE) {
        start++;
    }
    return (enclave_parms_t *)start;
}

uintptr_t create_enclave_mem(char *p, char *einit_path, int base_zero, void *base_zero_max) {
    einittoken_t *t = 0;
    sigstruct_t  *s = 0;

    struct stat sb;

    /* if einit_path is set, try to get the token from the file, otherwise it should be in .note.token */
    if (einit_path != 0) {
        int fd = open(einit_path, O_RDONLY);
        if (fd == -1) {
            fprintf(stderr, "cannot open einit file\n");
            exit(EXIT_FAILURE);
        }

        fstat(fd, &sb);
        t = (einittoken_t*)mmap(0, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
    }
    else
        t = (einittoken_t*)get_section_address(p, ".note.token");

    s = (sigstruct_t*)get_section_address(p, ".note.sigstruct");
    if (s == 0) {
        fprintf(stderr, "enclave library should have .note.sigstruct section\n");
        exit(EXIT_FAILURE);
    }


    enclave_parms_t *enc = get_enclave_parms(p);
    int ssaFrameSize = 1;
    int nssa = 2;
    int tcsp = enc->tcsn;
    size_t heap  = enc->heap_size / PAGE_SIZE;
    size_t stack = enc->stack_size / PAGE_SIZE;
    size_t size  = get_enclave_size(heap, stack, tcsp, ssaFrameSize, nssa, get_loadable_size(p), 1);

    void *encl_base_addr = ECREATE_NO_FIXED_ADDR;
    if (base_zero) {
        if (size * PAGE_SIZE > (size_t) base_zero_max) {
            fprintf(stderr, "Error: SGXLKL_HEAP must be smaller than %lu bytes to not overlap with sgx-lkl-run when SGXLKL_NON_PIE is set to 1.\n", (size_t) (base_zero_max - (size * PAGE_SIZE - enc->heap_size)));
            exit(EXIT_FAILURE);
        }
        encl_base_addr = (void*) 0x0;
    }

    ubase = ecreate(size, ssaFrameSize, s, encl_base_addr);
    heap_size = enc->heap_size; // Used by GDB plugin
    process_pages(p, (uint64_t)ubase, heap, stack, tcsp, nssa, &add_page);

    int res = einit(ubase, s, t);
    if (res != 0) {
        printf("Error while initializing enclave, error code: %d\n", res);
        destroy_enclave(ubase);
        exit(EXIT_FAILURE);
    }

    if (einit_path != 0)
        munmap(t, sb.st_size);

    __gdb_hook_init_done();

    /* enable performance counters */
    char buffer = 1;
    for (int i = 0; i < tcsp; i++) se_write_process_mem(threads[i].addr + 8, &buffer, 1, 0);

    return ubase;
}

uint64_t create_enclave(char* path, char* einit_path) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "cannot open enclave file\n");
        exit(EXIT_FAILURE);
    }

    struct stat sb;
    fstat(fd, &sb);
    char* p = mmap(0, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED) {
        fprintf(stderr, "cannot map enclave file\n");
        exit(EXIT_FAILURE);
    }
    close(fd);

    ubase = create_enclave_mem(p, einit_path, 0, (void*) 0);

    munmap(p, sb.st_size);
    return (uint64_t)ubase;
}


void destroy_enclave(unsigned long enclave) {
    munmap((void *)enclave, esize);
}

static void fill_enclave_parms(void* p, size_t heap_offset, size_t stack_offset, size_t init_offset, size_t ossa_offset, int tcsn, size_t heap_size, size_t stack_size) {
    Elf_Ehdr *ehdr = (Elf_Ehdr*)p;
    Elf_Shdr *shdr = (Elf_Shdr*)(p + ehdr->e_shoff);
    int shnum = ehdr->e_shnum;

    Elf_Shdr *sh_strtab = &shdr[ehdr->e_shstrndx];
    const char *const sh_strtab_p = p + sh_strtab->sh_offset;

    int offset = 0;
    uint64_t size = 0;
    for (int i = 0; i < shnum; ++i) {
        if (strcmp(sh_strtab_p + shdr[i].sh_name, ".tdata") == 0) {
            offset = shdr[i].sh_offset;
            size = shdr[i].sh_size;
            break;
        }
    }

    if (offset == 0) {
        fprintf(stderr, "enclave library should have .tdata section\n");
        exit(EXIT_FAILURE);
    }

    D printf("heap offset %lx, ossa offset %lx, tcs num %x, heap size %lx, init offset %lx, stack offset %lx\n", 
            heap_offset, ossa_offset, tcsn, heap_size, init_offset, stack_offset);

    uint64_t* start = (uint64_t*)(p + offset);
    while (*start != 0xBAADF00DDEADBABE) {
        start++;
        if ((start - (uint64_t*)(p + offset)) > size) {
            fprintf(stderr, "could not find enclave_parms_t in .tdata \n");
            exit(EXIT_FAILURE);
        }
    }
    enclave_parms_t* enc = (enclave_parms_t*)start;
    enc->heap  = heap_offset;
    enc->stack = stack_offset;
    enc->ossa  = ossa_offset;
    enc->tcsn  = tcsn;
    enc->heap_size  = heap_size;
    enc->stack_size = stack_size;
}

static void fill_sigstruct_section(void* p, void* s) {
    Elf_Ehdr *ehdr = (Elf_Ehdr*)p;
    Elf_Shdr *shdr = (Elf_Shdr*)(p + ehdr->e_shoff);
    int shnum = ehdr->e_shnum;

    Elf_Shdr *sh_strtab = &shdr[ehdr->e_shstrndx];
    const char *const sh_strtab_p = p + sh_strtab->sh_offset;

    int offset = 0;
    for (int i = 0; i < shnum; ++i) {
        if (strcmp(sh_strtab_p + shdr[i].sh_name, ".note.sigstruct") == 0) {
            offset = shdr[i].sh_offset;
            break;
        }
    }

    if (offset == 0) {
        fprintf(stderr, "enclave library should have .note.sigstruct section\n");
        exit(EXIT_FAILURE);
    }

    memcpy(offset + p, s, 1808);
}

static void fill_token_section(void* p, void* t) {
    Elf_Ehdr *ehdr = (Elf_Ehdr*)p;
    Elf_Shdr *shdr = (Elf_Shdr*)(p + ehdr->e_shoff);
    int shnum = ehdr->e_shnum;

    Elf_Shdr *sh_strtab = &shdr[ehdr->e_shstrndx];
    const char *const sh_strtab_p = p + sh_strtab->sh_offset;

    int offset = 0;
    for (int i = 0; i < shnum; ++i) {
        if (strcmp(sh_strtab_p + shdr[i].sh_name, ".note.token") == 0) {
            offset = shdr[i].sh_offset;
            break;
        }
    }

    if (offset == 0) {
        fprintf(stderr, "enclave library should have .note.token section\n");
        exit(EXIT_FAILURE);
    }

    memcpy(offset + p, t, 304);
}

void enclave_update_heap(void *p, size_t new_heap, char* key_path) {
    if (p == 0) return;
    if (key_path == 0) {
        fprintf(stderr, "Need a key to update heap size \n");
        return;
    }

    enclave_parms_t *enc = get_enclave_parms(p);
    int ssaFrameSize = 1;
    int nssa = 2;
    int tcsp = enc->tcsn;
    enc->heap_size = new_heap;
    new_heap /= PAGE_SIZE;
    size_t stack = enc->stack_size / PAGE_SIZE;
    size_t lib_size = get_loadable_size(p);
    size_t size = get_enclave_size(new_heap, stack, tcsp, ssaFrameSize, nssa, lib_size, 1);
    if (new_heap == 0) {
        new_heap = 0x5d7f - size;
        size += new_heap;
    }
    size *= PAGE_SIZE;
    size = get_next_power2(size);

    int heap_offset  = 0x0;
    int init_offset  = new_heap * PAGE_SIZE + get_symbol_address(p, "entry");
    int npages       = lib_size;
    int ossa_offset  = new_heap * PAGE_SIZE + npages * PAGE_SIZE;
    int stack_offset = ossa_offset + 2 * PAGE_SIZE + stack * PAGE_SIZE; //+ 0xfff;
    fill_enclave_parms(p, heap_offset, stack_offset, init_offset, ossa_offset, tcsp, new_heap * PAGE_SIZE, stack * PAGE_SIZE);

    unsigned char hash[32];
    sha256_init(&ctx);
    sha256_starts(&ctx, 0);
    uint64_t tmp_update_field[8];
    memset(&tmp_update_field[0], 0, 64);
    tmp_update_field[0] = STRING_ECREATE;
    memcpy((unsigned char*)&tmp_update_field[1], &ssaFrameSize, 4);
    memcpy((unsigned char*)&tmp_update_field[1] + 4, &size, 8);
    sha256_update(&ctx, (unsigned char *)tmp_update_field, 64);
    process_pages(p, 0, new_heap, stack, tcsp, nssa, &measure_page);
    sha256_finish(&ctx, (unsigned char*)hash);

    sigstruct_t *s = (sigstruct_t*)get_section_address(p, ".note.sigstruct");
    memcpy(s->enclaveHash, hash, 32);
    cmd_sign(s, key_path);
    char* t = get_init_token(s);
    if (t) {
        fill_token_section(p, t);
        update_init_token(p, (einittoken_t *)t);
        free(t);
    }

    D printf("enclave hash: ");
    for(int i = 0; i < 32; i++)
        D printf("%02x", (unsigned char)hash[i]);
    D printf("\n");
}

void enclave_sign(char* path, char* key, size_t heap, size_t stack, int tcsp, int get_token) {
    int fd = open(path, O_RDWR);
    if (fd == -1) {
        fprintf(stderr, "could not open enclave library \n");
        exit(EXIT_FAILURE);
    }
    struct stat sb;
    fstat(fd, &sb);
    char* p = mmap(0, sb.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);

    int ssaFrameSize = 1;
    int nssa = 2;
    size_t lib_size = get_loadable_size(p);

    size_t size = get_enclave_size(heap, stack, tcsp, ssaFrameSize, nssa, lib_size, 1);
    /* If heap size was not specified, attempt to fit the enclave into EPC (~94MB).
     * If the size is greater than EPC size, use 128MB heap */
    if (heap == 0) {
        if (size < 0x5d7f) {
            heap = 0x5d7f - size;
            size += heap;
        }
        else {
            heap = 32768;
            size += heap;
        }
    }

    D printf("enclave memory: \n");
    D printf("\theap:      %lu pages \n", heap);
    D printf("\tcode+data: %lu pages \n", lib_size);
    D printf("\ttcs:       %d pages \n", tcsp);
    D printf("per tcs: \n");
    D printf("\tstack:     %lu pages \n", stack);
    D printf("\tossa:      %d pages \n", ssaFrameSize * nssa);
    D printf("\ttls:       %d pages \n", 1);
    D printf("total number of pages: %lu\n", size);

    size *= PAGE_SIZE;
    size = get_next_power2(size);

    int heap_offset  = 0x0;
    int init_offset  = heap*PAGE_SIZE + get_symbol_address(p, "entry");
    int npages       = lib_size;
    int ossa_offset  = heap * PAGE_SIZE + npages * PAGE_SIZE;
    int stack_offset = ossa_offset + 2 * PAGE_SIZE + stack * PAGE_SIZE; //+ 0xfff;
    fill_enclave_parms(p, heap_offset, stack_offset, init_offset, ossa_offset, tcsp, heap * PAGE_SIZE, stack * PAGE_SIZE);
    D printf("stack start %lx, enclave size %lx\n", heap_offset + heap * PAGE_SIZE, size);

    unsigned char hash[32];
    sha256_init(&ctx);
    sha256_starts(&ctx, 0);
    uint64_t tmp_update_field[8];
    memset(&tmp_update_field[0], 0, 64);
    tmp_update_field[0] = STRING_ECREATE;
    memcpy((unsigned char*)&tmp_update_field[1], &ssaFrameSize, 4);
    memcpy((unsigned char*)&tmp_update_field[1] + 4, &size, 8);
    sha256_update(&ctx, (unsigned char *)tmp_update_field, 64);
    process_pages(p, 0, heap, stack, tcsp, nssa, &measure_page);
    sha256_finish(&ctx, (unsigned char*)hash);

    unsigned char header [16] = SIG_HEADER1;
    unsigned char header2[16] = SIG_HEADER2;

    sigstruct_t s = {};
    memcpy(s.header, header, 16);
    memcpy(s.header2, header2, 16);
    s.attributes.debug = 1;
    s.attributes.mode64bit = 1;
    s.attributes.xfrm = 0x7;
    s.attributes.provisionkey = 0;
    memset(&s.attributeMask, 0xff, 16);
    s.attributeMask.debug = 0;
    s.attributeMask.xfrm = 0xffffffffffffff1b;
    memcpy(s.enclaveHash, hash, 32);
    cmd_sign(&s, key);
    fill_sigstruct_section(p, &s);

    if (get_token) {
        char* t = get_init_token(&s);
        if (t) {
            fill_token_section(p, t);
            free(t);
        }
        else {
            fprintf(stderr, "error while obtaining einittoken\n");
        }
    }

    munmap(p, sb.st_size);
    close(fd);

    D printf("enclave hash: ");
    for(int i = 0; i < 32; i++)
        D printf("%02x", (unsigned char)hash[i]);
    D printf("\n");
}

__attribute__((destructor))
    void destructor() {
        if (ubase != BASE_ADDR_UNDEFINED)
            destroy_enclave((unsigned long)ubase);

        if (sgxfd)
            close(sgxfd);

        if (threads)
            free(threads);
    }

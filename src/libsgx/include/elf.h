#include <stdint.h>

/* from linux/include/uapi/linux/elf.h */

/* 64-bit ELF base types. */
typedef uint64_t  Elf64_Addr;
typedef uint16_t  Elf64_Half;
typedef uint16_t  Elf64_SHalf;
typedef uint64_t  Elf64_Off;
typedef int32_t   Elf64_Sword;
typedef uint32_t  Elf64_Word;
typedef uint64_t  Elf64_Xword;
typedef int64_t   Elf64_Sxword;

#define EI_NIDENT   16

typedef struct elf64_phdr {
        Elf64_Word p_type;
        Elf64_Word p_flags;
        Elf64_Off p_offset;       /* Segment file offset */
        Elf64_Addr p_vaddr;     /* Segment virtual address */
        Elf64_Addr p_paddr;       /* Segment physical address */
        Elf64_Xword p_filesz;       /* Segment size in file */
        Elf64_Xword p_memsz;      /* Segment size in memory */
        Elf64_Xword p_align;        /* Segment alignment, file & memory */
} Elf_Phdr;

typedef struct elf64_hdr {
        unsigned char e_ident[EI_NIDENT]; /* ELF "magic number" */
        Elf64_Half e_type;
        Elf64_Half e_machine;
        Elf64_Word e_version;
        Elf64_Addr e_entry;       /* Entry point virtual address */
        Elf64_Off e_phoff;      /* Program header table file offset */
        Elf64_Off e_shoff;        /* Section header table file offset */
        Elf64_Word e_flags;
        Elf64_Half e_ehsize;
        Elf64_Half e_phentsize;
        Elf64_Half e_phnum;
        Elf64_Half e_shentsize;
        Elf64_Half e_shnum;
        Elf64_Half e_shstrndx;
} Elf_Ehdr;

typedef struct elf64_shdr {
        Elf64_Word sh_name;       /* Section name, index in string tbl */
        Elf64_Word sh_type;     /* Type of section */
        Elf64_Xword sh_flags;     /* Miscellaneous section attributes */
        Elf64_Addr sh_addr;     /* Section virtual addr at execution */
        Elf64_Off sh_offset;      /* Section file offset */
        Elf64_Xword sh_size;        /* Size of section in bytes */
        Elf64_Word sh_link;       /* Index of another section */
        Elf64_Word sh_info;     /* Additional section information */
        Elf64_Xword sh_addralign; /* Section alignment */
        Elf64_Xword sh_entsize; /* Entry size if section holds table */
} Elf_Shdr;

typedef struct elf64_sym {
        Elf64_Word st_name;       /* Symbol name, index in string tbl */
        unsigned char   st_info;    /* Type and binding attributes */
        unsigned char st_other;   /* No defined meaning, 0 */
        Elf64_Half st_shndx;        /* Associated section index */
        Elf64_Addr st_value;      /* Value of the symbol */
        Elf64_Xword st_size;        /* Associated symbol size */
} Elf_Sym;

/* These constants are for the segment types stored in the image headers */
#define PT_NULL    0
#define PT_LOAD    1
#define PT_DYNAMIC 2
#define PT_INTERP  3
#define PT_NOTE    4
#define PT_SHLIB   5
#define PT_PHDR    6
#define PT_TLS     7               /* Thread local storage segment */
#define PT_LOOS    0x60000000      /* OS-specific */
#define PT_HIOS    0x6fffffff      /* OS-specific */
#define PT_LOPROC  0x70000000
#define PT_HIPROC  0x7fffffff
#define PT_GNU_EH_FRAME     0x6474e550

#define PT_GNU_STACK    (PT_LOOS + 0x474e551)

/* sh_type */
#define SHT_NULL    0
#define SHT_PROGBITS    1
#define SHT_SYMTAB  2
#define SHT_STRTAB  3
#define SHT_RELA    4
#define SHT_HASH    5
#define SHT_DYNAMIC 6
#define SHT_NOTE    7
#define SHT_NOBITS  8
#define SHT_REL     9
#define SHT_SHLIB   10
#define SHT_DYNSYM  11
#define SHT_NUM     12
#define SHT_LOPROC  0x70000000
#define SHT_HIPROC  0x7fffffff
#define SHT_LOUSER  0x80000000
#define SHT_HIUSER  0xffffffff

/* sh_flags */
#define SHF_WRITE   0x1
#define SHF_ALLOC   0x2
#define SHF_EXECINSTR   0x4
#define SHF_MASKPROC    0xf0000000

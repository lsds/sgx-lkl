#define AT_NULL 0 

// from elf.h in musl
typedef struct {
  uint64_t a_type;
  union {
      uint64_t a_val;
  } a_un;
} Elf64_auxv_t;

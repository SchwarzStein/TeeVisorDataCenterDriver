#include "ecall.h"
#include "ocall.h"
#include "utils.h"
#include "stdint.h"
#include "mm/mm.h"
#include "stdbool.h"
#include "../enclave_lib/enclave_runtime.h"
#include "elf.h"

volatile int64_t cpu_counter = 0; 
extern const Elf64_Ehdr __ehdr_start __attribute__((visibility("hidden")));
static int64_t enclave_initialized = 0; // 0 = not init, 1 = initializing, 2 = initialized, 3 = failed

void cpu_counter_inc()
{
    __atomic_fetch_add(&cpu_counter, 1, __ATOMIC_SEQ_CST);
}

void cpu_counter_dec()
{
    __atomic_fetch_sub(&cpu_counter, 1, __ATOMIC_SEQ_CST);
}

int64_t cpu_counter_read(void)
{
    return __atomic_load_n(&cpu_counter, __ATOMIC_SEQ_CST);
}

static Elf64_Dyn *find_dynamic_section(Elf64_Addr ehdr_addr, Elf64_Addr base_diff)
{
    const Elf64_Ehdr *elf_header = (const Elf64_Ehdr *)ehdr_addr;
    const Elf64_Phdr *phdr = (const Elf64_Phdr *)(ehdr_addr + elf_header->e_phoff);

    Elf64_Dyn *dynamic_section = NULL;
    for (const Elf64_Phdr *ph = phdr; ph < &phdr[elf_header->e_phnum]; ph++)
    {
        if (ph->p_type == PT_DYNAMIC)
        {
            dynamic_section = (Elf64_Dyn *)(ph->p_vaddr + base_diff);
            break;
        }
    }

    return dynamic_section;
}

static int locate_string_and_symbol_tables(const char **out_strtab,
                                           Elf64_Sym **out_symtab,
                                           uint32_t *out_symtab_count)
{
    const char *strtab = NULL;
    Elf64_Sym *symtab = NULL;
    uint32_t symtab_count = 0;
    Elf64_Addr base_diff = GET_ENCLAVE_TLS(runtime_base);

    Elf64_Dyn *dyn_section = find_dynamic_section((Elf64_Addr)&__ehdr_start, base_diff);
    if (!dyn_section)
    {
        return -1;
    }

    for (Elf64_Dyn *dyn = dyn_section; dyn->d_tag != DT_NULL; dyn++)
    {
        switch (dyn->d_tag)
        {
        case DT_STRTAB:
            strtab = (const char *)(dyn->d_un.d_ptr + base_diff);
            break;

        case DT_SYMTAB:
            symtab = (Elf64_Sym *)(dyn->d_un.d_ptr + base_diff);
            break;

        case DT_HASH:
        {
            uint32_t *hash_table = (uint32_t *)(dyn->d_un.d_ptr + base_diff);
            symtab_count = hash_table[1];
            break;
        }
        default:
            break;
        }
    }

    if (!strtab || !symtab || !symtab_count)
    {
        return -1;
    }

    *out_strtab = strtab;
    *out_symtab = symtab;
    *out_symtab_count = symtab_count;

    return 0;
}

#define ELF64_R_SYM(i) ((i) >> 32)
#define ELF64_R_TYPE(i) ((i) & 0xffffffff)

static int perform_relocations()
{
    Elf64_Addr base_diff = GET_ENCLAVE_TLS(runtime_base);
    Elf64_Dyn *dyn_section = find_dynamic_section((Elf64_Addr)&__ehdr_start, base_diff);
    Elf64_Rela *relas_start = NULL;
    Elf64_Xword relas_size = 0;
    Elf64_Xword relas_count = 0;
    Elf64_Xword expected_relas_count = 0;

    for (Elf64_Dyn *dyn = dyn_section; dyn->d_tag != DT_NULL; dyn++)
    {
        switch (dyn->d_tag)
        {
        case DT_RELACOUNT:
            expected_relas_count = dyn->d_un.d_val;
            break;
        case DT_RELA:
            relas_start = (Elf64_Rela *)(dyn->d_un.d_ptr + base_diff);
            break;
        case DT_RELASZ:
            relas_size = dyn->d_un.d_val;
            break;
        default:
            break;
        }
    }

    //  If there is no address to relocate
    if (!relas_start && relas_size)
    {
        return 0;
    }

    Elf64_Rela *relas_addr_end = (Elf64_Rela *)((uintptr_t)relas_start + relas_size);
    for (Elf64_Rela *rela = relas_start; rela < relas_addr_end; rela++)
    {
        if (ELF64_R_TYPE(rela->r_info) == R_X86_64_RELATIVE)
        {
            Elf64_Addr *rela_ptr = (Elf64_Addr *)(rela->r_offset + base_diff);
            *rela_ptr = *rela_ptr + base_diff;
            relas_count++;
        }
        else
        {
            return -1;
        }
    }

    if (relas_count != expected_relas_count)
    {
        return -1;
    }

    return 0;
}

static int relocate_symbol()
{
    const char *strtab = NULL;
    Elf64_Sym *symtab = NULL;
    uint32_t symtab_count = 0;
    int ret;

    // If we only relocate R_X86_64_RELATIVE, do not need to parse the symbol tables
    ret = locate_string_and_symbol_tables(&strtab, &symtab, &symtab_count);
    if (ret)
    {
        return ret;
    }

    ret = perform_relocations();

    return ret;
}

static int runtime_setup()
{
    int ret = 0;
    init_allocator();
    ret = relocate_symbol();
    if (ret)
    {
        return ret;
    }

    return ret;
}


void handle_ecall(unsigned long rdi, unsigned long rsi, unsigned long _aep /*rcx is set by firmware*/,
                  unsigned long r8, unsigned long r9)
{
    uint64_t ursp = GET_ENCLAVE_TLS(gpr)->ursp;
    uint64_t urbp = GET_ENCLAVE_TLS(gpr)->urbp;
    uint64_t enclave_base = GET_ENCLAVE_TLS(enclave_base);
    uint64_t enclave_top = GET_ENCLAVE_TLS(enclave_base) + GET_ENCLAVE_TLS(enclave_size);
    int ret;
    if (enclave_base <= ursp && ursp <= enclave_top)
    {
        return;
    }
    
    SET_ENCLAVE_TLS(ursp, ursp);
    SET_ENCLAVE_TLS(urbp, urbp);
    cpu_counter_inc();

    int64_t t = 0;
    if (__atomic_compare_exchange_n(&enclave_initialized, &t, 1, /*weak=*/false,
                                    __ATOMIC_SEQ_CST, __ATOMIC_RELAXED))
    {
        ret = runtime_setup();
        if (!ret)
        {
            __atomic_store_n(&enclave_initialized, 2, __ATOMIC_SEQ_CST);
        }
        else
        {
            __atomic_store_n(&enclave_initialized, 3, __ATOMIC_SEQ_CST);
            return;
        }
    }
    else
    {
        while (__atomic_load_n(&enclave_initialized, __ATOMIC_SEQ_CST) < 2)
        {
            asm volatile("pause" ::: "memory");
        }

        if (__atomic_load_n(&enclave_initialized, __ATOMIC_SEQ_CST) == 3)
        {
            return;
        }
    }

    if (ret) {
        do_eexit(EEXIT_FAIL, 1);
    }

    // call runtime test
    ret = runtime_test_case();
    if (ret) {
        do_eexit(EEXIT_FAIL, 2);
    }
    // handle ecall here

    // call user here
    

    do_eexit(EEXIT_EXIT, 0);
}
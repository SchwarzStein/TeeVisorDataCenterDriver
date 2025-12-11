#include "enclave.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <asm/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include "sha256.h"

static int teevisor_fd = -1;
static int epfd = -1;

int open_teevisor_driver(void)
{
    const char *path = "/dev/sgx_enclave";
    int ret = open(path, O_RDWR | O_CLOEXEC);
    if (ret < 0)
    {
        fprintf(stderr, "Cannot open %s (%s)\n", path, strerror(errno));
        return ret;
    }
    teevisor_fd = ret;
    return 0;
}

size_t calculate_elf_memory_size(int fd)
{
    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr))
    {
        fprintf(stderr, "Failed to read ELF header\n");
        return 0;
    }

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0)
    {
        fprintf(stderr, "Not a valid ELF file\n");
        return 0;
    }

    if (lseek(fd, ehdr.e_phoff, SEEK_SET) == -1)
    {
        perror("lseek");
        return 0;
    }

    uint64_t max_vaddr = 0;

    for (int i = 0; i < ehdr.e_phnum; i++)
    {
        Elf64_Phdr phdr;
        if (read(fd, &phdr, sizeof(phdr)) != sizeof(phdr))
        {
            fprintf(stderr, "Failed to read program header %d\n", i);
            break;
        }

        if (phdr.p_type == PT_LOAD)
        {
            uint64_t segment_end = phdr.p_vaddr + phdr.p_memsz;
            if (segment_end > max_vaddr)
            {
                max_vaddr = segment_end;
            }
        }
    }

    if (max_vaddr == 0)
    {
        fprintf(stderr, "No loadable segments found\n");
        return 0;
    }

    if (lseek(fd, 0, SEEK_SET) == -1)
    {
        perror("lseek reset failed");
        return 0;
    }

    return max_vaddr;
}

static int find_static_string_and_symbol_tables(uint64_t ehdr_addr, const char **out_string_table,
                                                Elf64_Sym **out_symbol_table, uint32_t *out_symbol_table_cnt)
{
    uint32_t symbol_table_cnt = 0;
    Elf64_Shdr *symtab_hdr = NULL;
    Elf64_Shdr *strtab_hdr = NULL;

    Elf64_Ehdr *header = (Elf64_Ehdr *)ehdr_addr;
    Elf64_Shdr *shdr = (Elf64_Shdr *)(ehdr_addr + header->e_shoff);
    Elf64_Shdr sh_str = shdr[header->e_shstrndx];
    char *sh_strtab = (char *)(ehdr_addr + sh_str.sh_offset);

    for (int i = 0; i < header->e_shnum; i++)
    {
        const char *name = sh_strtab + shdr[i].sh_name;
        if (strcmp(name, ".symtab") == 0)
        {
            symtab_hdr = &shdr[i];
        }
        else if (strcmp(name, ".strtab") == 0)
        {
            strtab_hdr = &shdr[i];
        }
    }
    if (!symtab_hdr || !strtab_hdr)
    {
        perror("Loaded binary doesn't have symtab and strtab section (required for symbol resolution)");
        return -1;
    }

    symbol_table_cnt = symtab_hdr->sh_size / sizeof(Elf64_Sym);

    *out_string_table = (char *)(ehdr_addr + strtab_hdr->sh_offset);
    *out_symbol_table = (Elf64_Sym *)(ehdr_addr + symtab_hdr->sh_offset);
    *out_symbol_table_cnt = symbol_table_cnt;
    return 0;
}

static uint64_t get_elf_entry_addr(int fd)
{
    struct stat st;
    uint64_t entry_addr = 0;
    void *map = NULL;

    if (fstat(fd, &st) < 0)
    {
        perror("fstat failed when parsing ELF entry!\n");
        return UINT64_MAX;
    }

    map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED)
    {
        perror("mmap failed when parsing ELF entry!\n");
        return UINT64_MAX;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map;

    /* ELF header sanity check */
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0)
    {
        fprintf(stderr, "Not a valid ELF file!\n");
        munmap(map, st.st_size);
        return UINT64_MAX;
    }

    entry_addr = ehdr->e_entry;

    munmap(map, st.st_size);
    return entry_addr;
}

static uint64_t get_handler_addr(int fd, char *handler_symbol_name)
{
    uint64_t handler_addr = 0;
    const char *string_table = NULL;
    Elf64_Sym *symbol_table = NULL;
    uint32_t symbol_table_cnt = 0;
    int ret;
    struct stat st;

    if (fstat(fd, &st) < 0)
    {
        perror("fstat with runtime fd failed!\n");
        return UINT64_MAX;
    }

    void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED)
    {
        perror("map with runtime fd failed!\n");
        return UINT64_MAX;
    }

    ret = find_static_string_and_symbol_tables((uint64_t)map, &string_table, &symbol_table,
                                               &symbol_table_cnt);
    if (ret < 0)
    {
        perror("Cannot find string and symbol tables for parsing handler address!\n");
        munmap(map, st.st_size);
        return UINT64_MAX;
    }

    for (uint32_t i = 0; i < symbol_table_cnt; i++)
    {
        const char *symbol_name = string_table + symbol_table[i].st_name;
        if (!strcmp(handler_symbol_name, symbol_name))
        {
            handler_addr = symbol_table[i].st_value;
            break;
        }
    }
    munmap(map, st.st_size);
    return handler_addr;
}

static void measure_ecreate(struct sha256 *sha, uint32_t ssa_frame_size, uint64_t enclave_size)
{
    struct ecreate_update update;
    memset(&update, 0, sizeof(update));
    update.ecreate = ECREATE;
    update.ssa_frame_size = ssa_frame_size;
    update.enclave_size = enclave_size;
    sha256_append(sha, &update, sizeof(update));
}

static void measure_eadd(struct sha256 *sha, uint64_t offset, uint64_t flags)
{
    struct eadd_update update;
    memset(&update, 0, sizeof(update));
    update.eadd = EADD;
    update.offset = offset;
    update.flags = flags;
    sha256_append(sha, &update, sizeof(update));
}

static void measure_eextend(struct sha256 *sha, uint64_t offset, void *content)
{
    struct eextend_update update;
    memset(&update, 0, sizeof(update));
    update.eextend = EEXTEND;
    update.offset = offset;
    sha256_append(sha, &update, sizeof(update));
    sha256_append(sha, content, EEXTEND_BLOCK_SIZE);
}

static int add_pages(struct enclave *encl, void *user_addr, uint64_t target_addr,
                     uint64_t length, int prot, enum sgx_page_type type,
                     bool skip_eextend, struct sha256 *sha)
{
    sgx_arch_sec_info_t secinfo = {0};
    int ret;

    switch (type)
    {
    case SGX_PAGE_TYPE_SECS:
        return -EPERM;
    case SGX_PAGE_TYPE_TCS:
        secinfo.flags = SGX_PAGE_TYPE_TCS << SGX_SECINFO_FLAGS_TYPE_SHIFT;
        break;
    case SGX_PAGE_TYPE_REG:
        secinfo.flags = SGX_PAGE_TYPE_REG << SGX_SECINFO_FLAGS_TYPE_SHIFT | prot;
        break;

    case SGX_PAGE_TYPE_HANDLER:
        if (prot != (PROT_READ | PROT_EXEC))
        {
            return -EINVAL;
        }
        secinfo.flags = SGX_PAGE_TYPE_HANDLER << SGX_SECINFO_FLAGS_TYPE_SHIFT | prot;
        break;
    default:
        return -EINVAL;
    }

    struct sgx_enclave_add_pages param = {
        .offset = target_addr - encl->user_base,
        .src = (uint64_t)user_addr,
        .length = length,
        .secinfo = (uint64_t)&secinfo,
        .flags = skip_eextend ? 0 : SGX_PAGE_MEASURE,
        .count = 0, /* output parameter, will be checked after IOCTL */
    };

    while (param.length > 0)
    {
        ret = ioctl(teevisor_fd, SGX_IOC_ENCLAVE_ADD_PAGES, &param);
        if (ret < 0)
        {
            if (ret == -EINTR)
                continue;
            perror("Enclave add-pages IOCTL failed");
            return ret;
        }

        uint64_t added_size = param.count;
        if (!added_size)
        {
            return -EPERM;
        }
        param.offset += added_size;
        param.src += added_size;
        param.length -= added_size;
    }

    for (uint64_t i = 0; i < length; i += PAGE_SIZE)
    {
        uint64_t offset = target_addr - encl->user_base + i;
        measure_eadd(sha, offset, secinfo.flags);
        if (!skip_eextend)
        {
            for (int j = 0; j < PAGE_SIZE / EEXTEND_BLOCK_SIZE; j++)
            {
                measure_eextend(sha, offset + j * EEXTEND_BLOCK_SIZE, user_addr + i + j * EEXTEND_BLOCK_SIZE);
            }
        }
    }

    return 0;
}

static int add_segement(struct enclave *encl, int fd, struct load_param *p, enum sgx_page_type type, uint64_t map_base_offset, struct sha256 *sha)
{

    printf("load_param:\n");
    printf("  map_start  = 0x%016llx\n", (unsigned long long)p->map_start);
    printf("  map_end    = 0x%016llx\n", (unsigned long long)p->map_end);
    printf("  data_start = 0x%016llx\n", (unsigned long long)p->data_start);
    printf("  data_end   = 0x%016llx\n", (unsigned long long)p->data_end);
    printf("  alloc_end  = 0x%016llx\n", (unsigned long long)p->alloc_end);
    printf("  map_offset = 0x%016llx\n", (unsigned long long)p->map_offset);
    printf("  prot       = 0x%x\n", p->prot);
    printf("  type       = 0x%x\n", type);

    if (p->map_end == p->map_start)
    {
        return 0;
    }

    void *addr = mmap(NULL, p->map_end - p->map_start, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, p->map_offset);
    int ret;

    if (addr == MAP_FAILED)
    {
        fprintf(stderr, "mmap failed at offset 0x%lx: %s\n",
                (unsigned long)p->map_offset, strerror(errno));
        return -1;
    }

    if (p->data_start > p->map_start)
        memset(addr, 0, p->data_start - p->map_start);

    uint64_t zero_page = ALIGN_UP(p->data_end, PAGE_SIZE);
    if (zero_page > p->data_end)
    {
        memset(addr + p->data_end - p->map_start, 0, zero_page - p->data_end);
    }

    ret = add_pages(encl, addr, p->map_start + map_base_offset, p->map_end - p->map_start,
                    p->prot, type, false, sha);

    munmap(addr, p->map_end - p->map_start);
    return ret;
}

static int add_elf(struct enclave *encl, int fd, bool user, uint64_t handler_addr, struct sha256 *sha)
{
    Elf64_Ehdr ehdr;
    uint64_t map_base_offset = user ? 0 : encl->runtime_base;
    uint64_t seg_map_start, seg_map_end;
    struct load_param p;
    int prot;
    int ret;

    ret = read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr);
    if (ret)
    {
        fprintf(stderr, "Failed to read ELF header\n");
        return ret;
    }

    ret = lseek(fd, ehdr.e_phoff, SEEK_SET);
    if (ret == -1)
    {
        perror("lseek");
        return ret;
    }

    for (int i = 0; i < ehdr.e_phnum; i++)
    {
        Elf64_Phdr phdr;
        if (read(fd, &phdr, sizeof(phdr)) != sizeof(phdr))
        {
            fprintf(stderr, "Failed to read program header %d\n", i);
            break;
        }

        if (phdr.p_type == PT_LOAD)
        {
            seg_map_start = ALIGN_DOWN(phdr.p_vaddr, PAGE_SIZE);
            seg_map_end = ALIGN_UP(phdr.p_vaddr + phdr.p_filesz, PAGE_SIZE);
            if (!user && handler_addr >= seg_map_start && handler_addr < seg_map_end)
            {
                // If handler page is part of the segment, add the handler page separately
                // [segment start, handler_addr)
                if (handler_addr > phdr.p_vaddr)
                {
                    p.map_start = seg_map_start;
                    p.map_end = handler_addr;
                    p.data_start = phdr.p_vaddr;
                    p.data_end = handler_addr;
                    p.alloc_end = handler_addr;
                    p.map_offset = ALIGN_DOWN(phdr.p_offset, PAGE_SIZE);
                    p.prot = (phdr.p_flags & PF_R ? PROT_READ : 0) |
                             (phdr.p_flags & PF_W ? PROT_WRITE : 0) |
                             (phdr.p_flags & PF_X ? PROT_EXEC : 0);
                    ret = add_segement(encl, fd, &p, SGX_PAGE_TYPE_REG, map_base_offset, sha);
                    if (ret)
                    {
                        fprintf(stderr, "Add segement before handler page failed!\n");
                        return ret;
                    }
                }

                // handler page
                p.map_start = handler_addr;
                p.map_end = handler_addr + PAGE_SIZE;
                p.data_start = handler_addr;
                p.data_end = handler_addr + PAGE_SIZE;
                p.alloc_end = handler_addr + PAGE_SIZE;
                p.map_offset = ALIGN_DOWN(phdr.p_offset, PAGE_SIZE) +
                               (handler_addr - ALIGN_DOWN(phdr.p_vaddr, PAGE_SIZE));
                p.prot = (phdr.p_flags & PF_R ? PROT_READ : 0) |
                         (phdr.p_flags & PF_W ? PROT_WRITE : 0) |
                         (phdr.p_flags & PF_X ? PROT_EXEC : 0);
                ret = add_segement(encl, fd, &p, SGX_PAGE_TYPE_HANDLER, map_base_offset, sha);
                if (ret)
                {
                    fprintf(stderr, "Add segement handler page failed!\n");
                    return ret;
                }

                // [handler_addr + PAGE_SIZE, segment end)
                if (handler_addr + PAGE_SIZE < phdr.p_vaddr + phdr.p_memsz)
                {
                    p.map_start = handler_addr + PAGE_SIZE;
                    p.map_end = ALIGN_UP(phdr.p_vaddr + phdr.p_memsz, PAGE_SIZE);
                    p.data_start = handler_addr + PAGE_SIZE;
                    p.data_end = phdr.p_vaddr + phdr.p_filesz;
                    p.alloc_end = phdr.p_vaddr + phdr.p_memsz;
                    p.map_offset = ALIGN_DOWN(phdr.p_offset, PAGE_SIZE) +
                                   (p.data_start - ALIGN_DOWN(phdr.p_vaddr, PAGE_SIZE));
                    p.prot = (phdr.p_flags & PF_R ? PROT_READ : 0) |
                             (phdr.p_flags & PF_W ? PROT_WRITE : 0) |
                             (phdr.p_flags & PF_X ? PROT_EXEC : 0);
                    ret = add_segement(encl, fd, &p, SGX_PAGE_TYPE_REG, map_base_offset, sha);
                    if (ret)
                    {
                        fprintf(stderr, "Add segement after handler page failed!\n");
                        return ret;
                    }
                }
            }
            else
            {
                p.map_start = seg_map_start;
                p.map_end = seg_map_end;
                p.data_start = phdr.p_vaddr;
                p.data_end = phdr.p_vaddr + phdr.p_filesz;
                p.alloc_end = phdr.p_vaddr + phdr.p_memsz;
                p.map_offset = ALIGN_DOWN(phdr.p_offset, PAGE_SIZE);
                p.prot = (phdr.p_flags & PF_R ? PROT_READ : 0) | (phdr.p_flags & PF_W ? PROT_WRITE : 0) |
                         (phdr.p_flags & PF_X ? PROT_EXEC : 0);
                ret = add_segement(encl, fd, &p, SGX_PAGE_TYPE_REG, map_base_offset, sha);
                if (ret)
                {
                    fprintf(stderr, "Add segement failed!\n");
                    return ret;
                }
            }
        }
    }

    return 0;
}

uint8_t *get_signing_data(const sgx_sigstruct_t *sig)
{
    assert(sig != NULL);
    uint8_t *buf = malloc(SGX_SIG_SIGNING_DATA_SIZE);
    if (!buf)
        return NULL;

    memcpy(buf, sig, 128);

    memcpy(buf + 128, ((uint8_t *)sig) + 0x384, 128);

    return buf;
}

void bn_to_le_bytes(const BIGNUM *bn, unsigned char *le_bytes, size_t len)
{
    unsigned char be_bytes[len];
    BN_bn2binpad(bn, be_bytes, len);
    for (size_t i = 0; i < len; i++)
    {
        le_bytes[i] = be_bytes[len - 1 - i];
    }
}

static void print_hex(const char *name, const uint8_t *buf, size_t len)
{
    printf("%s: ", name);
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

void print_sgx_sigstruct(const sgx_sigstruct_t *sig)
{
    if (!sig)
        return;

    print_hex("header", sig->header, sizeof(sig->header));
    printf("vendor: 0x%08x\n", sig->vendor);
    printf("date:   0x%08x\n", sig->date);
    print_hex("header2", sig->header2, sizeof(sig->header2));
    printf("swdefined: 0x%08x\n", sig->swdefined);
    print_hex("reserved1", sig->reserved1, sizeof(sig->reserved1));
    print_hex("modulus", sig->modulus, sizeof(sig->modulus));
    printf("exponent: 0x%08x\n", sig->exponent);
    print_hex("signature", sig->signature, sizeof(sig->signature));
    printf("misc_select: 0x%08x\n", sig->misc_select);
    printf("misc_mask:   0x%08x\n", sig->misc_mask);
    printf("cet_attributes: 0x%016llx\n", (unsigned long long)sig->cet_attributes);
    printf("cet_attributes_mask: 0x%016llx\n", (unsigned long long)sig->cet_attributes_mask);
    print_hex("reserved2", sig->reserved2, sizeof(sig->reserved2));
    print_hex("isv_family_id", sig->isv_family_id, sizeof(sig->isv_family_id));
    printf("attributes flags: 0x%016llx\n", (unsigned long long)sig->attributes.flags);
    printf("attributes xfrm: 0x%016llx\n", (unsigned long long)sig->attributes.xfrm);
    printf("attribute_flag_mask: 0x%016llx\n", (unsigned long long)sig->attribute_mask.flags);
    printf("attribute_xfrm_mask: 0x%016llx\n", (unsigned long long)sig->attribute_mask.xfrm);
    print_hex("enclave_hash", sig->enclave_hash.m, sizeof(sig->enclave_hash));
    print_hex("reserved3", sig->reserved3, sizeof(sig->reserved3));
    print_hex("isvext_prod_id", sig->isvext_prod_id, sizeof(sig->isvext_prod_id));
    printf("isv_prod_id:    0x%04x\n", sig->isv_prod_id);
    printf("isv_svn:        0x%04x\n", sig->isv_svn);
    print_hex("reserved4", sig->reserved4, sizeof(sig->reserved4));
    print_hex("q1", sig->q1, sizeof(sig->q1));
    print_hex("q2", sig->q2, sizeof(sig->q2));
}

int init_enclave(sgx_arch_secs_t *secs, sha256 *sha)
{
    BIO *bio = BIO_new_mem_buf(RSA_PRIV_PEM, -1);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA)
    {
        printf("This key is not RSA.\n");
        EVP_PKEY_free(pkey);
        return -1;
    }

    sgx_measurement_t mrenclave;
    sha256_finalize_bytes(sha, &mrenclave);

    // Create and sign the sigstruct
    sgx_sigstruct_t sigstruct = {
        .header = DEFAULT_SIG_HEADER,
        .header2 = DEFAULT_SIG_HEADER2,
        .misc_mask = DEFAULT_SIG_MISC_MASK,
        .attribute_mask.flags = DEFAULT_SIG_ATTRIBUTE_FLAGS_MASK,
        .attribute_mask.xfrm = DEFAULT_SIG_ATTRIBUTE_XFRM_MASK,
        .enclave_hash = mrenclave,
        .attributes.flags = secs->attributes.flags,
        .attributes.xfrm = secs->attributes.xfrm,
        .misc_select = secs->misc_select,
        .exponent = 3,
    };

    uint8_t *signed_buffer = get_signing_data(&sigstruct);
    if (!signed_buffer)
    {
        fprintf(stderr, "Extract sigstruct content to sign failed!\n");
        return -1;
    }

    BIGNUM *n = NULL, *e = NULL;

    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e);
    unsigned long e_val = BN_get_word(e);
    if (e_val != 3)
    {
        fprintf(stderr, "public e should be 3!\n");
        goto sign_error;
    }

    unsigned char sig[384]; // 3072-bit RSA = 384 bytes
    size_t sig_len = 384;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0)
    {
        fprintf(stderr, "EVP_DigestSignInit Failed!\n");
        goto sign_error_md;
    }

    if (EVP_DigestSignUpdate(mdctx, signed_buffer, SGX_SIG_SIGNING_DATA_SIZE) <= 0)
    {
        fprintf(stderr, "EVP_DigestSignUpdate Failed!\n");
        goto sign_error_md;
    }

    if (EVP_DigestSignFinal(mdctx, sig, &sig_len) <= 0)
    {
        fprintf(stderr, "EVP_DigestSignFinal Failed!\n");
        goto sign_error_md;
    }

    EVP_MD_CTX_free(mdctx);

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *signature_bn = BN_bin2bn(sig, 384, NULL);
    BIGNUM *tmp1 = BN_new();
    BIGNUM *tmp2 = BN_new();
    BIGNUM *tmp3 = BN_new();
    BIGNUM *q1 = BN_new();
    BIGNUM *q2 = BN_new();

    BN_sqr(tmp1, signature_bn, ctx);
    BN_div(q1, tmp2, tmp1, n, ctx);
    BN_mul(tmp3, tmp2, signature_bn, ctx);
    BN_div(q2, tmp2, tmp3, n, ctx); // tmp2 is not used anymore, use it here for returning remainder
    bn_to_le_bytes(n, sigstruct.modulus, SE_KEY_SIZE);
    bn_to_le_bytes(signature_bn, sigstruct.signature, SE_KEY_SIZE);
    bn_to_le_bytes(q1, sigstruct.q1, SE_KEY_SIZE);
    bn_to_le_bytes(q2, sigstruct.q2, SE_KEY_SIZE);

    BN_free(tmp1);
    BN_free(tmp2);
    BN_free(tmp3);
    BN_free(q1);
    BN_free(q2);
    BN_free(signature_bn);
    BN_free(n);
    BN_free(e);
    BN_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    struct sgx_enclave_init param = {
        .sigstruct = (uint64_t)&sigstruct,
    };

    //print_sgx_sigstruct(&sigstruct);
    int ret = ioctl(teevisor_fd, SGX_IOC_ENCLAVE_INIT, &param);
    if (ret < 0)
    {
        fprintf(stderr, "Enclave initialization IOCTL failed: %s", strerror(errno));
        return ret;
    }

    if (ret)
    {
        const char *error;
        switch (ret)
        {
        case SGX_INVALID_SIG_STRUCT:
            error = "Invalid SIGSTRUCT";
            break;
        case SGX_INVALID_ATTRIBUTE:
            error = "Invalid enclave attribute";
            break;
        case SGX_INVALID_MEASUREMENT:
            error = "Invalid measurement";
            break;
        case SGX_INVALID_SIGNATURE:
            error = "Invalid signature";
            break;
        case SGX_INVALID_EINITTOKEN:
            error = "Invalid EINIT token";
            break;
        case SGX_INVALID_CPUSVN:
            error = "Invalid CPU SVN";
            break;
        default:
            error = "Unknown reason";
            break;
        }
        fprintf(stderr, "Enclave initialization IOCTL failed: %s", error);
        return -EPERM;
    }

    return 0;

sign_error_md:
    EVP_MD_CTX_free(mdctx);
sign_error:
    BN_free(n);
    BN_free(e);
    EVP_PKEY_free(pkey);
    return -1;
}

struct enclave *build_enclave(struct enclave_build_param *param)
{
    uint64_t count, tcs_mutex_count;
    uint64_t runtime_total_size;
    uint64_t handler_addr, runtime_entry_addr, user_entry_addr = 0;
    int ret;
    int runtime_fd = -1;
    int user_fd = -1;
    sgx_arch_secs_t enclave_secs;
    struct sha256 sha;
    size_t runtime_map_size, user_map_size = 0;
    struct enclave *encl = malloc(sizeof(struct enclave) + param->tcs_count * sizeof(struct tcs));

    if (!encl)
    {
        fprintf(stderr, "Cannot allocate memory for enclave instance!\n");
        return NULL;
    }

    if (!IS_ALIGNED(param->enclave_base, PAGE_SIZE) ||
        !IS_ALIGNED(param->enclave_base, PAGE_SIZE) ||
        !IS_ALIGNED(param->enclave_size, PAGE_SIZE) ||
        !IS_ALIGNED(param->user_base, PAGE_SIZE) ||
        !IS_ALIGNED(param->user_size, PAGE_SIZE) ||
        !IS_ALIGNED(param->runtime_base, PAGE_SIZE) ||
        !IS_ALIGNED(param->runtime_size, PAGE_SIZE) ||
        !IS_ALIGNED(param->runtime_thread_stack_size, PAGE_SIZE) ||
        !IS_ALIGNED(param->shared_memory_base, PAGE_SIZE) ||
        !IS_ALIGNED(param->shared_memory_size, PAGE_SIZE))
    {
        fprintf(stderr, "Alignment error in struct enclave_build_param!\n");
        return NULL;
    }

    if (!param->handler_symbol_name)
    {
        fprintf(stderr, "handler_symbol_name cannot be null!\n");
        return NULL;
    }

    if (!param->runtime_path)
    {
        fprintf(stderr, "runtime_path cannot be null!\n");
        return NULL;
    }

    if (!encl)
    {
        fprintf(stderr, "malloc failed: %s\n", strerror(errno));
        return NULL;
    }

    runtime_fd = open(param->runtime_path, O_RDONLY);
    if (runtime_fd == -1)
    {
        fprintf(stderr, "Cannot open runtime file at path '%s': %s\n",
                param->runtime_path, strerror(errno));
        goto free_enclave_layout;
    }

    runtime_entry_addr = get_elf_entry_addr(runtime_fd);
    if (runtime_entry_addr == UINT64_MAX)
    {
        fprintf(stderr, "Cannot get runtime entry addr\n");
        goto close_runtime_fd;
    }

    handler_addr = get_handler_addr(runtime_fd, param->handler_symbol_name);
    if (handler_addr == UINT64_MAX)
    {
        fprintf(stderr, "Cannot get runtime handler addr by the symbol\n");
        goto close_runtime_fd;
    }

    runtime_map_size = calculate_elf_memory_size(runtime_fd);

    if (!runtime_map_size)
    {
        fprintf(stderr, "Get runtime_map_size failed\n");
        goto close_runtime_fd;
    }

    runtime_total_size = ALIGN_UP(runtime_map_size, PAGE_SIZE) + param->tcs_count * PAGE_SIZE   // TCS total size
                         + param->tcs_count * PAGE_SIZE                                         // TLS total size
                         + param->nssa * param->tcs_count * param->ssa_frame_size * PAGE_SIZE   // SSA total size
                         + param->tcs_count * PAGE_SIZE                                         // USSA total size
                         + param->runtime_thread_stack_size * param->tcs_count + PAGE_SIZE * 5; // Guard page between each component.

    if (runtime_total_size > param->runtime_size)
    {
        fprintf(stderr, "Runtime total size (0x%lx) exceeds allocated runtime_size (0x%lx), overflow: 0x%lx bytes\n",
                runtime_total_size, param->runtime_size, runtime_total_size - param->runtime_size);
        goto close_runtime_fd;
    }

    if (param->user_path)
    {
        user_fd = open(param->user_path, O_RDONLY);
        if (user_fd == -1)
        {
            fprintf(stderr, "Cannot open user file at path '%s': %s\n",
                    param->user_path, strerror(errno));
            goto close_runtime_fd;
        }
        user_map_size = calculate_elf_memory_size(user_fd);
        if (user_map_size > param->user_size)
        {
            fprintf(stderr, "User map size (0x%lx) exceeds allocated user_size (0x%lx)\n",
                    user_map_size, param->user_size);
            goto close_user_fd;
        }

        if (!user_map_size)
        {
            fprintf(stderr, "Get user_map_size failed\n");
            goto close_user_fd;
        }

        user_entry_addr = get_elf_entry_addr(user_fd);
        if (user_entry_addr == UINT64_MAX)
        {
            goto close_user_fd;
        }
    }

    uint64_t shared_buffer_addr = (uint64_t)mmap((void *)param->shared_memory_base, param->shared_memory_size,
                                                 PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                                                 -1, 0);
    if (shared_buffer_addr == (uint64_t)MAP_FAILED)
    {
        fprintf(stderr, "mmap failed shared memory: %s\n", strerror(errno));
        goto close_user_fd;
    }

    if (shared_buffer_addr != param->shared_memory_base)
    {
        fprintf(stderr, "mmap returned wrong address: got 0x%lx, expected 0x%lx\n",
                shared_buffer_addr, param->shared_memory_base);
        goto munmap_shared_addr;
    }

    ret = open_teevisor_driver();
    if (ret < 0)
    {
        goto munmap_shared_addr;
    }

    memset(&enclave_secs, 0, sizeof(enclave_secs));
    enclave_secs.base = param->user_base;
    enclave_secs.size = param->user_size;
    enclave_secs.runtime_base = param->runtime_base;
    enclave_secs.runtime_size = param->runtime_size;
    enclave_secs.ssa_frame_size = param->ssa_frame_size;
    enclave_secs.misc_select = ENCLAVE_DEFAULT_EXITINFO;
    enclave_secs.attributes.flags = param->attributes_flags;
    enclave_secs.attributes.xfrm = param->attributes_xfrm;

    uint64_t enclave_addr = (uint64_t)mmap((void *)param->enclave_base, param->enclave_size,
                                           PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED_NOREPLACE | MAP_SHARED,
                                           teevisor_fd, 0);

    if (enclave_addr == (uint64_t)MAP_FAILED)
    {
        fprintf(stderr, "mmap failed enclave: %s\n", strerror(errno));
        goto close_file;
    }

    if (enclave_addr != param->enclave_base)
    {
        fprintf(stderr, "mmap returned wrong address: got 0x%lx, expected 0x%lx\n",
                enclave_addr, param->enclave_base);
        goto munmap_enclave_addr;
    }

    struct sgx_enclave_create secs_param = {
        .src = (uint64_t)&enclave_secs,
    };

    ret = ioctl(teevisor_fd, SGX_IOC_ENCLAVE_CREATE, &secs_param);

    if (ret < 0)
    {
        fprintf(stderr, "ioctl SGX_IOC_ENCLAVE_CREATE failed: %s\n", strerror(errno));
        goto munmap_enclave_addr;
    }

    // enclave_secs.attributes.flags |= SGX_FLAGS_INITIALIZED;

    /*
        -------------------        size
    -- runtime top ----
        ---- runtime_heap -----           runtime_base + runtime_size - runtime_heap_base
        ---- stack ----           runtime_thread_stack_size * tcs_count
        ---- guard ----           0x1000
        ---- ussa ----            tcs_count * ssa_frame_size * PAGE_SIZE
        ---- guard ----           0x1000
        ---- ssa -----            nssa * tcs_count * ssa_frame_size * PAGE_SIZE
        ---- guard ----           0x1000
        ---- tls -----            PAGE_SIZE * tcs_count
        ---- guard ----           0x1000
        ---- tcs -----            PAGE_SIZE * tcs_count
        ---- guard ----           0x1000
        -- runtime map --         ALIGN_UP(runtime_map_size)
    -- runtime base ----

    -- user top  -----
        -- user heap ---          user_base + user_size - user_heap_base
        -- user map ----          ALIGN_UP(user_map_size)
    -- user base -----
    */

    encl->enclave_base = param->enclave_base;
    encl->enclave_size = param->enclave_size;

    encl->user_base = param->user_base;
    encl->user_map_size = ALIGN_UP(user_map_size, PAGE_SIZE);
    encl->user_heap_base = encl->user_base + encl->user_map_size;
    encl->user_heap_size = param->user_base + param->user_size - encl->user_heap_base;
    encl->user_total_size = param->user_size;

    encl->runtime_base = param->runtime_base;
    encl->runtime_map_size = ALIGN_UP(runtime_map_size, PAGE_SIZE);
    encl->tcs_base = param->runtime_base + encl->runtime_map_size + PAGE_SIZE /*Guard Page */;
    encl->tcs_size = PAGE_SIZE * param->tcs_count;
    encl->tls_base = encl->tcs_base + encl->tcs_size + PAGE_SIZE /*Guard Page */;
    encl->tls_size = PAGE_SIZE * param->tcs_count;
    encl->ssa_base = encl->tls_base + encl->tls_size + PAGE_SIZE /*Guard Page */;
    encl->ssa_size = param->nssa * param->tcs_count * param->ssa_frame_size * PAGE_SIZE;
    encl->ussa_base = encl->ssa_base + encl->ssa_size + PAGE_SIZE /*Guard Page */;
    encl->ussa_size = param->ssa_frame_size * param->tcs_count * PAGE_SIZE;
    encl->stack_base = encl->ussa_base + encl->ussa_size + PAGE_SIZE /*Guard Page */;
    encl->stack_size = param->runtime_thread_stack_size * param->tcs_count;
    encl->runtime_heap_base = encl->stack_base + encl->stack_size;
    encl->runtime_heap_size = param->runtime_base + param->runtime_size - encl->runtime_heap_base;
    encl->runtime_total_size = param->runtime_size;
    encl->shared_memory_base = param->shared_memory_base;
    encl->shared_memory_size = param->shared_memory_size;
    encl->tcs_count = param->tcs_count;

    printf("Initialize tcs instances\n");
    for (tcs_mutex_count = 0; tcs_mutex_count < param->tcs_count; tcs_mutex_count++)
    {
        ret = pthread_mutex_init(&encl->tcs[tcs_mutex_count].mutex, NULL);
        if (ret)
        {
            fprintf(stderr, "mutex initialization: %s\n", strerror(errno));
            goto free_tcs_mutex;
        }
        encl->tcs[tcs_mutex_count].state = TCS_STATE_INACTIVE;
        encl->tcs[tcs_mutex_count].addr = encl->tcs_base + PAGE_SIZE * tcs_mutex_count;
    }
    // Add all the pages and create the sigstruct
    sha256_init(&sha);
    // ECREATE
    measure_ecreate(&sha, enclave_secs.ssa_frame_size, param->user_size + param->runtime_size);
    printf("measure_ecreate\n");
    // Add and measure the user elf
    if (user_fd != -1)
    {
        ret = add_elf(encl, user_fd, true, 0, &sha);
        if (ret)
        {
            goto free_tcs_mutex;
        }
    }
    printf("add_elf user fd\n");
    // Add user heap if has enough memory
    if (encl->user_heap_size)
    {
        void *user_heap_mmap = mmap(NULL, encl->user_heap_size, PROT_READ | PROT_WRITE,
                                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (user_heap_mmap == MAP_FAILED)
        {
            fprintf(stderr, "mmap user heap failed: %s\n", strerror(errno));
            goto free_tcs_mutex;
        }
        ret = add_pages(encl, user_heap_mmap, encl->user_heap_base, encl->user_heap_size, PROT_READ | PROT_WRITE | PROT_EXEC, SGX_PAGE_TYPE_REG, true, &sha);
        munmap(user_heap_mmap, encl->user_heap_size);

        if (ret)
        {
            goto free_tcs_mutex;
        }
    }
    printf("add user heap\n");

    // Add and measure the runtime elf
    ret = add_elf(encl, runtime_fd, false, handler_addr, &sha);
    if (ret)
    {
        goto free_tcs_mutex;
    }
    printf("add runtime elf\n");

    // Add tcs pages
    void *tcs_mmap = mmap(NULL, encl->tcs_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    if (tcs_mmap == MAP_FAILED)
    {
        fprintf(stderr, "mmap tcs failed: %s\n", strerror(errno));
        goto free_tcs_mutex;
    }

    for (count = 0; count < param->tcs_count; count++)
    {
        sgx_arch_tcs_t *tcs = (sgx_arch_tcs_t *)(tcs_mmap + PAGE_SIZE * count);
        memset(tcs, 0, PAGE_SIZE);
        tcs->ossa = encl->ssa_base - encl->user_base + param->nssa * param->ssa_frame_size * count * PAGE_SIZE;
        tcs->nssa = param->nssa;
        tcs->oentry = runtime_entry_addr + encl->runtime_base - encl->user_base;
        tcs->ofs_base = 0;
        tcs->ogs_base = encl->tls_base - encl->user_base + count * PAGE_SIZE; // Point to tls page
        tcs->ofs_limit = 0xfff;
        tcs->ogs_limit = 0xfff;
        tcs->oussa = encl->ussa_base - encl->user_base + param->ssa_frame_size * count * PAGE_SIZE;
    }

    ret = add_pages(encl, tcs_mmap, encl->tcs_base, encl->tcs_size, PROT_READ | PROT_WRITE, SGX_PAGE_TYPE_TCS, false, &sha);

    munmap(tcs_mmap, encl->tcs_size);

    if (ret)
    {
        goto free_tcs_mutex;
    }
    printf("add tcs\n");

    // Add tls pages
    void *tls_mmap = mmap(NULL, encl->tls_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (tls_mmap == MAP_FAILED)
    {
        fprintf(stderr, "mmap tls failed: %s\n", strerror(errno));
        goto free_tcs_mutex;
    }

    for (count = 0; count < param->tcs_count; count++)
    {
        enclave_tls *tls = (enclave_tls *)(tls_mmap + PAGE_SIZE * count);
        memset(tls, 0, PAGE_SIZE);
        tls->enclave_base = encl->enclave_base;
        tls->enclave_size = encl->enclave_size;
        tls->runtime_base = encl->runtime_base;
        tls->runtime_size = encl->runtime_total_size;
        tls->user_base = encl->user_base;
        tls->user_size = encl->user_total_size;

        tls->tcs_index = count;
        tls->ssa = encl->ssa_base + param->nssa * param->ssa_frame_size * PAGE_SIZE * count;
        tls->ussa = encl->ussa_base + param->ssa_frame_size * PAGE_SIZE * count;
        tls->nssa = param->nssa;
        tls->ssa_frame_size = param->ssa_frame_size;
        tls->gpr = (sgx_pal_gpr_t *)(tls->ssa + param->ssa_frame_size * PAGE_SIZE - sizeof(sgx_pal_gpr_t));
        tls->ugpr = (sgx_pal_gpr_t *)(tls->ussa + param->ssa_frame_size * PAGE_SIZE - sizeof(sgx_pal_gpr_t));
        tls->tcs_stack_addr = encl->stack_base + param->runtime_thread_stack_size * (count + 1); // Stack grows downwards
        tls->stack_size = param->runtime_thread_stack_size;
        tls->runtime_heap_base = encl->runtime_heap_base;
        tls->runtime_heap_size = encl->runtime_heap_size;
        tls->user_heap_base = encl->user_heap_base;
        tls->user_heap_size = encl->user_heap_size;
        tls->shared_memory_base = encl->shared_memory_base;
        tls->shared_memory_size = encl->shared_memory_size;

        tls->user_elf_exist = user_fd == -1 ? false : true;
        tls->user_entry = user_entry_addr;
    }

    ret = add_pages(encl, tls_mmap, encl->tls_base, encl->tls_size, PROT_READ | PROT_WRITE, SGX_PAGE_TYPE_REG, false, &sha);

    munmap(tls_mmap, encl->tls_size);

    if (ret)
    {
        goto free_tcs_mutex;
    }
    printf("add tls\n");

    // Add ssa pages
    void *ssa_mmap = mmap(NULL, encl->ssa_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (ssa_mmap == MAP_FAILED)
    {
        fprintf(stderr, "mmap ssa failed: %s\n", strerror(errno));
        goto free_tcs_mutex;
    }
    ret = add_pages(encl, ssa_mmap, encl->ssa_base, encl->ssa_size, PROT_READ | PROT_WRITE, SGX_PAGE_TYPE_REG, false, &sha);
    munmap(ssa_mmap, encl->ssa_size);

    if (ret)
    {
        goto free_tcs_mutex;
    }
    printf("add ssa\n");

    // Add ussa pages
    void *ussa_mmap = mmap(NULL, encl->ussa_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (ussa_mmap == MAP_FAILED)
    {
        fprintf(stderr, "mmap ussa failed: %s\n", strerror(errno));
        goto free_tcs_mutex;
    }
    ret = add_pages(encl, ussa_mmap, encl->ussa_base, encl->ussa_size, PROT_READ | PROT_WRITE, SGX_PAGE_TYPE_REG, false, &sha);
    munmap(ussa_mmap, encl->ussa_size);

    if (ret)
    {
        goto free_tcs_mutex;
    }
    printf("add ussa\n");

    // Add stack pages
    void *stack_mmap = mmap(NULL, encl->stack_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (stack_mmap == MAP_FAILED)
    {
        fprintf(stderr, "mmap stack failed: %s\n", strerror(errno));
        goto free_tcs_mutex;
    }
    ret = add_pages(encl, stack_mmap, encl->stack_base, encl->stack_size, PROT_READ | PROT_WRITE, SGX_PAGE_TYPE_REG, false, &sha);
    munmap(stack_mmap, encl->stack_size);

    if (ret)
    {
        goto free_tcs_mutex;
    }
    printf("add runtime stack\n");

    // Add runtime heap pages
    void *runtime_heap_mmap = mmap(NULL, encl->runtime_heap_size, PROT_READ | PROT_WRITE,
                                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (runtime_heap_mmap == MAP_FAILED)
    {
        fprintf(stderr, "mmap runtime heap failed: %s\n", strerror(errno));
        goto free_tcs_mutex;
    }
    ret = add_pages(encl, runtime_heap_mmap, encl->runtime_heap_base, encl->runtime_heap_size, PROT_READ | PROT_WRITE | PROT_EXEC, SGX_PAGE_TYPE_REG, true, &sha);
    munmap(runtime_heap_mmap, encl->runtime_heap_size);

    if (ret)
    {
        goto free_tcs_mutex;
    }
    printf("add runtime heap\n");

    // Create the sigstruct and then initialize the enclave
    ret = init_enclave(&enclave_secs, &sha);
    if (ret)
    {
        fprintf(stderr, "einit failed\n");
        goto free_tcs_mutex;
    }

    printf("Enclave created:\n");
    printf("    base:           0x%016lx\n", enclave_secs.base);
    printf("    size:           0x%016lx\n", enclave_secs.size);
    printf("    runtime_base:   0x%016lx\n", enclave_secs.runtime_base);
    printf("    runtime_size:   0x%016lx\n", enclave_secs.runtime_size);
    printf("    handler_base:   0x%016lx\n", handler_addr + enclave_secs.runtime_base);
    printf("    misc_select:    0x%08x\n", enclave_secs.misc_select);
    printf("    attr.flags:     0x%016lx\n", enclave_secs.attributes.flags);
    printf("    attr.xfrm:      0x%016lx\n", enclave_secs.attributes.xfrm);
    printf("    ssa_frame_size: %d\n", enclave_secs.ssa_frame_size);

    return encl;

free_tcs_mutex:
    for (uint64_t i = 0; i < tcs_mutex_count; i++)
    {
        pthread_mutex_destroy(&encl->tcs[i].mutex);
    }

munmap_enclave_addr:
    munmap((void *)enclave_addr, param->enclave_size);
close_file:
    close(teevisor_fd);
    teevisor_fd = -1;
munmap_shared_addr:
    munmap((void *)shared_buffer_addr, param->shared_memory_size);
close_user_fd:
    if (user_fd != -1)
    {
        close(user_fd);
    }
close_runtime_fd:
    close(runtime_fd);
free_enclave_layout:
    free(encl);
    return NULL;
}

int abort_enclave_clone()
{
    return ioctl(teevisor_fd, SGX_IOC_ENCLAVE_CLONE_ABORT);
}

int enclave_clone_bind(struct sgx_enclave_clone_metadata *clone_metadata)
{
    return ioctl(teevisor_fd, SGX_IOC_ENCLAVE_CLONE_BIND, clone_metadata);
}

int enclave_modify_type(struct sgx_enclave_modify_types *metadata)
{
     return ioctl(teevisor_fd, SGX_IOC_ENCLAVE_MODIFY_TYPES, metadata);
}

int is_clone_failed()
{
    return ioctl(teevisor_fd, SGX_IOC_ENCLAVE_CLONE_RESULT);
}
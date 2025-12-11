#ifndef ENCLAVE_H
#define ENCLAVE_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include "sgx_arch.h"
#include "enclave_runtime.h"
#include "sgx_user.h"
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <errno.h>
#include <ucontext.h>

#define __UNUSED(x) \
    do {            \
        (void)(x);  \
    } while (0)

#define PAGE_SIZE (0x1000)
#define IS_ALIGNED(val, alignment) ((val) % (alignment) == 0)
#define ALIGN_DOWN(val, alignment) ((val) - (val) % (alignment))
#define ALIGN_UP(val, alignment) ALIGN_DOWN((val) + (alignment) - 1, alignment)
#define ENCLAVE_DEFAULT_EXITINFO SGX_MISCSELECT_EXINFO
#define ENCLAVE_DEFAULT_ATTRIBUTE_FLAG SGX_FLAGS_MODE64BIT | SGX_FLAGS_RUNTIME
#define ENCLAVE_ATTRIBUTE_FLAG_CLONE SGX_FLAGS_MODE64BIT | SGX_FLAGS_RUNTIME | SGX_FLAGS_CLONE
#define ENCLAVE_DEFAULT_ATTRIBUTE_XFRM SGX_XFRM_LEGACY | SGX_XFRM_AVX

#ifndef SGX_INVALID_SIG_STRUCT
#define SGX_INVALID_SIG_STRUCT 1
#endif

#ifndef SGX_INVALID_ATTRIBUTE
#define SGX_INVALID_ATTRIBUTE 2
#endif

#ifndef SGX_INVALID_MEASUREMENT
#define SGX_INVALID_MEASUREMENT 4
#endif

#ifndef SGX_INVALID_SIGNATURE
#define SGX_INVALID_SIGNATURE 8
#endif

#ifndef SGX_INVALID_EINITTOKEN
#define SGX_INVALID_EINITTOKEN 16
#endif

#ifndef SGX_INVALID_CPUSVN
#define SGX_INVALID_CPUSVN 32
#endif

#define DEFAULT_SIG_VENDOR 0U
#define DEFAULT_SIG_SWDEFINED 0U

/* 32-bit masks */
#define DEFAULT_SIG_MISC_MASK 0xFFFFFFFFU

/* 64-bit masks */
#define DEFAULT_SIG_ATTRIBUTE_FLAGS_MASK UINT64_C(0xFFFFFFFFFFFFFFFF)
#define DEFAULT_SIG_ATTRIBUTE_XFRM_MASK UINT64_C(0xFFFFFFFFFFF9FF1B)

/* header (16 bytes) */
#define DEFAULT_SIG_HEADER { \
    0x06, 0x00, 0x00, 0x00,  \
    0xE1, 0x00, 0x00, 0x00,  \
    0x00, 0x00, 0x01, 0x00,  \
    0x00, 0x00, 0x00, 0x00}

/* header2 (16 bytes) */
#define DEFAULT_SIG_HEADER2 { \
    0x01, 0x01, 0x00, 0x00,   \
    0x60, 0x00, 0x00, 0x00,   \
    0x60, 0x00, 0x00, 0x00,   \
    0x01, 0x00, 0x00, 0x00}

#define RSA_PRIV_PEM                                                     \
    "-----BEGIN RSA PRIVATE KEY-----\n"                                  \
    "MIIG4gIBAAKCAYEAswq0KIpbHGcFXS/3SJ3sonmk8TCVBrpleXM8bw4hdtvmfzoa\n" \
    "eQC0diZCpTXp4k8nr8rgf/E767aHJuNC9QEClSrB7mCMN3M2tDC2CLiPefEfPwi+\n" \
    "19X0Cqs6LvNBvKWA1+9HfQOD7yryiyzpnbsk2WYThw+f65H8QA5A+mRYeCX8SL9u\n" \
    "XC/xt+Q/Zdn0ybwJA+YViWtuNtRoKJgj+sE8CnItO6uZZk7InY6n15WLA9m8e0AH\n" \
    "uxjpG+L3Dccsf3L/UGjdQV7jxZ1Oqgk4v9KkZIgmxXpxk2bON4yqDMfgKOijk5Vu\n" \
    "g+GKDFILoThcMkR8482h5OMLjFsrLoefToN2ipfR5yw96tpaQHHSdVohsWD+xsqB\n" \
    "iQ7wdNW9lCg0wh0gzsYdl0Y9IKeWXIXQW+iwF6IxJ6rHXlx1riPFxlI5Wqei2tBB\n" \
    "Ma4mSMlLwhrquxh9OZe5cGU06GYXfs7qTfnqBcEbUkgOti7COnEukWgVfO2eee08\n" \
    "hOBknTbgV1MOZ3KtAgEDAoIBgB3XHgbBudoRK4+H/owaUhsURigyw4EfEOmTNL0t\n" \
    "BZPPURU0Wb7Vc2kGYHDeUaW32/Kh0BVS31HzwTEl4H4q1cOHIFJlbLPoiR4IHlbJ\n" \
    "bT79hTUsH86jqKxx3wfTNZ9w6s6n4T+Alf0x0xcyJu+fMM7mWJaCmqdC/2ACYCm7\n" \
    "ZBQGVLbKkmSyqElQtTukU3b0rCtRA5bnPQkjZrFusKnK31cTB4nx7uZidsTtG/lD\n" \
    "lytO9L81Vp8u0YSl09ehMhU91PCZKbkMAyyUpZptqJZp1eGTzEUDo5eTrniQj7Nq\n" \
    "mLjnPdBU1EbtJ4h3X0y6HVYsBwUrXAmnObiHXgxw+Voszr1OT+8Q726vC/MUD9/k\n" \
    "oy0HoBtHALHOreCisHyOJDs93upxdrlGjdI+g6cDhVjuy1EQOnri0DnFV6OBzijS\n" \
    "LV2LHemlWarbg2l/r/CZfxFpVTlv6P7dLU9GO2y5iLA4DwghD0qiA9pm8W51Rwmx\n" \
    "zrj4kd1Dd2CbyTUiSBFr4U/LGwKBwQDiHG4TN7qFuViVjNQHRceOA94i2kz1WcS6\n" \
    "vT45sWJF9q+px6uCyzer73vvkpMPewSorbN1ri4ErnuH5a+h9xtg07jYgR8ghjfl\n" \
    "+E5cd+fN17htYIjre9rkwXaIMoA9aoGO+bnksxRgInRtQR38HnktyGCzrkOQJFPM\n" \
    "g7KgQMddXTCm1SAg4NZrlL5X6LcLDSFp/orTCuVAYcLYYwqy9WvoWJbZx7pYX+XJ\n" \
    "2p0q/Tl5nZBTyY04nYOV4y/ysb0gqaUCgcEAyrV0198WNGgUdepxMhHZjQ1/BIpP\n" \
    "EJbyqWwNnpbpjYaBB9DJV4dlLZZT5UkZHcFOHBvGNUmDNIB7W/wXj3+Cue45dEWC\n" \
    "MjnaqAEk2YZm1VuFtb/0crsCTEQkIKDbIT9lwSObWuvV0w4MBS+SSjFzA3hxkqui\n" \
    "c5gUDJU+MSRhzAe+uhsHD6g7ZDZtxpk5R5Ncdvm4pCs/zF7wGhKrebQj7KIouLQ9\n" \
    "P2Uz2dbnLEADrXyi9o7jCJwpyIX//BoJaAZpAoHBAJa9nrd6fFkmOw5d4q+D2l6t\n" \
    "PsHm3fjmgyco1CZ2QYP5ynEvx6yHenKfp/UMYgpSAxsed6PJdAMe/QVDymv6EkCN\n" \
    "JeWrahWuz+6liZL6mok6evOVsJz9PJiA+bAhqtOcVl9RJph3YurBovOAvqgUUMkw\n" \
    "QHfJgmAYN92tIcArL5OTdcSOFWtAjvJjKY/wegdeFkapseIHQ4BBLJBCByH48prl\n" \
    "ueaFJuWVQ9vnE3H+JlETtY0xCNBpAmPsyqHL02sbwwKBwQCHI6M6lLl4RWL5RvYh\n" \
    "YTuzXlStsYoLD0xw8rO/D0ZeWataizDlBO4eZDfuMLtpK4loEoQjhld4VaeSqA+0\n" \
    "/6x79CZNg6whe+caq23mWZnjklkj1U2h0gGILW1rFedrf5krbRI8nTk3XrKuH7bc\n" \
    "IPdXpaEMcmxNEA1duNQgwuvdWn8mvK9fxXzteZ6EZiYvt5L5+9BtciqIP0q8DHJR\n" \
    "IsKdwXB7ItN/mM075JodgAJzqGykX0IFvXEwWVVSvAZFWZsCgcBjQFYOUmzUwp93\n" \
    "y28smuY04HSTdY8xHqrda7hyXYX5lGwvpZKM02QNy73IhEivpDP2/yQXsE73lAtK\n" \
    "tt+afWIBzRMoEyQJpBZTqEHaIuggpzlMHA4Aj8DgauVR41Pi8v/MEZZv/Sh+Gtwu\n" \
    "ajD7bbPZSfyt8MDxKdW0uPrK4UD2gDepkux0tZuNnfHBJKyYpeabeyLMge/+n0mk\n" \
    "8xEBi78M+Fi80IuzYc/dpiaN1O/adqMyGqgChAsB/nVgTy6O4mc=\n"             \
    "-----END RSA PRIVATE KEY-----\n"

#define SGX_SIG_SIGNING_DATA_SIZE (256)

// The enclave is built with runtime enabled by default
struct enclave_build_param
{
    uint64_t enclave_base;
    uint64_t enclave_size;
    uint64_t user_base;
    uint64_t user_size;
    uint64_t runtime_base;
    uint64_t runtime_size;
    uint64_t runtime_thread_stack_size;
    uint64_t attributes_flags;
    uint64_t attributes_xfrm;
    uint64_t tcs_count;
    uint64_t nssa;           // nssa in tcs, exclude ussa
    uint64_t ssa_frame_size; // page number of each ssa
    uint64_t shared_memory_base;
    uint64_t shared_memory_size;
    char *runtime_path;        // The path of runtime code binary to run
    char *user_path;           // The path of program code binary to run
    char *handler_symbol_name; // Use to locate the symbol and add handler page
};

enum tcs_state
{
    TCS_STATE_INACTIVE = 0,
    TCS_STATE_ACTIVE = 1,
    TCS_STATE_TERMINATE = 2,
};


struct thread {
    char switch_stack[9 * 1024];
    ucontext_t saved_ctx;
    unsigned long fs_reg;
    unsigned long gs_reg;
    int self_pid;
};

struct tcs
{
    enum tcs_state state;
    uint64_t addr;
    pthread_mutex_t mutex;
    pthread_t thread;
    struct thread th;
};

struct enclave
{
    uint64_t enclave_base;
    uint64_t enclave_size;
    uint64_t user_base;
    uint64_t user_map_size;
    uint64_t user_heap_base;
    uint64_t user_heap_size;
    uint64_t user_total_size;
    uint64_t runtime_base;
    uint64_t runtime_map_size;
    uint64_t tcs_base;
    uint64_t tcs_size;
    uint64_t tls_base;
    uint64_t tls_size;
    uint64_t ssa_base;
    uint64_t ssa_size;
    uint64_t ussa_base;
    uint64_t ussa_size;
    uint64_t stack_base;
    uint64_t stack_size;
    uint64_t runtime_heap_base;
    uint64_t runtime_heap_size;
    uint64_t runtime_total_size;
    uint64_t shared_memory_base;
    uint64_t shared_memory_size;
    uint64_t tcs_count;
    struct tcs tcs[];
};

struct load_param
{
    uint64_t map_start;
    uint64_t map_end;
    uint64_t data_start;
    uint64_t data_end;
    uint64_t alloc_end;
    uint64_t map_offset;
    int prot;
};

#define EXIT_EEXIT  0
#define EXIT_SIGNAL 1

// Here we do not vdso to redirect to another address when signal received
// Signal handler is used instead of exception handler
struct enclave_run
{
    uint64_t function; // RAX, should be ERESUME or EENTER
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rdx;
    // uint64_t rcx; AEP used by the library
    uint64_t r8;
    uint64_t r9;
    struct tcs *tcs;
    // output rcx is aep
    // return 0 to end the execution
    int (*user_handler)(uint64_t rdi, uint64_t rsi, uint64_t rdx, struct enclave_run* run, uint64_t r8, uint64_t r9);
    uint64_t signal_mask;
    //void (*signal_handler)(int signum, siginfo_t *info, void *uc);
    int exit_reason;
    int signum;
};

#define EEXTEND_BLOCK_SIZE 256
#define ECREATE 0x0045544145524345ULL
#define EADD 0x0000000044444145ULL
#define EEXTEND 0x00444E4554584545ULL

struct ecreate_update
{
    uint64_t ecreate; // "ECREATE"
    uint32_t ssa_frame_size;
    uint64_t enclave_size;
    uint8_t reserved[44];
} __attribute__((packed));

struct eadd_update
{
    uint64_t eadd; // "EADD"
    uint64_t offset;
    uint64_t flags;
    uint8_t reserved[40];
} __attribute__((packed));

struct eextend_update
{
    uint64_t eextend; // "EEXTEND"
    uint64_t offset;
    uint8_t reserved[48];
} __attribute__((packed));

struct enclave *build_enclave(struct enclave_build_param *param);
int enter_enclave(struct enclave_run *run);
int abort_enclave_clone();
int enclave_clone_bind(struct sgx_enclave_clone_metadata *clone_metadata);
int enclave_modify_type(struct sgx_enclave_modify_types *metadata);
int is_clone_failed();
int prepare_fork(int64_t tcs_num, int efd);
int wait_for_fork(int efd);
int recreate_thread(struct tcs *tcs);
void tcs_terminate(struct tcs * tcs);
void wait_enclave_end(struct enclave *encl);
#endif
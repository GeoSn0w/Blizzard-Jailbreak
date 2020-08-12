#import <stdio.h>
#import <sys/types.h>
#import "../AMFI Utilities/cs_blob.h"

#define MACHO(p) ((*(unsigned int *)(p) & ~1) == 0xfeedface)

typedef char hash_t[20];

struct trust_chain {
    uint64_t next;
    unsigned char uuid[16];
    unsigned int count;
} __attribute__((packed));


void *load_bytes(FILE *file, off_t offset, size_t size);
int strtail(const char *str, const char *tail);
void getSHA256inplace(const uint8_t* code_dir, uint8_t *out);
uint8_t *getSHA256(const uint8_t* code_dir);
uint8_t *getCodeDirectory(const char* name);
uint64_t ubc_cs_blob_allocate(vm_size_t size);
void kern_free(uint64_t addr, vm_size_t size);
int cs_validate_csblob(const uint8_t *addr, size_t length, CS_CodeDirectory **rcd, CS_GenericBlob **rentitlements);
uint64_t getCodeSignatureLC(FILE *file, int64_t *machOff);
int addBinaryToAMFITrustCache(const char *path);
int amfiTrustHash(hash_t hash);
const struct cs_hash *cs_find_md(uint8_t type);

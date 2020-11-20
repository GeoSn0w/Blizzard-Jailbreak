//  Comes from Electra, adapted for FAT binary support by Jake James
//
//  amfi_utils.c
//  electra
//
//  Created by Jamie on 27/01/2018.
//  Copyright © 2018 Electra Team. All rights reserved.
//

#include "amfi_utils.h"
#include "kernel_utils.h"
#include "patchfinder64.h"
#include <stdlib.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <CommonCrypto/CommonDigest.h>
#include <Foundation/Foundation.h>
#include "../Kernel Utilities/kexecute.h"
#include "../Kernel Utilities/kernel_utils.h"
#include "../Exploits/sock_port/kernel_memory.h"
#include <sys/mman.h>

uint32_t swap_uint32( uint32_t val ) {
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF );
    return (val << 16) | (val >> 16);
}

uint32_t read_magic(FILE* file, off_t offset) {
    uint32_t magic;
    fseek(file, offset, SEEK_SET);
    fread(&magic, sizeof(uint32_t), 1, file);
    return magic;
}

void *load_bytes(FILE *file, off_t offset, size_t size) {
    void *buf = calloc(1, size);
    fseek(file, offset, SEEK_SET);
    fread(buf, size, 1, file);
    return buf;
}

void getSHA256inplace(const uint8_t* code_dir, uint8_t *out) {
    if (code_dir == NULL) {
        printf("AMFI TOOLS: NULL passed to getSHA256inplace!\n");
        return;
    }
    uint32_t* code_dir_int = (uint32_t*)code_dir;
    uint32_t realsize = 0;
    for (int j = 0; j < 10; j++) {
        if (swap_uint32(code_dir_int[j]) == 0xfade0c02) {
            realsize = swap_uint32(code_dir_int[j+1]);
            code_dir += 4*j;
        }
    }
    CC_SHA256(code_dir, realsize, out);
}

uint8_t *getSHA256(const uint8_t* code_dir) {
    uint8_t *out = malloc(CC_SHA256_DIGEST_LENGTH);
    getSHA256inplace(code_dir, out);
    return out;
}

uint8_t *getCodeDirectory(const char* name) {
    FILE* fd = fopen(name, "r");
    uint32_t magic;
    fread(&magic, sizeof(magic), 1, fd);
    fseek(fd, 0, SEEK_SET);
    long off = 0, file_off = 0;
    int ncmds = 0;
    BOOL foundarm64 = false;
    if (magic == MH_MAGIC_64) {
        struct mach_header_64 mh64;
        fread(&mh64, sizeof(mh64), 1, fd);
        off = sizeof(mh64);
        ncmds = mh64.ncmds;
    }
    else if (magic == MH_MAGIC) {
        printf("AMFI TOOLS: %s is 32bit. What are you doing here?\n", name);
        fclose(fd);
        return NULL;
    }
    else if (magic == 0xBEBAFECA) {
        size_t header_size = sizeof(struct fat_header);
        size_t arch_size = sizeof(struct fat_arch);
        size_t arch_off = header_size;
        struct fat_header *fat = (struct fat_header*)load_bytes(fd, 0, header_size);
        struct fat_arch *arch = (struct fat_arch *)load_bytes(fd, arch_off, arch_size);
        int n = swap_uint32(fat->nfat_arch);
        printf("AMFI TOOLS: Binary is FAT with %d architectures\n", n);
        while (n-- > 0) {
            magic = read_magic(fd, swap_uint32(arch->offset));
            if (magic == 0xFEEDFACF) {
                printf("AMFI TOOLS: Found arm64\n");
                foundarm64 = true;
                struct mach_header_64* mh64 = (struct mach_header_64*)load_bytes(fd, swap_uint32(arch->offset), sizeof(struct mach_header_64));
                file_off = swap_uint32(arch->offset);
                off = swap_uint32(arch->offset) + sizeof(struct mach_header_64);
                ncmds = mh64->ncmds;
                break;
            }
            arch_off += arch_size;
            arch = load_bytes(fd, arch_off, arch_size);
        }
        if (!foundarm64) {
            printf("AMFI TOOLS: No arm64? RIP\n");
            fclose(fd);
            return NULL;
        }
    }
    else {
        printf("AMFI TOOLS: %s is not a macho! (or has foreign endianness?) (magic: %x)\n", name, magic);
        fclose(fd);
        return NULL;
    }
    for (int i = 0; i < ncmds; i++) {
        struct load_command cmd;
        fseek(fd, off, SEEK_SET);
        fread(&cmd, sizeof(struct load_command), 1, fd);
        if (cmd.cmd == LC_CODE_SIGNATURE) {
            uint32_t off_cs;
            fread(&off_cs, sizeof(uint32_t), 1, fd);
            uint32_t size_cs;
            fread(&size_cs, sizeof(uint32_t), 1, fd);
            
            uint8_t *cd = malloc(size_cs);
            fseek(fd, off_cs + file_off, SEEK_SET);
            fread(cd, size_cs, 1, fd);
            fclose(fd);
            return cd;
        } else {
            off += cmd.cmdsize;
        }
    }
    fclose(fd);
    return NULL;
}

//from xerub
int strtail(const char *str, const char *tail)
{
    size_t lstr = strlen(str);
    size_t ltail = strlen(tail);
    if (ltail > lstr) {
        return -1;
    }
    str += lstr - ltail;
    return memcmp(str, tail, ltail);
}

int cs_validate_csblob(const uint8_t *addr, size_t length, CS_CodeDirectory **rcd, CS_GenericBlob **rentitlements) {
    uint64_t rcdptr = kalloc(sizeof(uint64_t));
    uint64_t entptr = kalloc(sizeof(uint64_t));
    
    int ret = (int)kexecute(Find_cs_validate_csblob(), (uint64_t)addr, length, rcdptr, entptr, 0, 0, 0);
    *rcd = (CS_CodeDirectory *)rk64(rcdptr);
    *rentitlements = (CS_GenericBlob *)rk64(entptr);
    
    kfree(rcdptr, sizeof(uint64_t));
    kfree(entptr, sizeof(uint64_t));
    
    return ret;
}

uint64_t ubc_cs_blob_allocate(vm_size_t size) {
    if (size <= 0x1ff8) {
        uint64_t size_p = kalloc(sizeof(vm_size_t));
        if (!size_p) return 0;
        kwrite(size_p, &size, sizeof(vm_size_t));
        
        uint64_t kall = Find_kalloc_canblock();
        if (!kall) return 0;
        
        uint64_t site = Find_cs_blob_allocate_site();
        if (!site) return 0;
        
        uint64_t alloced = kexecute(kall, size_p, 1, site, 0, 0, 0, 0);
        if (!alloced) return 0;
        
        kfree(size_p, sizeof(vm_size_t));
        alloced = ZmFixAddr(alloced);
        return alloced;
    }
    else {
        size = (size + 0x3fff) & ~0x3fff;
        
        uint64_t addrp = kalloc(sizeof(uint64_t));
        if (!addrp) return 0;
        
        uint64_t kernel_map = Find_kernel_map();
        if (!kernel_map) return 0;
        
        kernel_map = rk64(kernel_map);
        if (!kernel_map) return 0;
        
        uint64_t alloc = Find_kernel_memory_allocate();
        if (!alloc) return 0;
        
        kexecute(alloc, kernel_map, addrp, size, 0, 4, 17, 0);
        addrp = rk64(addrp);
        return addrp;
    }
}

void kern_free(uint64_t addr, vm_size_t size) {
    if (size > 0x1ff8) size = (size + 0x3fff) & ~0x3fff;
    kexecute(Find_kfree(), addr, size, 0, 0, 0, 0, 0);
}

const struct cs_hash *cs_find_md(uint8_t type) {
    return (struct cs_hash *)rk64(Find_cs_find_md() + ((type - 1) * 8));
}

uint64_t getCodeSignatureLC(FILE *file, int64_t *machOff) {
    size_t offset = 0;
    struct load_command *cmd = NULL;
    *machOff = -1;
    uint32_t *magic = load_bytes(file, offset, sizeof(uint32_t));
    int ncmds = 0;
    
    if (*magic != 0xFEEDFACF && *magic != 0xBEBAFECA) {
        printf("AMFI TOOLS: File is not an arm64 or FAT macho!\n");
        free(magic);
        return 0;
    }
    
    if(*magic == 0xBEBAFECA) {
        uint32_t arch_off = sizeof(struct fat_header);
        struct fat_header *fat = (struct fat_header*)load_bytes(file, 0, sizeof(struct fat_header));
        bool foundarm64 = false;
        int n = ntohl(fat->nfat_arch);
        printf("AMFI TOOLS: Binary is FAT with %d architectures\n", n);
        while (n-- > 0) {
            struct fat_arch *arch = (struct fat_arch *)load_bytes(file, arch_off, sizeof(struct fat_arch));
            if (ntohl(arch->cputype) == 0x100000c) {
                printf("AMFI TOOLS: Found arm64\n");
                offset = ntohl(arch->offset);
                foundarm64 = true;
                free(fat);
                free(arch);
                break;
            }
            free(arch);
            arch_off += sizeof(struct fat_arch);
        }
        if (!foundarm64) {
            printf("AMFI TOOLS: Binary does not have any arm64 slice\n");
            free(fat);
            free(magic);
            return 0;
        }
    }
    free(magic);
    *machOff = offset;
    struct mach_header_64 *mh64 = load_bytes(file, offset, sizeof(struct mach_header_64));
    ncmds = mh64->ncmds;
    free(mh64);
    offset += sizeof(struct mach_header_64);
    
    for (int i = 0; i < ncmds; i++) {
        cmd = load_bytes(file, offset, sizeof(struct load_command));
        if (cmd->cmd == LC_CODE_SIGNATURE) {
            free(cmd);
            return offset;
        }
        offset += cmd->cmdsize;
        free(cmd);
    }
    return 0;
}

int addBinaryToAMFITrustCache(const char *path) {
    NSMutableArray *paths = [NSMutableArray array];
    NSFileManager *fileManager = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if (![fileManager fileExistsAtPath:@(path) isDirectory:&isDir]) {
        printf("AMFI TRUST: Path does not exist!\n");
        return -1;
    }
    NSURL *directoryURL = [NSURL URLWithString:@(path)];
    NSArray *keys = [NSArray arrayWithObject:NSURLIsDirectoryKey];
    if (isDir) {
        NSDirectoryEnumerator *enumerator = [fileManager
                                             enumeratorAtURL:directoryURL
                                             includingPropertiesForKeys:keys
                                             options:0
                                             errorHandler:^(NSURL *url, NSError *error) {
                                                 if (error) printf("AMFI TRUST: %s\n", [[error localizedDescription] UTF8String]);
                                                 return YES;
                                             }];
        
        for (NSURL *url in enumerator) {
            NSError *error;
            NSNumber *isDirectory = nil;
            if (![url getResourceValue:&isDirectory forKey:NSURLIsDirectoryKey error:&error]) {
                if (error) continue;
            }
            else if (![isDirectory boolValue]) {
                int rv;
                int fd;
                uint8_t *p;
                off_t sz;
                struct stat st;
                uint8_t buf[16];
                char *fpath = strdup([[url path] UTF8String]);
                if (strtail(fpath, ".plist") == 0 || strtail(fpath, ".nib") == 0 || strtail(fpath, ".strings") == 0 || strtail(fpath, ".png") == 0) {
                    continue;
                }
                rv = lstat(fpath, &st);
                if (rv || !S_ISREG(st.st_mode) || st.st_size < 0x4000) {
                    continue;
                }
                fd = open(fpath, O_RDONLY);
                if (fd < 0) {
                    continue;
                }
                sz = read(fd, buf, sizeof(buf));
                if (sz != sizeof(buf)) {
                    close(fd);
                    continue;
                }
                if (*(uint32_t *)buf != 0xBEBAFECA && !MACHO(buf)) {
                    close(fd);
                    continue;
                }
                p = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
                if (p == MAP_FAILED) {
                    close(fd);
                    continue;
                }
                [paths addObject:@(fpath)];
                printf("AMFI TRUST: ADDING TO TRUST CACHE %s\n", fpath);
                free(fpath);
            }
        }
        if ([paths count] == 0) {
            printf("AMFI TRUST: No files in %s passed the integrity checks!\n", path);
            return -2;
        }
    }
    else {
        printf("AMFI TRUST: ADDING TO TRUST CACHE %s\n", path);
        [paths addObject:@(path)];
        int rv;
        int fd;
        uint8_t *p;
        off_t sz;
        struct stat st;
        uint8_t buf[16];
        
        if (strtail(path, ".plist") == 0 || strtail(path, ".nib") == 0 || strtail(path, ".strings") == 0 || strtail(path, ".png") == 0) {
            printf("AMFI TRUST Binary not an executable! Kernel doesn't like trusting data, geez\n");
            return 2;
        }
        
        rv = lstat(path, &st);
        if (rv || !S_ISREG(st.st_mode) || st.st_size < 0x4000) {
            printf("AMFI TRUST Binary too big\n");
            return 3;
        }
        
        fd = open(path, O_RDONLY);
        if (fd < 0) {
            printf("AMFI TRUST Don't have permission to open file\n");
            return 4;
        }
        
        sz = read(fd, buf, sizeof(buf));
        if (sz != sizeof(buf)) {
            close(fd);
            printf("AMFI TRUST Failed to read from binary\n");
            return 5;
        }
        if (*(uint32_t *)buf != 0xBEBAFECA && !MACHO(buf)) {
            close(fd);
            printf("AMFI TRUST Binary not a macho!\n");
            return 6;
        }
        
        p = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (p == MAP_FAILED) {
            close(fd);
            printf("AMFI TRUST Failed to mmap file\n");
            return 7;
        }
    }
    uint64_t trust_chain = Find_trustcache();
    printf("AMFI TRUST trust_chain at 0x%llx\n", trust_chain);
    struct trust_chain fake_chain;
    fake_chain.next = rk64(trust_chain);
    arc4random_buf(fake_chain.uuid, 16);
    int cnt = 0;
    uint8_t hash[CC_SHA256_DIGEST_LENGTH];
    hash_t *allhash = malloc(sizeof(hash_t) * [paths count]);
    for (int i = 0; i != [paths count]; ++i) {
        uint8_t *cd = getCodeDirectory((char*)[[paths objectAtIndex:i] UTF8String]);
        if (cd != NULL) {
            getSHA256inplace(cd, hash);
            memmove(allhash[cnt], hash, sizeof(hash_t));
            ++cnt;
        }
        else {
            printf("AMFI TRUST CD NULL\n");
            continue;
        }
    }
    fake_chain.count = cnt;
    size_t length = (sizeof(fake_chain) + cnt * sizeof(hash_t) + 0x3FFF) & ~0x3FFF;
    uint64_t kernel_trust = kalloc(length);
    printf("AMFI TRUST allocated: 0x%zx => 0x%llx\n", length, kernel_trust);
    kwrite(kernel_trust, &fake_chain, sizeof(fake_chain));
    kwrite(kernel_trust + sizeof(fake_chain), allhash, cnt * sizeof(hash_t));
#if __arm64e__
    Kernel_Execute(Find_pmap_load_trust_cache_ppl(), kernel_trust, length, 0, 0, 0, 0, 0);
#else
    wk64(trust_chain, kernel_trust);
#endif
    free(allhash);
    return 0;
}

int amfiTrustHash(hash_t hash) {
    uint64_t trust_chain = Find_trustcache();
    printf("AMFI TRUST trust_chain at 0x%llx\n", trust_chain);
    struct trust_chain fake_chain;
    fake_chain.next = rk64(trust_chain);
    arc4random_buf(fake_chain.uuid, 16);
    fake_chain.count = 1;
    size_t length = (sizeof(fake_chain) + sizeof(hash_t) + 0x3FFF) & ~0x3FFF;
    uint64_t kernel_trust = kalloc(length);
    printf("AMFI TRUST allocated: 0x%zx => 0x%llx\n", length, kernel_trust);
    kwrite(kernel_trust, &fake_chain, sizeof(fake_chain));
    kwrite(kernel_trust + sizeof(fake_chain), hash, sizeof(hash_t));
#if __arm64e__
    kexecute(Find_pmap_load_trust_cache_ppl(), kernel_trust, length, 0, 0, 0, 0, 0);
#else
    wk64(trust_chain, kernel_trust);
#endif
    return 0;
}

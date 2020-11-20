//
//  kernelSymbolFinder.c
//  KernelSymbolFinder
//
//  Created by Jake James on 8/21/18.
//  Copyright © 2018 Jake James. All rights reserved.
//

#include "kernSymbolication.h"
#include "../Kernel Utilities/lzssdec.hpp"
#define SWAP32(p) __builtin_bswap32(p)

static FILE *file;
uint32_t offset = 0;

static void *load_bytes(FILE *obj_file, off_t offset, uint32_t size) {
    void *buf = calloc(1, size);
    fseek(obj_file, offset, SEEK_SET);
    fread(buf, size, 1, obj_file);
    return buf;
}

uint64_t find_symbol(const char *symbol, bool verbose) {
    uint64_t addr = 0;
    size_t offset = 0;
    size_t sym_offset = 0;
    int ncmds = 0;
    struct load_command *cmd = NULL;
    uint32_t *magic = load_bytes(file, offset, sizeof(uint32_t)); //at offset 0 we have the magic number
    if (verbose) printf("SymbolFinder: MAGIC = 0x%x\n", *magic);
    if (*magic == 0xFEEDFACF) {
        if (verbose) printf("SymbolFinder: 64bit binary\n");
        struct mach_header_64 *mh64 = load_bytes(file, offset, sizeof(struct mach_header_64));
        ncmds = mh64->ncmds;
        free(mh64);
        offset += sizeof(struct mach_header_64);
        if (verbose) printf("SymbolFinder: %d LOAD COMMANDS\n", ncmds);
        for (int i = 0; i < ncmds; i++) {
            cmd = load_bytes(file, offset, sizeof(struct load_command));
            if (verbose) printf("SymbolFinder: LOAD COMMAND %d = 0x%x\n", i, cmd->cmd);
            if (cmd->cmd == LC_SYMTAB) {
                if (verbose) printf("SymbolFinder: Found LC_SYMTAB command!\n");
                struct symtab_command *symtab = load_bytes(file, offset, cmd->cmdsize);
                if (verbose) printf("\t %d symbols\n", symtab->nsyms);
                if (verbose) printf("\t Symbol table at 0x%x\n", symtab->symoff);
                for (int i = 0; i < symtab->nsyms; i++) {
                    struct symbol *sym = load_bytes(file, symtab->symoff + sym_offset, sizeof(struct symbol));
                    int symlen = 0;
                    int sym_str_addr = sym->table_index + symtab->stroff;
                    uint8_t *byte = load_bytes(file, sym_str_addr+symlen, 1);
                    while (*byte != 0) {
                        free(byte);
                        symlen++;
                        byte = load_bytes(file, sym_str_addr+symlen, 1);
                    }
                    free(byte);
                    char *sym_name = load_bytes(file, sym_str_addr, symlen + 1);
                    if (verbose) printf("\t%s: 0x%llx\n", sym_name, sym->address);
                    if (!strcmp(sym_name, symbol)) {
                        addr = sym->address;
                        if (!verbose) return addr;
                    }
                    free(sym_name);
                    sym_offset += sizeof(struct symbol);
                    free(sym);
                }
                free(symtab);
                free(cmd);
                break;
            }
            offset += cmd->cmdsize;
            free(cmd);
        }
    }
    else if (*magic == 0xFEEDFACE){
        if (verbose) printf("SymbolFinder: Got 32bit binary\n");
        struct mach_header *mh = load_bytes(file, offset, sizeof(struct mach_header));
        ncmds = mh->ncmds;
        free(mh);
        offset += sizeof(struct mach_header);
        if (verbose) printf("SymbolFinder: %d LOAD COMMANDS\n", ncmds);
        for (int i = 0; i < ncmds; i++) {
            cmd = load_bytes(file, offset, sizeof(struct load_command));
            if (verbose) printf("SymbolFinder: LOAD COMMAND %d = 0x%x\n", i, cmd->cmd);
            offset += cmd->cmdsize;
            if (cmd->cmd == LC_SYMTAB) {
                if (verbose) printf("SymbolFinder: Found LC_SYMTAB command!\n");
                struct symtab_command *symtab = load_bytes(file, offset, cmd->cmdsize);
                if (verbose) printf("\t %d symbols\n", symtab->nsyms);
                if (verbose) printf("\t Symbol table at 0x%x\n", symtab->symoff);
                for (int i = 0; i < symtab->nsyms; i++) {
                    struct symbol *sym = load_bytes(file, symtab->symoff + sym_offset, sizeof(struct symbol));
                    int symlen = 0;
                    int sym_str_addr = sym->table_index + symtab->stroff;
                    uint8_t *byte = load_bytes(file, sym_str_addr+symlen, 1);
                    
                    while (*byte != 0) {
                        free(byte);
                        symlen++;
                        byte = load_bytes(file, sym_str_addr+symlen, 1);
                    }
                    free(byte);
                    char *sym_name = load_bytes(file, sym_str_addr, symlen + 1);
                    if (verbose) printf("\t%s: 0x%llx\n", sym_name, sym->address);
                    if (!strcmp(sym_name, symbol)) {
                        addr = sym->address;
                        if (!verbose) return addr;
                    }
                    free(sym_name);
                    sym_offset += sizeof(struct symbol);
                    free(sym);
                }
                free(symtab);
                free(cmd);
                break;
            }
            offset += cmd->cmdsize;
            free(cmd);
        }
    }
    else {
        if (verbose) printf("[!] Unrecognized file\n");
        return -1;
    }
    return addr;
}

uint32_t find_macho_header() {
    uint32_t off = 0;
    uint32_t *magic = load_bytes(file, off, sizeof(uint32_t));
    while ((*magic & ~1) != 0xFEEDFACE) {
        off++;
        magic = load_bytes(file, off, sizeof(uint32_t));
    }
    return off - 1;
}

int decompressKernelCache(const char *kernelcache) {
    file = fopen(kernelcache, "rb");
    offset = find_macho_header();
    if (!offset) {
        printf("SymbolFinder: offset = 0; This is not a Mach-O Binary!\n");
        return -1;
    }
    printf("SymbolFinder: Mach-o header at 0x%X\n", offset);
    char strOff[128];
    sprintf(strOff, "0x%X", offset);
    char *args[5] = { strdup("lzssdec"), strdup("-o"), strdup(strOff), strdup(kernelcache), strcat(strdup(kernelcache), ".dec")};
    
    if (lzssdec(5, (char **)args)) {
        printf("SymbolFinder: Failed to decompress the Kernel!\n");
        return -1;
    }
    else printf("SymbolFinder: Successfully decompressed the KernelCache!\n");
    fclose(file);
    file = fopen(strcat(strdup(kernelcache), ".dec"), "rb");
    return 0;
}

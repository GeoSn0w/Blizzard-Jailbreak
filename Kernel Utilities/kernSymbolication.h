//
//  kernSymbolication.h
//  Blizzard Jailbreak
//
//  Created by GeoSn0w on 8/11/20.
//  Copyright © 2020 GeoSn0w. All rights reserved.
//

#ifndef kernSymbolication_h
#define kernSymbolication_h

#import <unistd.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <stdbool.h>
#import <mach-o/loader.h>
#import <mach-o/swap.h>


// dunno if the built-in headers have something like this but I couldn't find any so DIY :)
struct symbol {
    uint32_t table_index;
    uint8_t type;
    uint8_t section_index;
    uint16_t description;
    uint64_t address;
};

uint32_t find_macho_header(void);
uint64_t find_symbol(const char *symbol, bool verbose);
int decompressKernelCache(const char *kernelcache);
#endif /* kernSymbolication_h */

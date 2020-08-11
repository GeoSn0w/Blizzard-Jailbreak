// Based on tihmstar's liboffsetfinder64 which is open source here:
// https://github.com/tihmstar/liboffsetfinder64
// Also Coolstar's implementation from Electra.

#include <stdint.h>
#include <stdio.h>
#include "rootfs_remount.h"
#include "liboffsetfinder64.hpp"

using namespace std;
using namespace tihmstar;

extern "C" uint64_t offset_vfs_context_current;
extern "C" uint64_t offset_vnode_lookup;
extern "C" uint64_t offset_vnode_put;

extern "C" bool offsetizeRN(uint64_t slide){
    printf("Initializing OffsetFinder...\n");
    offsetfinder64 fi("/System/Library/Caches/com.apple.kernelcaches/kernelcache");
   
    try {
        offset_vfs_context_current = (uint64_t)fi.find_sym("_vfs_context_current");
        offset_vnode_lookup = (uint64_t)fi.find_sym("_vnode_lookup");
        offset_vnode_put = (uint64_t)fi.find_sym("_vnode_put");
        
        printf("    Offsetfinder: GOT: vfs_context_current: %p\n", (void *)offset_vfs_context_current);
        printf("    Offsetfinder: GOT: vnode_lookup: %p\n", (void *)offset_vnode_lookup);
        printf("    Offsetfinder: GOT: vnode_put: %p\n", (void *)offset_vnode_put);
        
        offset_vfs_context_current += slide;
        offset_vnode_lookup += slide;
        offset_vnode_put += slide;
        printf("OffsetFinder: The OffsetFinder ran successfully! Continuing...\n");
        return true;
    } catch (tihmstar::exception &e){
        printf("OffsetFinder: The OffsetFinder has failed! Aborting... %d (%s)\n", e.code(), e.what());
        return false;
    } catch (std::exception &e){
        printf("OffsetFinder: Could not properly initialize the OffsetFinder! %s\n", e.what());
        return false;
    }
}

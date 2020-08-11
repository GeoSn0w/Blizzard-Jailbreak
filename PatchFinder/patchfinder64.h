#ifndef PATCHFINDER64_H_
#define PATCHFINDER64_H_

int initializePatchFinderWithBase(uint64_t base, const char *filename);
void terminatePatchFinder(void);

uint64_t find_allproc(void);
uint64_t find_add_x0_x0_0x40_ret(void);
uint64_t find_copyout(void);
uint64_t find_bzero(void);
uint64_t find_bcopy(void);
uint64_t find_rootvnode(void);
uint64_t find_trustcache(void);
uint64_t find_amficache(void);
uint64_t find_realhost(void);
uint64_t find_zone_map_ref(void);
uint64_t find_zone_map(void);

#endif

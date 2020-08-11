//
//  rootfs_remount.h
//  electra1131
//
//  Created by CoolStar on 6/7/18.
//  Copyright © 2018 CoolStar. All rights reserved.
//

#ifndef rootfs_remount_h
#define rootfs_remount_h
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <copyfile.h>

int file_exists(const char *filename);
#define cp(to, from) copyfile(from, to, 0, COPYFILE_ALL)
#ifdef __cplusplus
extern "C" {
#endif
extern int shouldReboot;
int remountRootFS(void);
int unjailbreakBlizzard(void);
#ifdef __cplusplus
}
#endif

#endif /* rootfs_remount_h */

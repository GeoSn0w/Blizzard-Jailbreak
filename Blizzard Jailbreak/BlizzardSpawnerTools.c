//
//  BlizzardSpawnerTools.c
//  Blizzard Jailbreak
//
//  Created by GeoSn0w on 8/11/20.
//  Copyright © 2020 GeoSn0w. All rights reserved.
//

#include "BlizzardSpawnerTools.h"
#import <string.h>
#import <stdlib.h>
#import <stdio.h>
#import <unistd.h>
#import <spawn.h>
#import <sys/mman.h>
#import <sys/attr.h>
#import <mach/mach.h>
#import <sys/types.h>
#import <CommonCrypto/CommonDigest.h>

int launchProcessFrozen(char *whom, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5, char *arg6, char**env) {
    const char* args[] = {whom, arg1, arg2, arg3, arg4, arg5, arg6, NULL};
    pid_t process_pid;
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
    int returnValue = posix_spawn(&process_pid, whom, NULL, &attr, (char **)&args, env);
    
    if (returnValue) {
        return returnValue;
    } else {
        return process_pid;
    }
}

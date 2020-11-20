//
//  blizzardJailbreak.h
//
//  Created by GeoSn0w on 8/10/20.
//  Copyright © 2020 GeoSn0w. All rights reserved.
//

#ifndef blizzardJailbreak_h
#define blizzardJailbreak_h

#include <stdio.h>
extern mach_port_t tfp0;
void remountFirstStepSys(void);
int ios11_exploit_init(void);
int rootifyOurselves(void);
int rootifyProcessByPid(void);
int restoreProcessCredentials(uint64_t creds, pid_t pid);
int obtainAPFSSnapshotsList(void);
int remountFileSystem(void);
int setcsflags(pid_t pid);
int prepareKernelForPatchFinder(void);
int cleanupAfterBlizzard(void);
int installBootStrap(void);
uint64_t findOurOwnProcess(void);
uint64_t escapeSandboxForProcess(pid_t proc_pid);
uint64_t copyPIDCredentials(pid_t processToBeGivenCreds, pid_t donorProcess);
#endif /* blizzardJailbreak_h */

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

int exploit_init(void);
int rootifyOurselves(void);
int rootifyProcessByPid(void);
int restoreProcessCredentials(uint64_t creds, pid_t pid);
uint64_t findOurOwnProcess(void);
uint64_t escapeSandboxForProcess(pid_t proc_pid);

#endif /* blizzardJailbreak_h */

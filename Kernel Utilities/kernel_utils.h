#ifndef kernUtils_h
#define kernUtils_h
#import <stdio.h>
#import <mach-o/loader.h>
#import <stdlib.h>
#import <fcntl.h>
#import <unistd.h>
#import <errno.h>
#import <mach/mach.h>
#import <sys/stat.h>
#include <stdbool.h>

// Needed definitions
kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
kern_return_t mach_vm_deallocate(vm_map_t target, mach_vm_address_t address, mach_vm_size_t size);
kern_return_t mach_vm_protect (vm_map_t target_task, mach_vm_address_t address,  mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
kern_return_t mach_vm_read(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt);
kern_return_t mach_vm_region(vm_map_t target_task, mach_vm_address_t *address, mach_vm_size_t *size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t *infoCnt, mach_port_t *object_name);

bool PatchHostPriv(mach_port_t host);
// init function
void init_kernel_utils(mach_port_t tfp0);

// utils
uint64_t TaskSelfAddr(void);
uint64_t IPCSpaceKernel(void);
uint64_t FindPortAddress(mach_port_name_t port);
mach_port_t FakeHostPriv(void);
void convertPortToTaskPort(mach_port_t port, uint64_t space, uint64_t task_kaddr);
void MakePortFakeTaskPort(mach_port_t port, uint64_t task_kaddr);
int Kernel_strcmp(uint64_t kstr, const char* str);

// for messing with processes
uint64_t proc_of_pid(pid_t pid);
uint64_t proc_of_procName(char *nm);
unsigned int pid_of_procName(char *nm);
uint64_t taskStruct_of_pid(pid_t pid);
uint64_t taskStruct_of_procName(char *nm);
uint64_t taskPortKaddr_of_pid(pid_t pid);
uint64_t taskPortKaddr_of_procName(char *nm);
mach_port_t task_for_pid_in_kernel(pid_t pid);

// used to fix what kexecute returns
typedef struct {
    uint64_t prev;
    uint64_t next;
    uint64_t start;
    uint64_t end;
} kmap_hdr_t;
uint64_t ZmFixAddr(uint64_t addr);

uint64_t grabKernelBase(void);
#endif

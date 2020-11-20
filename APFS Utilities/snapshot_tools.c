#import "../Kernel Utilities/kernel_utils.h"
#import "../PatchFinder/patchfinder64.h"
#import "../Exploits/sock_port/offsetof.h"
#import "../Exploits/sock_port/offsets.h"
#import <sys/snapshot.h>
#include "../Exploits/sock_port/include/IOKit/IOKitLib.h"
#import <stdlib.h>
#import <signal.h>
#import <sys/attr.h>
#include "snapshot_tools.h"
#include "../Blizzard Jailbreak/BlizzardSpawnerTools.h"
#include "../Blizzard Jailbreak/blizzardJailbreak.h"

typedef struct val_attrs {
    uint32_t          length;
    attribute_set_t   returned;
    attrreference_t   name_info;
} val_attrs_t;

int list_snapshots(const char *vol){
    int dirfd = open(vol, O_RDONLY, 0);
    if (dirfd < 0) {
        perror("get_dirfd");
        printf("List Snapshots: Failed to open file descriptor!\n");
        return -1;
    }
    struct attrlist alist = { 0 };
    char abuf[2048];
    alist.commonattr = ATTR_BULK_REQUIRED;
    int count = fs_snapshot_list(dirfd, &alist, &abuf[0], sizeof (abuf), 0);
    if (count < 0) {
        perror("fs_snapshot_list");
        printf("List Snapshots: Failed to list Snapshots!\n");
        return -1;
    }
    char *p = &abuf[0];
    for (int i = 0; i < count; i++) {
        char *field = p;
        uint32_t len = *(uint32_t *)field;
        field += sizeof (uint32_t);
        attribute_set_t attrs = *(attribute_set_t *)field;
        field += sizeof (attribute_set_t);
        
        if (attrs.commonattr & ATTR_CMN_NAME) {
            attrreference_t ar = *(attrreference_t *)field;
            char *name = field + ar.attr_dataoffset;
            field += sizeof (attrreference_t);
            (void) printf("\t ->> %s\n", name);
        }
        
        p += len;
    }
    return (0);
}

char *copyBootHash() {
    io_registry_entry_t chosen = IORegistryEntryFromPath(kIOMasterPortDefault, "IODeviceTree:/chosen");
    unsigned char buf[1024];
    uint32_t size = 1024;
    char *hash;
    if (chosen && chosen != -1) {
        kern_return_t ret = IORegistryEntryGetProperty(chosen, "boot-manifest-hash", (char*)buf, &size);
        IOObjectRelease(chosen);
        if (ret) {
            printf("List Snapshots: Unable to read boot-manifest-hash\n");
            hash = NULL;
        }
        else {
            char *result = (char*)malloc((2 * size) | 1);
            memset(result, 0, (2 * size) | 1);
            
            int i = 0;
            while (i < size) {
                unsigned char ch = buf[i];
                sprintf(result + 2 * i++, "%02X", ch);
            }
            printf("List Snapshots: Hash: %s\n", result);
            hash = strdup(result);
        }
    }
    else {
        printf("List Snapshots: Unable to get IODeviceTree:/chosen port\n");
        hash = NULL;
    }
    return hash;
}

char *find_system_snapshot() {
    const char *hash = copyBootHash();
    size_t len = strlen(hash);
    char *str = (char*)malloc(len + 29);
    memset(str, 0, len + 29);
    if (!hash) return 0;
    sprintf(str, "com.apple.os.update-%s", hash);
    printf("List Snapshots: System snapshot: %s\n", str);
    return str;
}

int createNewAPFSSnapshot(const char *volume, const char *snapshot) {
    int retvalue;
    printf("APFS Utilities: Preparing to create a new Snapshot...\n");
    int fileDescriptor = get_dirfd(volume);
    if (fileDescriptor < 0) {
        perror("open");
        printf("APFS Utilities: Failed to create a Snapshot! Error at get_dirfd.\n");
        return -1;
    }
    retvalue = fs_snapshot_create(fileDescriptor, snapshot, 0);
    close(fileDescriptor);
    if (retvalue != 0) {
        perror("fs_snapshot_create");
        printf("APFS Utilities: Failed to create a Snapshot! Error at fs_snapshot_create()\n");
        return -1;
    }
    return 0;
}

int renameAPFSSnapshot(const char *volume, const char *snapshot, const char *nw) {
    int retvalue;
    int fileDescriptor = open(volume, O_RDONLY);
    if (fileDescriptor < 0) {
        perror("open");
        printf("APFS Utilities: RENAME: Cannot open file descriptor.\n");
        return -1;
    }
    retvalue = fs_snapshot_rename(fileDescriptor, snapshot, nw, 0);
    close(fileDescriptor);
    if (retvalue != 0) {
        perror("fs_snapshot_rename\n");
        printf("APFS Utilities: RENAME: Failed to rename a Snapshot! Error at fs_snapshot_rename()\n");
    }
    return 0;
}

int verifySnapshot(const char *vol, const char *name){
    struct attrlist attr_list = { 0 };
    attr_list.commonattr = ATTR_BULK_REQUIRED;
    char *buf = (char*)calloc(2048, sizeof(char));
    int retcount;
    int fd = open(vol, O_RDONLY, 0);
    while ((retcount = fs_snapshot_list(fd, &attr_list, buf, 2048, 0))>0) {
        char *bufref = buf;
        for (int i=0; i<retcount; i++) {
            val_attrs_t *entry = (val_attrs_t *)bufref;
            if (entry->returned.commonattr & ATTR_CMN_NAME) {
                printf("%s\n", (char*)(&entry->name_info) + entry->name_info.attr_dataoffset);
                if (strstr((char*)(&entry->name_info) + entry->name_info.attr_dataoffset, name)){
                    return 1;
                }
            }
            bufref += entry->length;
        }
    }
    free(buf);
    close(fd);
    
    if (retcount < 0) {
        perror("fs_snapshot_list");
        printf("List Snapshots: Failed to list snapshots!\n");
        return -1;
    }
    return 0;
}

int mountSnapshot(const char *vol, const char *name, const char *dir) {
    int proces_pid;
    proces_pid = launchProcessFrozen("/sbin/mount_apfs", "-s", (char *)name, (char *)vol, (char *)dir, NULL, NULL, NULL);
    copyPIDCredentials(proces_pid, 0);
    kill(proces_pid, SIGCONT);
    int a;
    if (proces_pid != -1) waitpid(proces_pid, &a, 0);
    return WEXITSTATUS(a);
}

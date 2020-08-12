#ifndef apfs_util_h
#define apfs_util_h

#define get_dirfd(vol) open(vol, O_RDONLY, 0)

char *find_snapshot_with_ref(const char *vol, const char *ref);
char *find_system_snapshot(void);

int createNewAPFSSnapshot(const char *volume, const char *snapshot);
int renameAPFSSnapshot(const char *volume, const char *snapshot, const char *nw);
int list_snapshots(const char *vol);
int check_snapshot(const char *vol, const char *snap);
char *copyBootHash(void);
int renameAPFSSnapshot(const char *vol, const char *snap, const char *nw);
int verifySnapshot(const char *vol, const char *name);
#endif
/* apfs_util_h */

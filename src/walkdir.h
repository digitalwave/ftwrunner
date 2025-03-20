
#ifndef _WALKTREE_H
#define _WALKTREE_H

int walkcmp(const void *p1, const void *p2);
void walkdir(char *rootdir, char ***files, unsigned *files_count);

#endif

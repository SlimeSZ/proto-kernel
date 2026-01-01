#include <asm-generic/errno.h>
#include <bits/pthreadtypes.h>
#include <errno.h>
#include <stdint.h>
#include <pthread.h>
#include <assert.h>
#include <sched.h>
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>

#define MAX_FDS 1024
#define FD_ERR -1
#define MIN_FD 3
#define CACHE_LINE_SIZE 64
#define NPROC 64 

typedef struct FileDescriptorTable fd_table; 
typedef struct OpenFileTable open_file;
typedef struct InodeTable inode;
typedef struct FD fd_table_entry;
struct FD { // unique per-process, fd3 in process A is independent from fd3 in another
	open_file *file_ptr;
	uint8_t close_on_exec;
	uint8_t _pad_[7];
}; 
struct FileDescriptorTable { // isolated per-process
	fd_table_entry fds[MAX_FDS];
	uint64_t fd_bitmap[MAX_FDS/64];

	int next_fd; 
	int open_fds;
	pthread_mutex_t lock;
};
struct OpenFileTable {
	off_t offset;
	int status_flags;
	inode *inode_ptr;
	atomic_uint refcnt; // how many refs in fd_table
};
struct InodeTable { // many open_files can point to one inode 
	char *path;
	size_t size;
	int perms;
	time_t atime, mtime;
	char *data;
	atomic_uint refcnt; // how many refs in open file table 
};

enum proc_state { UNUSED, EMBRYO, RUNNING, ZOMBIE };
typedef int pid_t;
typedef struct Process {
	pid_t pid;
	fd_table *file_descriptor_table;
	enum proc_state state;	
	struct proc *parent;
	pthread_mutex_t lock;
	char name[16]; // debugging 
} proc;
static_assert(NPROC % 64 == 0, "NPROC must be a multiple of 64");
typedef struct ProcessTable {
	proc procs[NPROC];
	pthread_mutex_t lock;
	
	uint64_t pid_bitmap[NPROC/64];
	pid_t next_pid;
} ptable; 
static ptable global_ptable = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.next_pid = 1
};

proc *proc_alloc(void) {
    if (pthread_mutex_lock(&global_ptable.lock) != 0) {
        perror("pthread_mutex_lock");
        return NULL;
    }

    for (size_t i = 0; i < NPROC/64; i++) {
        uint64_t word = global_ptable.pid_bitmap[i];
        if (word == UINT64_MAX) continue;

        for (size_t b = 0; b < 64; b++) {
            size_t proc_idx = (i << 6) + b;
            if (proc_idx >= NPROC) break;

            if ((word & (1ULL << b)) == 0) {
                proc *p = &global_ptable.procs[proc_idx];
                if (pthread_mutex_lock(&p->lock) != 0) {
                    perror("pthread_mutex_lock proc");
                    pthread_mutex_unlock(&global_ptable.lock);
                    return NULL;
                }

                p->state = EMBRYO;
                p->pid = global_ptable.next_pid++;
                global_ptable.pid_bitmap[i] |= (1ULL << b);

                pthread_mutex_unlock(&p->lock);
                pthread_mutex_unlock(&global_ptable.lock);
                return p;
            }
        }
    }

    pthread_mutex_unlock(&global_ptable.lock);
    return NULL;
}
static inline void fdtable_rm(fd_table *table);
void proc_free(proc *p) {
	if (__builtin_expect(!p, 0)) {
        	errno = EINVAL;
        	return;
	}
	if (pthread_mutex_lock(&global_ptable.lock) != 0) {
		perror("pthread_mutex_lock");
		errno = EINVAL;
		return;
	}
	pthread_mutex_lock(&p->lock);

	fdtable_rm(p->file_descriptor_table);
	p->file_descriptor_table = NULL;

	p->state = UNUSED;
	p->pid = 0;

	size_t idx = (p - global_ptable.procs); 
	global_ptable.pid_bitmap[idx >> 6] &= ~(1ULL << idx & 63);

	if (p->parent) {
		// to be implemented	
		p->parent = NULL;
	}

	pthread_mutex_unlock(&global_ptable.lock);
	pthread_mutex_unlock(&p->lock);
}

proc *proc_fork(proc *parent) {

}

proc *proc_fork(proc *parent);
proc *proc_fdtable(proc *p);
void proc_set_fdtable(proc *p, fd_table *table);

static inline fd_table *fdtable_init(void) {
	fd_table *table = aligned_alloc(CACHE_LINE_SIZE, sizeof(fd_table));
	if (__builtin_expect(!table, 0)) {
		errno = ENOMEM;
		return NULL;
	}
	memset(table, 0, sizeof(fd_table));
	if (__builtin_expect(pthread_mutex_init(&table->lock, NULL)
		!= 0, 0)) {
		perror("mutex init failed");
		free(table);
		return NULL;
	} 
	table->next_fd = MIN_FD;

	// touch memory to pre-fault pages, so page faults don't 
	// occur later during critical loops
	for (size_t i = 0; i < sizeof(fd_table)/64; i++) {
		((volatile char*)table)[i] = 0;
	}

	return table;
} 

static inline void fdtable_rm(fd_table *table) {
	if (__builtin_expect(!table, 0)) {
		errno = ENOMEM;
		return;
	}
	pthread_mutex_lock(&table->lock);
	for (size_t word = 0; word < MAX_FDS/64; word++) {
		uint64_t b64 = table->fd_bitmap[word];
		if (b64 == 0) continue; 
		for (int8_t b = 0; b < 64; b++) {
			// clear bits 
			int abs_fd = (word << 6) + b;
			if (__builtin_expect(abs_fd >= MAX_FDS, 0))
				continue;
			if (!(b64 & (1ULL << b))) 
				continue;
			table->fd_bitmap[word] &= ~(1ULL << b);	
			// free fd_table -> open_file -> ino
			// only clear fd_entry
			fd_table_entry *fde = &table->fds[abs_fd];
			if (!fde->file_ptr) continue; 
			open_file *fptr = fde->file_ptr;

			if (atomic_fetch_sub(&fptr->refcnt, 1) == 1) {
				if (fptr->inode_ptr) {
					inode *ino = fptr->inode_ptr;
					free(ino->data);
					free(ino->path);
					free(ino);
				}
				free(fptr);
			}

		fde->file_ptr = NULL;
		fde->close_on_exec = 0;
		}
	}
	pthread_mutex_unlock(&table->lock);
	pthread_mutex_destroy(&table->lock);
	free(table);
}

static inline int fd_alloc(fd_table *table, open_file *file) {
	if (__builtin_expect(!table || !file, 0)) {
		errno = ENOMEM;
		return FD_ERR;
	}
	pthread_mutex_lock(&table->lock);
	if (__builtin_expect(table->open_fds >= MAX_FDS, 0)) {
		pthread_mutex_unlock(&table->lock);
		errno = EMFILE;
		return FD_ERR;
	}
	
	for (size_t word = 0; word < MAX_FDS/64; word++) {
		uint64_t b64 = table->fd_bitmap[word];
		if (b64 == UINT64_MAX) continue; 
		for (int8_t b = 0; b < 64; b++) {
			int abs_fd = (word << 6) + b;
			if (abs_fd >= MAX_FDS || abs_fd < MIN_FD) 
				continue;
			// word[b] is set 
			if ((b64 & (1ULL << b)) == 0) {
				table->fd_bitmap[word] |= 1ULL << b; // set 
				table->open_fds++;
				table->next_fd = abs_fd + 1;
				fd_table_entry *fde = &table->fds[abs_fd];
				fde->close_on_exec = 0;
				fde->file_ptr =  file;
				pthread_mutex_unlock(&table->lock);
				return abs_fd;
			}
		}
	}
	pthread_mutex_unlock(&table->lock);
	errno = EMFILE;
	return FD_ERR;
}

static inline int fd_close(fd_table *table, int fd) {
	if (__builtin_expect(!table, 0)) {
		errno = EINVAL;
		return -1;
	}
	if (__builtin_expect(fd < 0 || fd >= MAX_FDS, 0)) {
		errno = EBADF;
		return -1;
	}
	pthread_mutex_lock(&table->lock);
	
	size_t word = fd >> 6;
	size_t bit_pos = fd & 63;
	// check if FD open to save potential cycle(s)
	if ((table->fd_bitmap[word] & (1ULL << bit_pos)) == 0) {
		pthread_mutex_unlock(&table->lock);
		errno = EBADF;
		return -1;
	}

	fd_table_entry *fde = &table->fds[fd];
	if (__builtin_expect(!fde->file_ptr, 0)) {
		pthread_mutex_unlock(&table->lock);
		errno = EBADF;
		return -1;
	}

	// free internal structs
	open_file *fptr= fde->file_ptr;
	if (atomic_fetch_sub(&fptr->refcnt, 1) == 1) {
		if (fptr->inode_ptr) {
			inode *ino = fptr->inode_ptr;
			if (atomic_fetch_sub(&ino->refcnt, 1) == 1) {
				free(ino->data);
				free(ino->path);
				free(ino);
			}
		}
		free(fptr);
	}
	fde->file_ptr = NULL;
	fde->close_on_exec = 0;

	// clear corresponding bitmap bit
	table->fd_bitmap[word] &= ~(1ULL << (bit_pos));
	table->open_fds--;
	
	// update hint if possible
	if (fd < table->next_fd) {
		table->next_fd = fd;
	}

	pthread_mutex_unlock(&table->lock);
	return 0;
}

static inline bool fd_isopen(fd_table *table, int fd) {
	if (__builtin_expect(fd < MIN_FD || fd >= MAX_FDS, 0)) {
		return false;
	}
	return(table->fd_bitmap[fd >> 6] & (1ULL << (fd & 63))) 
		!= 0;
}
// >> 6 -> (fd -> word)
// << 6 -> (word -> fd)
static inline open_file *fd_get(fd_table *table, int fd) {
	if (__builtin_expect(!table, 0)) {
		errno = EINVAL;
		return NULL;
	}
	if (__builtin_expect(fd >= MAX_FDS || fd < MIN_FD, 0)) {
		errno = EBADF;
		return NULL;
	}
	pthread_mutex_lock(&table->lock);
	if (__builtin_expect(!fd_isopen(table, fd), 0)) {
		errno = EBADF;
		return NULL;
	}
	fd_table_entry *fde = &table->fds[fd];
	return fde->file_ptr;
}

static inline int fd_set_close_on_exec(fd_table *table, int fd) {
	if (__builtin_expect(!table, 0)) {
		errno = EINVAL;
		return -1;
	}
	if (__builtin_expect(fd >= MAX_FDS || fd < MIN_FD, 0)) {
		errno = EBADF;
		return -1;
	}
	pthread_mutex_lock(&table->lock);
	table->fds[fd].close_on_exec = 0;
	return 0;
}

/*
 * Loops starting at 'next_fd', circular iter if MAX_FD 
 * reached without finding suitable candidate for dup.
 * 
 * returns corresponding fd guaranteed to be lowest used on success,
 * FD_ERR otherwise
 */
static inline int fd_dup(fd_table *table, int fd) {
	if (__builtin_expect(!table, 0)) {
		errno = EINVAL;
		return -1;
	}
	if (__builtin_expect(fd >= MAX_FDS || fd < MIN_FD, 0)) {
		errno = EBADF;
		return -1;
	}
	pthread_mutex_lock(&table->lock);
	if (!fd_isopen(table, fd)) {
		pthread_mutex_unlock(&table->lock);
		errno = EBADF;
		return -1;
	}

	open_file *fptr = table->fds[fd].file_ptr;
	if (!fptr) {
		pthread_mutex_unlock(&table->lock);
		errno = EBADF;
		return -1;
	}

	size_t candidate = table->next_fd;

	for (size_t i = 0; i < MAX_FDS; i++, candidate++) {
		// loop from next_fd, start back at 3 if end reached
		// without finding candidate
		if (candidate >= MAX_FDS)
			candidate = MIN_FD;
		size_t word = candidate >> 6;
		size_t bit = candidate & 63;

		if ((table->fd_bitmap[word] & (1ULL << bit)) == 0) {
			table->fd_bitmap[word] |= 1ULL << bit;
			table->open_fds++;
			table->next_fd = candidate + 1;
			fd_table_entry *fde = &table->fds[candidate];
			fde->file_ptr = fptr;
			fde->close_on_exec = 0;
			atomic_fetch_add(&fptr->refcnt, 1);
			pthread_mutex_unlock(&table->lock);
			return candidate;
		}
	}

	pthread_mutex_unlock(&table->lock);
	errno = EMFILE;
	return FD_ERR;
}

int fd_dup2(fd_table *table, int old_fd, int new_fd) {
	if (__builtin_expect(!table, 0)) {
		errno = EINVAL;
		return FD_ERR;
	}
	if (__builtin_expect(old_fd >= MAX_FDS || old_fd < MIN_FD
			|| new_fd >= MAX_FDS || new_fd < MIN_FD, 0)) {
		errno = EBADF;
		return FD_ERR;
	}
	if (__builtin_expect(old_fd == new_fd, 0)) {
		errno = EINVAL;
		return FD_ERR;
	}
	pthread_mutex_lock(&table->lock);
	if (!fd_isopen(table, old_fd)) {
		pthread_mutex_unlock(&table->lock);
		errno = EBADF;
		return FD_ERR;
	}

	if (fd_isopen(table, new_fd)) {
		fd_close(table, new_fd);
	}

	open_file *fptr = table->fds[old_fd].file_ptr;
	table->fds[new_fd].file_ptr = fptr;
	table->fds[new_fd].close_on_exec = 0;
	table->fd_bitmap[new_fd >> 6] |= (1ULL << new_fd & 63);
	atomic_fetch_add(&fptr->refcnt, 1);
	
	pthread_mutex_unlock(&table->lock);
	return new_fd;
}


#ifndef BLOCK_DEVICE_H
#define BLOCK_DEVICE_H

#include <stdint.h>
#include <stddef.h>

typedef struct block_device block_device_t;

struct block_device {
	char name[32];
	size_t block_size;
	size_t total_blocks;
	
	int (*read)(block_device_t *dev, uint64_t block_num, void *buf);
	int (*write)(block_device_t *dev, uint64_t block_num, const void *buf);
	int (*sync)(block_device_t *dev);

	/*
	 * Generic backing memory (e.g. malloc'd disk, file-backed disk)
	*/
	void *private_data;
};

#define BDEV_OK 	0 // success 
#define BDEV_ERANGE 	-1 // block no. out of range 
#define BDEV_EIO 	-2 // I/O err 
#define BDEV_EINVAL 	-3 // invalid arg

/*
 * Offset index for block N is [block_num * block_size ...]
*/

int bdev_read(block_device_t *dev, uint64_t block_num, void *buf);
int bdev_write(block_device_t *dev, uint64_t block_num, const void *buf);
/*
 * RAM-backed writes are instant
 * File-backed writes are flushed via fsync()
 * Network-backed not yet implemented 
*/
int bdev_sync(block_device_t *dev);

#endif

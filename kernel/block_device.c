#include "../include/block_device.h"
#include <string.h>

int bdev_read(block_device_t *dev, uint64_t block_num, void *buf) {
	if (!dev || !buf) return BDEV_EINVAL;
	if (block_num >= dev->total_blocks) return BDEV_ERANGE;
	return dev->read(dev, block_num, buf);
}

int bdev_write(block_device_t *dev, uint64_t block_num, const void *buf) {
	if (!dev || !buf) return BDEV_EINVAL;
	if (block_num >= dev->total_blocks) return BDEV_ERANGE;
	return dev->write(dev, block_num, buf);
}
int bdev_sync(block_device_t *dev) {
	if (!dev) return BDEV_EINVAL;
	if (dev->sync) return dev->sync(dev);
	return BDEV_OK; // NOP if sync not impl for this backing
}




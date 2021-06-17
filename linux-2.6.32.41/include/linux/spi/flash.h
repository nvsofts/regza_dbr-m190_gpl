#ifndef LINUX_SPI_FLASH_H
#define LINUX_SPI_FLASH_H

struct mtd_partition;

/**
 * struct flash_platform_data: board-specific flash data
 * @name: optional flash device name (eg, as used with mtdparts=)
 * @parts: optional array of mtd_partitions for static partitioning
 * @nr_parts: number of mtd_partitions for static partitoning
 * @type: optional flash device type (e.g. m25p80 vs m25p64), for use
 *	with chips that can't be queried for JEDEC or other IDs
 *
 * Board init code (in arch/.../mach-xxx/board-yyy.c files) can
 * provide information about SPI flash parts (such as DataFlash) to
 * help set up the device and its appropriate default partitioning.
 *
 * Note that for DataFlash, sizes for pages, blocks, and sectors are
 * rarely powers of two; and partitions should be sector-aligned.
 */
struct flash_platform_data {
	char		*name;
	struct mtd_partition *parts;
	unsigned int	nr_parts;

	char		*type;

#if defined(CONFIG_SPI_TC90431) || defined(CONFIG_SPI_TC90431_MODULE)
	unsigned long size;
	unsigned long phys;
	unsigned long virt;

	unsigned char read_opcode;
#define OPCODE_FAST_READ_SINGLE      0x0b
#define OPCODE_FAST_READ_DUAL_OUTPUT 0x3b
#define OPCODE_FAST_READ_DUAL_IO     0xbb
#define OPCODE_FAST_READ_QUAD_OUTPUT 0x6b
#define OPCODE_FAST_READ_QUAD_IO     0xeb
#define OPCODE_AUTO                  0x9f
/* SPI cmd 0x9f is generally 'Read JEDEC ID', so never used as Read command */

	unsigned char dummy_count;
	unsigned char flash_initialized;
#endif
	/* we'll likely add more ... use JEDEC IDs, etc */
};

#endif

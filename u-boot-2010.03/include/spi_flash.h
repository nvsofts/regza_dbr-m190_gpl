/*
 * Interface to SPI flash
 *
 * Copyright (C) 2008 Atmel Corporation
 *
 * See file CREDITS for list of people who contributed to this
 * project.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */
#ifndef _SPI_FLASH_H_
#define _SPI_FLASH_H_

#include <spi.h>
#include <linux/types.h>
#ifdef CONFIG_SYS_FLASH_PHYS_MAP_SPI
#include <asm/types.h>
#endif

struct spi_flash_region {
	unsigned int	count;
	unsigned int	size;
};

struct spi_flash {
	struct spi_slave *spi;

	const char	*name;

	u32		size;

#ifdef CONFIG_SYS_FLASH_PHYS_MAP_SPI
	u32		sector_size;

	phys_addr_t	map_base;

	u32		map_len;

	u32		read_op;
#define OPCODE_FAST_READ_SINGLE		0x0b
#define OPCODE_FAST_READ_DUAL_OUTPUT	0x3b
#define OPCODE_FAST_READ_DUAL_IO	0xbb
#define OPCODE_FAST_READ_QUAD_OUTPUT	0x6b
#define OPCODE_FAST_READ_QUAD_IO	0xeb

	u32		dummy_count;

	int		(*option)(u32 flag, void *param);
#define SF_SET_MAP_READ		0x1
#endif
	int		(*read)(struct spi_flash *flash, u32 offset,
				size_t len, void *buf);
	int		(*write)(struct spi_flash *flash, u32 offset,
				size_t len, const void *buf);
	int		(*erase)(struct spi_flash *flash, u32 offset,
				size_t len);
};

#ifdef CONFIG_SYS_FLASH_PHYS_MAP_SPI
struct spi_flash_map {
	phys_addr_t base;
	unsigned int len;
	unsigned int bus;
	unsigned int cs;
};
#endif

struct spi_flash *spi_flash_probe(unsigned int bus, unsigned int cs,
		unsigned int max_hz, unsigned int spi_mode);
void spi_flash_free(struct spi_flash *flash);

static inline int spi_flash_read(struct spi_flash *flash, u32 offset,
		size_t len, void *buf)
{
	return flash->read(flash, offset, len, buf);
}

static inline int spi_flash_write(struct spi_flash *flash, u32 offset,
		size_t len, const void *buf)
{
	return flash->write(flash, offset, len, buf);
}

static inline int spi_flash_erase(struct spi_flash *flash, u32 offset,
		size_t len)
{
	return flash->erase(flash, offset, len);
}

#endif /* _SPI_FLASH_H_ */

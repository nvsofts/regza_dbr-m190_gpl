/*
 * Driver for SST serial flashes
 *
 * (C) Copyright 2000-2002
 * Wolfgang Denk, DENX Software Engineering, wd@denx.de.
 * Copyright 2008, Network Appliance Inc.
 * Jason McMullan <mcmullan@netapp.com>
 * Copyright (C) 2004-2007 Freescale Semiconductor, Inc.
 * TsiChung Liew (Tsi-Chung.Liew@freescale.com)
 * Copyright (c) 2008-2009 Analog Devices Inc.
 *
 * Licensed under the GPL-2 or later.
 */

#include <common.h>
#include <malloc.h>
#include <spi_flash.h>

#include "spi_flash_internal.h"

#define CMD_SST_WREN		0x06	/* Write Enable */
#define CMD_SST_WRDI		0x04	/* Write Disable */
#define CMD_SST_RDSR		0x05	/* Read Status Register */
#define CMD_SST_WRSR		0x01	/* Write Status Register */
#define CMD_SST_READ		0x03	/* Read Data Bytes */
#define CMD_SST_FAST_READ	0x0b	/* Read Data Bytes at Higher Speed */
#define CMD_SST_BP		0x02	/* Byte Program */
#define CMD_SST_AAI_WP		0xAD	/* Auto Address Increment Word Program */
#define CMD_SST_SE		0x20	/* Sector Erase */
#ifdef CONFIG_TC90431_SPI
#define CMD_SST_BE		0xd8	/* Block Erase */
#endif

#define SST_SR_WIP		(1 << 0)	/* Write-in-Progress */
#define SST_SR_WEL		(1 << 1)	/* Write enable */
#define SST_SR_BP0		(1 << 2)	/* Block Protection 0 */
#define SST_SR_BP1		(1 << 3)	/* Block Protection 1 */
#define SST_SR_BP2		(1 << 4)	/* Block Protection 2 */
#define SST_SR_AAI		(1 << 6)	/* Addressing mode */
#define SST_SR_BPL		(1 << 7)	/* BP bits lock */

struct sst_spi_flash_params {
	u8 idcode1;
	u16 nr_sectors;
	const char *name;
#ifdef CONFIG_TC90431_SPI
	u32 max_hz;
	u32 deassert_time;
	u32 hp_read_op;
	u32 max_hp_hz;
#endif
};

struct sst_spi_flash {
	struct spi_flash flash;
	const struct sst_spi_flash_params *params;
};

static inline struct sst_spi_flash *to_sst_spi_flash(struct spi_flash *flash)
{
	return container_of(flash, struct sst_spi_flash, flash);
}

#ifdef CONFIG_SYS_FLASH_PHYS_MAP_SPI
static int sst_option (u32 flag, void *param)
{
	if (flag & SF_SET_MAP_READ) {
		struct spi_flash *flash = param;
		struct sst_spi_flash *stm = to_sst_spi_flash(flash);

		switch (flash->read_op) {
		case OPCODE_FAST_READ_SINGLE:
			flash->spi->max_map_read_hz = stm->params->max_hz;
			flash->dummy_count = 1;
			break;
		default:
			return -1;
		}
	}
	return 0;
}
#endif

#define SST_SECTOR_SIZE (4 * 1024)
static const struct sst_spi_flash_params sst_spi_flash_table[] = {
#ifdef CONFIG_TC90431_SPI
#define SST_BLOCK_SIZE	(SST_SECTOR_SIZE * 16)
	{
		.idcode1 = 0x41,
		.nr_sectors = 512,
		.name = "SST25VF016B",
		.max_hz = 50000000,
		.deassert_time = 50,
		.hp_read_op = OPCODE_FAST_READ_SINGLE,
		.max_hp_hz = 50000000,
	},
#else
	{
		.idcode1 = 0x8d,
		.nr_sectors = 128,
		.name = "SST25VF040B",
	},{
		.idcode1 = 0x8e,
		.nr_sectors = 256,
		.name = "SST25VF080B",
	},{
		.idcode1 = 0x41,
		.nr_sectors = 512,
		.name = "SST25VF016B",
	},{
		.idcode1 = 0x4a,
		.nr_sectors = 1024,
		.name = "SST25VF032B",
	},{
		.idcode1 = 0x01,
		.nr_sectors = 16,
		.name = "SST25WF512",
	},{
		.idcode1 = 0x02,
		.nr_sectors = 32,
		.name = "SST25WF010",
	},{
		.idcode1 = 0x03,
		.nr_sectors = 64,
		.name = "SST25WF020",
	},{
		.idcode1 = 0x04,
		.nr_sectors = 128,
		.name = "SST25WF040",
	},
#endif
};

static int
sst_wait_ready(struct spi_flash *flash, unsigned long timeout)
{
	struct spi_slave *spi = flash->spi;
	unsigned long timebase;
	int ret;
	u8 byte = CMD_SST_RDSR;
#ifdef CONFIG_TC90431_SPI
	u8 status;

        timebase = get_timer(0);
        do {
                ret = spi_flash_cmd(spi, byte, &status, sizeof(status));
                if (ret)
                        return -1;

                if ((status & SST_SR_WIP) == 0)
                        break;

        } while (get_timer(timebase) < timeout);

        if ((status & SST_SR_WIP) == 0)
                return 0;

        /* Timed out */
        return -1;
#else
	ret = spi_xfer(spi, sizeof(byte) * 8, &byte, NULL, SPI_XFER_BEGIN);
	if (ret) {
		debug("SF: Failed to send command %02x: %d\n", byte, ret);
		return ret;
	}

	timebase = get_timer(0);
	do {
		ret = spi_xfer(spi, sizeof(byte) * 8, NULL, &byte, 0);
		if (ret)
			break;

		if ((byte & SST_SR_WIP) == 0)
			break;

	} while (get_timer(timebase) < timeout);

	spi_xfer(spi, 0, NULL, NULL, SPI_XFER_END);

	if (!ret && (byte & SST_SR_WIP) != 0)
		ret = -1;

	if (ret)
		debug("SF: sst wait for ready timed out\n");
	return ret;
#endif
}

static int
sst_enable_writing(struct spi_flash *flash)
{
	int ret = spi_flash_cmd(flash->spi, CMD_SST_WREN, NULL, 0);
	if (ret)
		debug("SF: Enabling Write failed\n");
	return ret;
}

static int
sst_disable_writing(struct spi_flash *flash)
{
	int ret = spi_flash_cmd(flash->spi, CMD_SST_WRDI, NULL, 0);
	if (ret)
		debug("SF: Disabling Write failed\n");
	return ret;
}

static int
sst_read_fast(struct spi_flash *flash, u32 offset, size_t len, void *buf)
{
#ifdef CONFIG_TC90431_SPI
        unsigned long page_addr;
        unsigned long page_size;
        u8 cmd[5];
        unsigned long byte_addr;
        size_t chunk_len;
        size_t actual;
        int ret;

        page_size = 256;
        page_addr = offset / page_size;
        byte_addr = offset % page_size;

        ret = 0;
        for (actual = 0; actual < len; actual += chunk_len) {
                chunk_len = min(len - actual, page_size - byte_addr);

                cmd[0] = CMD_READ_ARRAY_FAST;
                cmd[1] = page_addr >> 8;
                cmd[2] = page_addr;
                cmd[3] = byte_addr;
                cmd[4] = 0x00;

                debug
                    ("READ: 0x%p => cmd = { 0x%02x 0x%02x%02x%02x%02x } chunk_len = %d\n",
		     buf + actual, cmd[0], cmd[1], cmd[2], cmd[3], cmd[4], chunk_len);

                ret = spi_flash_read_common(flash, cmd, sizeof(cmd), buf + actual, chunk_len);
                if (ret < 0) {
                        debug("SF: SST Read failed\n");
                        break;
                }

                page_addr++;
                byte_addr = 0;
        }

        debug("SF: SST: Successfully Read %u bytes @ 0x%x\n",
              len, offset);

        return ret;
#else
	u8 cmd[5] = {
		CMD_READ_ARRAY_FAST,
		offset >> 16,
		offset >> 8,
		offset,
		0x00,
	};
	return spi_flash_read_common(flash, cmd, sizeof(cmd), buf, len);
#endif
}

static int
sst_byte_write(struct spi_flash *flash, u32 offset, const void *buf)
{
	int ret;
	u8 cmd[4] = {
		CMD_SST_BP,
		offset >> 16,
		offset >> 8,
		offset,
	};

	debug("BP[%02x]: 0x%p => cmd = { 0x%02x 0x%06x }\n",
		spi_w8r8(flash->spi, CMD_SST_RDSR), buf, cmd[0], offset);

	ret = sst_enable_writing(flash);
	if (ret)
		return ret;

	ret = spi_flash_cmd_write(flash->spi, cmd, sizeof(cmd), buf, 1);
	if (ret)
		return ret;

	return sst_wait_ready(flash, SPI_FLASH_PROG_TIMEOUT);
}

static int
sst_write(struct spi_flash *flash, u32 offset, size_t len, const void *buf)
{
	size_t actual, cmd_len;
	int ret;
	u8 cmd[4];

	ret = spi_claim_bus(flash->spi);
	if (ret) {
		debug("SF: Unable to claim SPI bus\n");
		return ret;
	}

	/* If the data is not word aligned, write out leading single byte */
	actual = offset % 2;
	if (actual) {
		ret = sst_byte_write(flash, offset, buf);
		if (ret)
			goto done;
	}
	offset += actual;

	ret = sst_enable_writing(flash);
	if (ret)
		goto done;

	cmd_len = 4;
	cmd[0] = CMD_SST_AAI_WP;
	cmd[1] = offset >> 16;
	cmd[2] = offset >> 8;
	cmd[3] = offset;

	for (; actual < len - 1; actual += 2) {
		debug("WP[%02x]: 0x%p => cmd = { 0x%02x 0x%06x }\n",
		     spi_w8r8(flash->spi, CMD_SST_RDSR), buf + actual, cmd[0],
		     offset);

		ret = spi_flash_cmd_write(flash->spi, cmd, cmd_len,
		                          buf + actual, 2);
		if (ret) {
			debug("SF: sst word program failed\n");
			break;
		}

		ret = sst_wait_ready(flash, SPI_FLASH_PROG_TIMEOUT);
		if (ret)
			break;

		cmd_len = 1;
		offset += 2;
	}

	if (!ret)
		ret = sst_disable_writing(flash);

	/* If there is a single trailing byte, write it out */
	if (!ret && actual != len)
		ret = sst_byte_write(flash, offset, buf + actual);

 done:
	debug("SF: sst: program %s %zu bytes @ 0x%zx\n",
	      ret ? "failure" : "success", len, offset - actual);

	spi_release_bus(flash->spi);
	return ret;
}

int
sst_erase(struct spi_flash *flash, u32 offset, size_t len)
{
	unsigned long sector_size;
	u32 start, end;
	int ret;
	u8 cmd[4];

	/*
	 * This function currently uses sector erase only.
	 * Probably speed things up by using bulk erase
	 * when possible.
	 */

#ifdef CONFIG_TC90431_SPI
	sector_size = SST_BLOCK_SIZE;
#else
	sector_size = SST_SECTOR_SIZE;
#endif

	if (offset % sector_size) {
		debug("SF: Erase offset not multiple of sector size\n");
		return -1;
	}

	ret = spi_claim_bus(flash->spi);
	if (ret) {
		debug("SF: Unable to claim SPI bus\n");
		return ret;
	}

#ifdef CONFIG_TC90431_SPI
	cmd[0] = CMD_SST_BE;
#else
	cmd[0] = CMD_SST_SE;
#endif
	cmd[3] = 0;
	start = offset;
	end = start + len;

	ret = 0;
	while (offset < end) {
		cmd[1] = offset >> 16;
		cmd[2] = offset >> 8;
		offset += sector_size;

		debug("SF: erase %2x %2x %2x %2x (%x)\n", cmd[0], cmd[1],
		      cmd[2], cmd[3], offset);

		ret = sst_enable_writing(flash);
		if (ret)
			break;

		ret = spi_flash_cmd_write(flash->spi, cmd, sizeof(cmd), NULL, 0);
		if (ret) {
			debug("SF: sst page erase failed\n");
			break;
		}

		ret = sst_wait_ready(flash, SPI_FLASH_PAGE_ERASE_TIMEOUT);
		if (ret)
			break;
	}

#ifdef CONFIG_TC90431_SPI
	/* bug fixed */
	debug("SF: sst: Successfully erased %lu bytes @ 0x%x\n",
	      len, start);
#else
	debug("SF: sst: Successfully erased %lu bytes @ 0x%x\n",
	      len * sector_size, start);
#endif

	spi_release_bus(flash->spi);
	return ret;
}

static int
sst_unlock(struct spi_flash *flash)
{
	int ret;
	u8 cmd, status;

	ret = sst_enable_writing(flash);
	if (ret)
		return ret;

	cmd = CMD_SST_WRSR;
	status = 0;
	ret = spi_flash_cmd_write(flash->spi, &cmd, 1, &status, 1);
	if (ret)
		debug("SF: Unable to set status byte\n");

	debug("SF: sst: status = %x\n", spi_w8r8(flash->spi, CMD_SST_RDSR));

	return ret;
}

struct spi_flash *
spi_flash_probe_sst(struct spi_slave *spi, u8 *idcode)
{
	const struct sst_spi_flash_params *params;
	struct sst_spi_flash *stm;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(sst_spi_flash_table); ++i) {
		params = &sst_spi_flash_table[i];
		if (params->idcode1 == idcode[2])
			break;
	}

	if (i == ARRAY_SIZE(sst_spi_flash_table)) {
		debug("SF: Unsupported SST ID %02x\n", idcode[1]);
		return NULL;
	}

	stm = malloc(sizeof(*stm));
	if (!stm) {
		debug("SF: Failed to allocate memory\n");
		return NULL;
	}

	stm->params = params;
	stm->flash.spi = spi;
	stm->flash.name = params->name;

	stm->flash.write = sst_write;
	stm->flash.erase = sst_erase;
	stm->flash.read = sst_read_fast;
	stm->flash.size = SST_SECTOR_SIZE * params->nr_sectors;

#ifdef CONFIG_TC90431_SPI
	spi->max_hz = params->max_hz;
	spi->deassert_time = params->deassert_time;
#ifdef CONFIG_SYS_FLASH_PHYS_MAP_SPI
	stm->flash.sector_size = SST_BLOCK_SIZE;
	stm->flash.option = sst_option;
#ifdef CONFIG_SYS_FLASH_SPI_HIGH_PERFORMANCE_READ
	spi->max_map_read_hz = params->max_hp_hz;
	stm->flash.read_op = params->hp_read_op;
#else
	spi->max_map_read_hz = params->max_hz;
	stm->flash.read_op = OPCODE_FAST_READ_SINGLE;
#endif
#endif
#endif

	debug("SF: Detected %s with page size %u, total %u bytes\n",
	      params->name, SST_SECTOR_SIZE, stm->flash.size);

	/* Flash powers up read-only, so clear BP# bits */
	sst_unlock(&stm->flash);

	return &stm->flash;
}

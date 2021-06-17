/*
 * SPI flash interface
 *
 * Copyright (C) 2008 Atmel Corporation
 * Licensed under the GPL-2 or later.
 */

#include <common.h>
#include <malloc.h>
#include <spi.h>
#include <spi_flash.h>

#include "spi_flash_internal.h"

int spi_flash_cmd(struct spi_slave *spi, u8 cmd, void *response, size_t len)
{
	unsigned long flags = SPI_XFER_BEGIN;
	int ret;

	if (len == 0)
		flags |= SPI_XFER_END;

	ret = spi_xfer(spi, 8, &cmd, NULL, flags);
	if (ret) {
		debug("SF: Failed to send command %02x: %d\n", cmd, ret);
		return ret;
	}

	if (len) {
		ret = spi_xfer(spi, len * 8, NULL, response, SPI_XFER_END);
		if (ret)
			debug("SF: Failed to read response (%zu bytes): %d\n",
					len, ret);
	}

	return ret;
}

int spi_flash_cmd_read(struct spi_slave *spi, const u8 *cmd,
		size_t cmd_len, void *data, size_t data_len)
{
	unsigned long flags = SPI_XFER_BEGIN;
	int ret;

	if (data_len == 0)
		flags |= SPI_XFER_END;

	ret = spi_xfer(spi, cmd_len * 8, cmd, NULL, flags);
	if (ret) {
		debug("SF: Failed to send read command (%zu bytes): %d\n",
				cmd_len, ret);
	} else if (data_len != 0) {
		ret = spi_xfer(spi, data_len * 8, NULL, data, SPI_XFER_END);
		if (ret)
			debug("SF: Failed to read %zu bytes of data: %d\n",
					data_len, ret);
	}

	return ret;
}

int spi_flash_cmd_write(struct spi_slave *spi, const u8 *cmd, size_t cmd_len,
		const void *data, size_t data_len)
{
	unsigned long flags = SPI_XFER_BEGIN;
	int ret;

	if (data_len == 0)
		flags |= SPI_XFER_END;

	ret = spi_xfer(spi, cmd_len * 8, cmd, NULL, flags);
	if (ret) {
		debug("SF: Failed to send read command (%zu bytes): %d\n",
				cmd_len, ret);
	} else if (data_len != 0) {
		ret = spi_xfer(spi, data_len * 8, data, NULL, SPI_XFER_END);
		if (ret)
			debug("SF: Failed to read %zu bytes of data: %d\n",
					data_len, ret);
	}

	return ret;
}


int spi_flash_read_common(struct spi_flash *flash, const u8 *cmd,
		size_t cmd_len, void *data, size_t data_len)
{
	struct spi_slave *spi = flash->spi;
	int ret;

	spi_claim_bus(spi);
	ret = spi_flash_cmd_read(spi, cmd, cmd_len, data, data_len);
	spi_release_bus(spi);

	return ret;
}

struct spi_flash *spi_flash_probe(unsigned int bus, unsigned int cs,
		unsigned int max_hz, unsigned int spi_mode)
{
	struct spi_slave *spi;
	struct spi_flash *flash;
	int ret;
	u8 idcode[5];

	spi = spi_setup_slave(bus, cs, max_hz, spi_mode);
	if (!spi) {
		debug("SF: Failed to set up slave\n");
		return NULL;
	}

	ret = spi_claim_bus(spi);
	if (ret) {
		debug("SF: Failed to claim SPI bus: %d\n", ret);
		goto err_claim_bus;
	}

	/* Read the ID codes */
	ret = spi_flash_cmd(spi, CMD_READ_ID, &idcode, sizeof(idcode));
	if (ret)
		goto err_read_id;

	debug("SF: Got idcode %02x %02x %02x %02x %02x\n", idcode[0],
			idcode[1], idcode[2], idcode[3], idcode[4]);

	switch (idcode[0]) {
#ifdef CONFIG_SPI_FLASH_SPANSION
	case 0x01:
		flash = spi_flash_probe_spansion(spi, idcode);
		break;
#endif
#ifdef CONFIG_SPI_FLASH_ATMEL
	case 0x1F:
		flash = spi_flash_probe_atmel(spi, idcode);
		break;
#endif
#ifdef CONFIG_SPI_FLASH_MACRONIX
	case 0xc2:
		flash = spi_flash_probe_macronix(spi, idcode);
		break;
#endif
#ifdef CONFIG_SPI_FLASH_WINBOND
	case 0xef:
		flash = spi_flash_probe_winbond(spi, idcode);
		break;
#endif
#ifdef CONFIG_SPI_FLASH_STMICRO
	case 0x20:
		flash = spi_flash_probe_stmicro(spi, idcode);
		break;
#endif
#ifdef CONFIG_SPI_FLASH_SST
	case 0xBF:
		flash = spi_flash_probe_sst(spi, idcode);
		break;
#endif
#ifdef CONFIG_SPI_FLASH_EON
	case 0x1c:
		flash = spi_flash_probe_eon(spi, idcode);
		break;
#endif
	default:
		debug("SF: Unsupported manufacturer %02X\n", idcode[0]);
		flash = NULL;
		break;
	}

	if (!flash)
		goto err_manufacturer_probe;

	spi_release_bus(spi);

	return flash;

err_manufacturer_probe:
err_read_id:
	spi_release_bus(spi);
err_claim_bus:
	spi_free_slave(spi);
	return NULL;
}

void spi_flash_free(struct spi_flash *flash)
{
	spi_free_slave(flash->spi);
	free(flash);
}

#ifdef CONFIG_SYS_FLASH_PHYS_MAP_SPI
#include <flash.h>

#ifndef CONFIG_SYS_SPI_READID_HZ
#define CONFIG_SYS_SPI_READID_HZ	1000000
#endif

#ifndef CONFIG_SYS_SPI_FLASH_BANKS_LIST
#define CONFIG_SYS_SPI_FLASH_BANKS_LIST	{ \
	{CONFIG_SYS_FLASH_BASE, 0x01000000, 0, 0} }
#endif

#ifndef CONFIG_SYS_MAX_SPI_FLASH_BANKS
#define CONFIG_SYS_MAX_SPI_FLASH_BANKS	1
#endif

#define SPI_INVALID_BUS 0xffffffff
#define SPI_INVALID_CS  0xffffffff

static struct spi_flash_map map[CONFIG_SYS_MAX_SPI_FLASH_BANKS] = CONFIG_SYS_SPI_FLASH_BANKS_LIST;
static unsigned int base2len(phys_addr_t base) {
	int i;
	for (i=0; i < CONFIG_SYS_MAX_SPI_FLASH_BANKS; i++) {
		if (base == map[i].base) {
			return map[i].len;
		}
	}
	return 0;
}
   
static unsigned int base2bus(phys_addr_t base) {
	int i;
	for (i=0; i < CONFIG_SYS_MAX_SPI_FLASH_BANKS; i++) {
		if (base == map[i].base) {
			return map[i].bus;
		}
	}
	return SPI_INVALID_BUS;
}
   
static unsigned int base2cs(phys_addr_t base) {
	int i;
	for (i=0; i < CONFIG_SYS_MAX_SPI_FLASH_BANKS; i++) {
		if (base == map[i].base) {
			return map[i].cs;
		}
	}
	return SPI_INVALID_CS;
}
   
int flash_detect_spi(flash_info_t *info)
{
	int ret;
	phys_addr_t base = info->start[0];
	unsigned int len = base2len(base);
	unsigned int bus = base2bus(base);
	unsigned int cs = base2cs(base);

	info->spifl =
	    spi_flash_probe(bus, cs, CONFIG_SYS_SPI_READID_HZ, SPI_MODE_0);

	if (!(info->spifl)) {
		debug("%s : Failed to probe spi flash\n", __func__);
		return 0;
	}

	info->spifl->map_base = base;
	info->spifl->map_len = len;

	info->spifl->spi->flag = DEVICE_PROBE_DONE;
	info->spifl->spi->device_data = info->spifl;
	info->spifl->option(SF_SET_MAP_READ, info->spifl);

	/* setup for direct access */
	ret = spi_claim_bus(info->spifl->spi);
	if (ret) {
		debug("SF: Failed to claim SPI bus: %d\n", ret);
		spi_free_slave(info->spifl->spi);
		return 0;
	}
	spi_release_bus(info->spifl->spi);

	return 1;	
}
#endif

/*
 * (C) Copyright 2002
 * Wolfgang Denk, DENX Software Engineering, wd@denx.de.
 *
 * See file CREDITS for list of people who contributed to this
 * project.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

/* for now: just dummy functions to satisfy the linker */

#include <common.h>

#ifdef CONFIG_TC90431

#ifdef CONFIG_ENABLE_ICACHE
void invalidate_icache_all (void)
{
#ifdef CONFIG_ENABLE_L2CACHE
	invalidate_l2_cache_all ();
#endif
	v7_invalidate_icache_all ();
}

void invalidate_icache_range(unsigned long start_addr, unsigned long stop)
{
	unsigned long lsize = CONFIG_SYS_CACHELINE_SIZE;
	unsigned long addr = start_addr & ~(lsize - 1);
	unsigned long aend = (stop - 1) & ~(lsize - 1);

#ifdef CONFIG_ENABLE_L2CACHE
	while (1) {
		invalidate_l2_cache_line (addr);
		if (addr == aend)
			break;
		addr += lsize;
	}

	addr = start_addr & ~(lsize - 1);
#endif
	while (1) {
		v7_invalidate_icache_line(addr);
		if (addr == aend)
			break;
		addr += lsize;
	}
}
#else
void invalidate_icache_all (void)
{
}

void invalidate_icache_range(unsigned long start_addr, unsigned long stop)
{
}
#endif

#if defined(CONFIG_ENABLE_ICACHE) || defined(CONFIG_ENABLE_DCACHE)
void flush_cache (unsigned long start_addr, unsigned long size)
{
	unsigned long lsize = CONFIG_SYS_CACHELINE_SIZE;
	unsigned long addr = start_addr & ~(lsize - 1);
	unsigned long aend = (start_addr + size - 1) & ~(lsize - 1);

#ifdef CONFIG_ENABLE_L2CACHE
	while (1) {
#ifdef CONFIG_ENABLE_DCACHE
		v7_clean_dcache_line(addr);
#endif
#ifdef CONFIG_ENABLE_ICACHE
		v7_invalidate_icache_line(addr);
#endif
		if (addr == aend)
			break;
		addr += lsize;
	}

	addr = start_addr & ~(lsize - 1);
	while (1) {
		clean_and_invalidate_l2_cache_line (addr);
		if (addr == aend)
			break;
		addr += lsize;
	}

	addr = start_addr & ~(lsize - 1);
#endif
	while (1) {
#ifdef CONFIG_ENABLE_DCACHE
		v7_clean_and_invalidate_dcache_line(addr);
#endif
#ifdef CONFIG_ENABLE_ICACHE
		v7_invalidate_icache_line(addr);
#endif
		if (addr == aend)
			break;
		addr += lsize;
	}

}
#else
void flush_cache (unsigned long start_addr, unsigned long size)
{
}
#endif

#ifdef CONFIG_ENABLE_DCACHE
void invalidate_dcache_all (void)
{
#ifdef CONFIG_ENABLE_L2CACHE
	invalidate_l2_cache_all ();
#endif
	v7_invalidate_dcache_all ();
}

void invalidate_dcache_range(unsigned long start_addr, unsigned long stop)
{
	unsigned long lsize = CONFIG_SYS_CACHELINE_SIZE;
	unsigned long addr = start_addr & ~(lsize - 1);
	unsigned long aend = (stop - 1) & ~(lsize - 1);

#ifdef CONFIG_ENABLE_L2CACHE
	while (1) {
		invalidate_l2_cache_line (addr);
		if (addr == aend)
			break;
		addr += lsize;
	}

	addr = start_addr & ~(lsize - 1);
#endif
	while (1) {
		v7_invalidate_dcache_line(addr);
		if (addr == aend)
			break;
		addr += lsize;
	}
}

void flush_dcache_range(unsigned long start_addr, unsigned long stop)
{
	unsigned long lsize = CONFIG_SYS_CACHELINE_SIZE;
	unsigned long addr = start_addr & ~(lsize - 1);
	unsigned long aend = (stop - 1) & ~(lsize - 1);

#ifdef CONFIG_ENABLE_L2CACHE
	while (1) {
		v7_clean_dcache_line(addr);
		if (addr == aend)
			break;
		addr += lsize;
	}

	addr = start_addr & ~(lsize - 1);
	while (1) {
		clean_and_invalidate_l2_cache_line (addr);
		if (addr == aend)
			break;
		addr += lsize;
	}

	addr = start_addr & ~(lsize - 1);
#endif
	while (1) {
		v7_clean_and_invalidate_dcache_line(addr);
		if (addr == aend)
			break;
		addr += lsize;
	}
}

void flush_invalidate_dcache_all (void)
{
#ifdef CONFIG_ENABLE_L2CACHE
	v7_clean_dcache_all ();
	clean_and_invalidate_l2_cache_all ();
#endif
	v7_clean_and_invalidate_dcache_all ();
}

#else
void invalidate_dcache_all (void)
{
}

void invalidate_dcache_range(unsigned long start_addr, unsigned long stop)
{
}

void flush_dcache_range(unsigned long start_addr, unsigned long stop)
{
}

void flush_invalidate_dcache_all (void)
{
}
#endif
#else	/* CONFIG_TC90431 */
void  flush_cache (unsigned long dummy1, unsigned long dummy2)
{
#ifdef CONFIG_OMAP2420
	void arm1136_cache_flush(void);

	arm1136_cache_flush();
#endif
	return;
}
#endif	/* CONFIG_TC90431 */

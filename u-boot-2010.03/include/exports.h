#ifndef __EXPORTS_H__
#define __EXPORTS_H__

#ifndef __ASSEMBLY__

#include <common.h>

/* These are declarations of exported functions available in C code */
unsigned long get_version(void);
int  getc(void);
int  tstc(void);
void putc(const char);
void puts(const char*);
void printf(const char* fmt, ...);
void install_hdlr(int, interrupt_handler_t*, void*);
void free_hdlr(int);
void *malloc(size_t);
void free(void*);
void __udelay(unsigned long);
unsigned long get_timer(unsigned long);
void vprintf(const char *, va_list);
void do_reset (void);
unsigned long simple_strtoul(const char *cp,char **endp,unsigned int base);
char *getenv (char *name);
int setenv (char *varname, char *varvalue);
long simple_strtol(const char *cp,char **endp,unsigned int base);
int strcmp(const char * cs,const char * ct);
int ustrtoul(const char *cp, char **endp, unsigned int base);
#ifdef CONFIG_HAS_UID
void forceenv (char *varname, char *varvalue);
#endif
#if defined(CONFIG_CMD_I2C)
int i2c_write (uchar, uint, int , uchar* , int);
int i2c_read (uchar, uint, int , uchar* , int);
#endif
#include <spi.h>

void app_startup(char **);

#ifdef CONFIG_STANDALONE_ENABLE_CACHE
void invalidate_icache_all (void);
void invalidate_icache_range (unsigned long start, unsigned long stop);
void flush_cache (unsigned long start, unsigned long size);
void flush_dcache_range (unsigned long start, unsigned long stop);
void flush_invalidate_dcache_all (void);
void invalidate_dcache_all (void);
void invalidate_dcache_range (unsigned long start, unsigned long stop);
#ifdef CONFIG_ENABLE_MMU
void mmu_enable_cache_on (void);
void mmu_disable_cache_off (void);
#endif
#endif

#endif    /* ifndef __ASSEMBLY__ */

enum {
#define EXPORT_FUNC(x) XF_ ## x ,
#include <_exports.h>
#undef EXPORT_FUNC

	XF_MAX
};

#define XF_VERSION	6

#if defined(CONFIG_I386)
extern gd_t *global_data;
#endif

#endif	/* __EXPORTS_H__ */

/*
 * Copyright (C) 2006 Atmark Techno, Inc.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License. See the file "COPYING" in the main directory of this archive
 * for more details.
 */

#ifndef _ASM_MICROBLAZE_IRQ_H
#define _ASM_MICROBLAZE_IRQ_H

#define NR_IRQS 32
#include <asm-generic/irq.h>

#include <linux/interrupt.h>

extern unsigned int nr_irq;

#define NO_IRQ (-1)

struct pt_regs;
extern void do_IRQ(struct pt_regs *regs);

/** FIXME - not implement
 * irq_dispose_mapping - Unmap an interrupt
 * @virq: linux virq number of the interrupt to unmap
 */
static inline void irq_dispose_mapping(unsigned int virq)
{
	return;
}

#endif /* _ASM_MICROBLAZE_IRQ_H */

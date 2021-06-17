/*
 * Arch specific extensions to struct device
 *
 * This file is released under the GPLv2
 */
#ifndef ASMARM_DEVICE_H
#define ASMARM_DEVICE_H

struct dev_archdata {
#ifdef CONFIG_DMABOUNCE
	struct dmabounce_device_info *dmabounce;
#endif
#ifdef CONFIG_OF
	struct device_node *of_node;
#endif
#ifdef CONFIG_ACP_ENABLE
	int dma_coherent;
#endif
};

struct pdev_archdata {
};

#ifdef CONFIG_OF
/*
 * Taken from arch/powerpc/include/asm/device.h.
 * Should be dropped if "of: eliminate of_device->node and
 * dev_archdata->{of,prom}_node" is merged.
 */
static inline void dev_archdata_set_node(struct dev_archdata *ad,
					 struct device_node *np)
{
	ad->of_node = np;
}

static inline struct device_node *
dev_archdata_get_node(const struct dev_archdata *ad)
{
	return ad->of_node;
}
#endif /* CONFIG_OF */

#endif

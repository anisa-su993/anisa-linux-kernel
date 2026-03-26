// SPDX-License-Identifier: GPL-2.0
/*  Copyright(c) 2024 Intel Corporation. All rights reserved. */

#include <linux/device.h>
#include <cxl.h>

#include "core.h"

static void cxled_release_extent(struct cxl_endpoint_decoder *cxled,
				 struct cxled_extent *ed_extent)
{
	struct cxl_memdev_state *mds = cxled_to_mds(cxled);
	struct device *dev = &cxled->cxld.dev;

	dev_dbg(dev, "Remove extent %pra (%pU)\n",
		&ed_extent->dpa_range, &ed_extent->uuid);
	memdev_release_extent(mds, &ed_extent->dpa_range);
	kfree(ed_extent);
}

static void free_region_extent(struct region_extent *region_extent)
{
	struct cxled_extent *ed_extent;
	unsigned long index;

	/*
	 * Remove from each endpoint decoder the extent which backs this region
	 * extent
	 */
	xa_for_each(&region_extent->decoder_extents, index, ed_extent)
		cxled_release_extent(ed_extent->cxled, ed_extent);
	xa_destroy(&region_extent->decoder_extents);
	region_extent->cxlr_dax->region_extent = NULL;
	kfree(region_extent);
}

static void region_extent_release(struct device *dev)
{
	struct region_extent *region_extent = to_region_extent(dev);

	free_region_extent(region_extent);
}

static const struct device_type region_extent_type = {
	.name = "extent",
	.release = region_extent_release,
};

bool is_region_extent(struct device *dev)
{
	return dev->type == &region_extent_type;
}
EXPORT_SYMBOL_NS_GPL(is_region_extent, "CXL");

static void region_extent_unregister(void *ext)
{
	struct region_extent *region_extent = ext;

	dev_dbg(&region_extent->dev, "DAX region rm extent HPA %pra\n",
		&region_extent->hpa_range);
	device_unregister(&region_extent->dev);
}

static void region_rm_extent(struct region_extent *region_extent)
{
	struct device *region_dev = region_extent->dev.parent;

	devm_release_action(region_dev, region_extent_unregister, region_extent);
}

static struct region_extent *
alloc_region_extent(struct cxl_dax_region *cxlr_dax, struct range *hpa_range,
		    uuid_t *uuid)
{
	struct region_extent *region_extent __free(kfree) =
				kzalloc(sizeof(*region_extent), GFP_KERNEL);
	if (!region_extent)
		return ERR_PTR(-ENOMEM);

	region_extent->hpa_range = *hpa_range;
	region_extent->cxlr_dax = cxlr_dax;
	uuid_copy(&region_extent->uuid, uuid);
	region_extent->dev.id = 0;
	xa_init(&region_extent->decoder_extents);
	return no_free_ptr(region_extent);
}

static int online_region_extent(struct region_extent *region_extent)
{
	struct cxl_dax_region *cxlr_dax = region_extent->cxlr_dax;
	struct device *dev = &region_extent->dev;
	int rc;

	device_initialize(dev);
	device_set_pm_not_required(dev);
	dev->parent = &cxlr_dax->dev;
	dev->type = &region_extent_type;
	rc = dev_set_name(dev, "extent%d.%d", cxlr_dax->cxlr->id, dev->id);
	if (rc)
		goto err;

	rc = device_add(dev);
	if (rc)
		goto err;

	dev_dbg(dev, "region extent HPA %pra\n", &region_extent->hpa_range);
	return devm_add_action_or_reset(&cxlr_dax->dev, region_extent_unregister,
					region_extent);

err:
	dev_err(&cxlr_dax->dev, "Failed to initialize region extent HPA %pra\n",
		&region_extent->hpa_range);

	put_device(dev);
	return rc;
}

static bool extents_contain(struct cxl_dax_region *cxlr_dax,
			    struct cxl_endpoint_decoder *cxled,
			    struct range *new_range)
{
	struct region_extent *re = cxlr_dax->region_extent;
	struct cxled_extent *entry;
	unsigned long index;

	if (!re)
		return false;

	xa_for_each(&re->decoder_extents, index, entry) {
		if (cxled == entry->cxled &&
		    range_contains(&entry->dpa_range, new_range))
			return true;
	}
	return false;
}

static bool extents_overlap(struct cxl_dax_region *cxlr_dax,
			    struct cxl_endpoint_decoder *cxled,
			    struct range *new_range)
{
	struct region_extent *re = cxlr_dax->region_extent;
	struct cxled_extent *entry;
	unsigned long index;

	if (!re)
		return false;

	xa_for_each(&re->decoder_extents, index, entry) {
		if (cxled == entry->cxled &&
		    range_overlaps(&entry->dpa_range, new_range))
			return true;
	}
	return false;
}

static void calc_hpa_range(struct cxl_endpoint_decoder *cxled,
			   struct cxl_dax_region *cxlr_dax,
			   struct range *dpa_range,
			   struct range *hpa_range)
{
	resource_size_t dpa_offset, hpa;

	dpa_offset = dpa_range->start - cxled->dpa_res->start;
	hpa = cxled->cxld.hpa_range.start + dpa_offset;

	hpa_range->start = hpa - cxlr_dax->hpa_range.start;
	hpa_range->end = hpa_range->start + range_len(dpa_range) - 1;
}

static void recalc_hpa_range(struct region_extent *re)
{
	struct cxled_extent *ed_extent;
	struct range hpa_range;
	unsigned long index;
	bool first = true;

	xa_for_each(&re->decoder_extents, index, ed_extent) {
		calc_hpa_range(ed_extent->cxled, re->cxlr_dax,
			       &ed_extent->dpa_range, &hpa_range);
		if (first) {
			re->hpa_range = hpa_range;
			first = false;
		} else {
			re->hpa_range.start = min(re->hpa_range.start,
						  hpa_range.start);
			re->hpa_range.end = max(re->hpa_range.end,
						hpa_range.end);
		}
	}
}

static void cxlr_rm_decoder_extents(struct cxl_dax_region *cxlr_dax,
				    struct cxl_endpoint_decoder *cxled,
				    struct range *dpa_range)
{
	struct region_extent *re = cxlr_dax->region_extent;
	struct cxled_extent *ed_extent;
	unsigned long index;

	if (!re)
		return;

	xa_for_each(&re->decoder_extents, index, ed_extent) {
		if (ed_extent->cxled == cxled &&
		    range_overlaps(&ed_extent->dpa_range, dpa_range)) {
			dev_dbg(&re->dev, "Remove decoder extent %pra\n",
				&ed_extent->dpa_range);
			xa_erase(&re->decoder_extents, index);
			cxled_release_extent(cxled, ed_extent);
		}
	}

	if (xa_empty(&re->decoder_extents)) {
		dev_dbg(&re->dev, "Remove region extent HPA %pra\n",
			&re->hpa_range);
		region_rm_extent(re);
	} else {
		recalc_hpa_range(re);
	}
}

int cxl_rm_extent(struct cxl_memdev_state *mds, struct cxl_extent *extent)
{
	u64 start_dpa = le64_to_cpu(extent->start_dpa);
	struct cxl_memdev *cxlmd = mds->cxlds.cxlmd;
	struct cxl_endpoint_decoder *cxled;
	struct range dpa_range;
	struct cxl_region *cxlr;

	dpa_range = (struct range) {
		.start = start_dpa,
		.end = start_dpa + le64_to_cpu(extent->length) - 1,
	};

	guard(rwsem_read)(&cxl_rwsem.region);
	cxlr = cxl_dpa_to_region(cxlmd, start_dpa, &cxled);
	if (!cxlr) {
		/*
		 * No region can happen here for a few reasons:
		 *
		 * 1) Extents were accepted and the host crashed/rebooted
		 *    leaving them in an accepted state.  On reboot the host
		 *    has not yet created a region to own them.
		 *
		 * 2) Region destruction won the race with the device releasing
		 *    all the extents.  Here the release will be a duplicate of
		 *    the one sent via region destruction.
		 *
		 * 3) The device is confused and releasing extents for which no
		 *    region ever existed.
		 *
		 * In all these cases make sure the device knows we are not
		 * using this extent.
		 */
		memdev_release_extent(mds, &dpa_range);
		return -ENXIO;
	}

	cxlr_rm_decoder_extents(cxlr->cxlr_dax, cxled, &dpa_range);
	return 0;
}

static int cxlr_add_extent(struct cxl_dax_region *cxlr_dax,
			   struct cxl_endpoint_decoder *cxled,
			   struct cxled_extent *ed_extent)
{
	struct region_extent *region_extent;
	struct range hpa_range;
	int rc;

	calc_hpa_range(cxled, cxlr_dax, &ed_extent->dpa_range, &hpa_range);

	region_extent = cxlr_dax->region_extent;
	if (region_extent) {
		/* Add decoder extent to existing region extent */
		rc = xa_insert(&region_extent->decoder_extents,
			       ed_extent->dpa_range.start, ed_extent,
			       GFP_KERNEL);
		if (rc) {
			kfree(ed_extent);
			return rc;
		}
		region_extent->hpa_range.start = min(region_extent->hpa_range.start,
						     hpa_range.start);
		region_extent->hpa_range.end = max(region_extent->hpa_range.end,
						   hpa_range.end);
		return 0;
	}

	/* First decoder extent - create new region extent */
	region_extent = alloc_region_extent(cxlr_dax, &hpa_range, &ed_extent->uuid);
	if (IS_ERR(region_extent)) {
		kfree(ed_extent);
		return PTR_ERR(region_extent);
	}

	rc = xa_insert(&region_extent->decoder_extents,
		       ed_extent->dpa_range.start, ed_extent, GFP_KERNEL);
	if (rc) {
		free_region_extent(region_extent);
		kfree(ed_extent);
		return rc;
	}

	/* device model handles freeing region_extent */
	rc = online_region_extent(region_extent);
	if (rc)
		return rc;

	cxlr_dax->region_extent = region_extent;
	return 0;
}

/* Callers are expected to ensure cxled has been attached to a region */
int cxl_add_extent(struct cxl_memdev_state *mds, struct cxl_extent *extent)
{
	u64 start_dpa = le64_to_cpu(extent->start_dpa);
	struct cxl_memdev *cxlmd = mds->cxlds.cxlmd;
	struct cxl_endpoint_decoder *cxled;
	struct range ed_range, ext_range;
	struct cxl_dax_region *cxlr_dax;
	struct cxled_extent *ed_extent;
	struct cxl_region *cxlr;
	struct device *dev;

	ext_range = (struct range) {
		.start = start_dpa,
		.end = start_dpa + le64_to_cpu(extent->length) - 1,
	};

	guard(rwsem_read)(&cxl_rwsem.region);
	cxlr = cxl_dpa_to_region(cxlmd, start_dpa, &cxled);
	if (!cxlr)
		return -ENXIO;

	cxlr_dax = cxled->cxld.region->cxlr_dax;
	dev = &cxled->cxld.dev;
	ed_range = (struct range) {
		.start = cxled->dpa_res->start,
		.end = cxled->dpa_res->end,
	};

	dev_dbg(&cxled->cxld.dev, "Checking ED (%pr) for extent %pra\n",
		cxled->dpa_res, &ext_range);

	if (!range_contains(&ed_range, &ext_range)) {
		dev_err_ratelimited(dev,
				    "DC extent DPA %pra (%pU) is not fully in ED %pra\n",
				    &ext_range, extent->uuid, &ed_range);
		return -ENXIO;
	}

	/*
	 * Allowing duplicates or extents which are already in an accepted
	 * range simplifies extent processing, especially when dealing with the
	 * cxl dax driver scanning for existing extents.
	 */
	if (extents_contain(cxlr_dax, cxled, &ext_range)) {
		dev_warn_ratelimited(dev, "Extent %pra exists; accept again\n",
				     &ext_range);
		return 0;
	}

	if (extents_overlap(cxlr_dax, cxled, &ext_range))
		return -ENXIO;

	ed_extent = kzalloc(sizeof(*ed_extent), GFP_KERNEL);
	if (!ed_extent)
		return -ENOMEM;

	ed_extent->cxled = cxled;
	ed_extent->dpa_range = ext_range;
	import_uuid(&ed_extent->uuid, extent->uuid);

	dev_dbg(dev, "Add extent %pra (%pU)\n", &ed_extent->dpa_range, &ed_extent->uuid);

	return cxlr_add_extent(cxlr_dax, cxled, ed_extent);
}

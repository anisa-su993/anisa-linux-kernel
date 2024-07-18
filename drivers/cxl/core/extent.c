// SPDX-License-Identifier: GPL-2.0
/*  Copyright(c) 2024 Intel Corporation. All rights reserved. */

#include <linux/device.h>
#include <cxl.h>

#include "core.h"


static void cxled_release_extent(struct cxl_endpoint_decoder *cxled,
				 struct dc_extent *dc_extent)
{
	struct cxl_memdev_state *mds = cxled_to_mds(cxled);
	struct device *dev = &cxled->cxld.dev;

	dev_dbg(dev, "Remove extent %pra (%pU)\n",
		&dc_extent->dpa_range, &dc_extent->uuid);
	memdev_release_extent(mds, &dc_extent->dpa_range);
}

static void free_tag_group(struct cxl_dc_tag_group *group)
{
	xa_destroy(&group->dc_extents);
	kfree(group);
}

static void dc_extent_release(struct device *dev)
{
	struct dc_extent *dc_extent = to_dc_extent(dev);
	struct cxl_dc_tag_group *group = dc_extent->group;

	cxled_release_extent(dc_extent->cxled, dc_extent);
	xa_erase(&group->cxlr_dax->dc_extents, dc_extent->dev.id);
	xa_erase(&group->dc_extents, dc_extent->shared_extn_seq);
	group->nr_extents--;
	if (!group->nr_extents)
		free_tag_group(group);
	kfree(dc_extent);
}

static const struct device_type dc_extent_type = {
	.name = "extent",
	.release = dc_extent_release,
};

bool is_dc_extent(struct device *dev)
{
	return dev->type == &dc_extent_type;
}
EXPORT_SYMBOL_NS_GPL(is_dc_extent, "CXL");

static void dc_extent_unregister(void *ext)
{
	struct dc_extent *dc_extent = ext;

	dev_dbg(&dc_extent->dev, "DAX region rm extent HPA %pra\n",
		&dc_extent->hpa_range);
	device_unregister(&dc_extent->dev);
}

static void rm_tag_group(struct cxl_dc_tag_group *group)
{
	struct device *region_dev = &group->cxlr_dax->dev;
	struct dc_extent *dc_extent;
	unsigned long index;

	/*
	 * Tagged allocations release atomically.  Invalidate caches once
	 * for the whole group (no mappings exist at this point — partial
	 * release is not supported, so all members are leaving use
	 * together) before tearing down each dc_extent device.
	 *
	 * Pin @group across the walk: each devm_release_action runs the
	 * dc_extent_unregister action synchronously, which drops the last
	 * reference on the dc_extent device and fires dc_extent_release.
	 * The release decrements group->nr_extents and, on the final
	 * decrement, frees @group.  Without the pin the next iteration's
	 * xa_find_after() dereferences a freed xarray.
	 */
	cxl_region_invalidate_memregion(group->cxlr_dax->cxlr);

	group->nr_extents++;
	xa_for_each(&group->dc_extents, index, dc_extent)
		devm_release_action(region_dev, dc_extent_unregister, dc_extent);
	group->nr_extents--;
	if (!group->nr_extents)
		free_tag_group(group);
}

static struct cxl_dc_tag_group *
alloc_tag_group(struct cxl_dax_region *cxlr_dax, uuid_t *uuid)
{
	struct cxl_dc_tag_group *group __free(kfree) =
				kzalloc(sizeof(*group), GFP_KERNEL);
	if (!group)
		return ERR_PTR(-ENOMEM);

	group->cxlr_dax = cxlr_dax;
	uuid_copy(&group->uuid, uuid);
	xa_init(&group->dc_extents);
	return no_free_ptr(group);
}

static void cleanup_pending_dc_extent(struct dc_extent *dc_extent)
{
	struct cxl_dc_tag_group *group = dc_extent->group;

	cxled_release_extent(dc_extent->cxled, dc_extent);
	xa_erase(&group->dc_extents, dc_extent->shared_extn_seq);
	group->nr_extents--;
	if (!group->nr_extents)
		free_tag_group(group);
	kfree(dc_extent);
}

int online_tag_group(struct cxl_dc_tag_group *group)
{
	struct cxl_dax_region *cxlr_dax = group->cxlr_dax;
	struct dc_extent *dc_extent;
	unsigned long index;
	int rc = 0;

	/*
	 * Seed nr_extents with the full group size plus a +1 pin held by
	 * this function.  The size counts every dc_extent that might
	 * decrement nr_extents on cleanup; the pin keeps @group alive
	 * across the body even if every dc_extent release fires inside
	 * the loop (e.g. devm_add_action_or_reset failure on the only
	 * pending extent).  The pin is dropped at the end of the function.
	 */
	xa_for_each(&group->dc_extents, index, dc_extent)
		group->nr_extents++;
	group->nr_extents++;

	xa_for_each(&group->dc_extents, index, dc_extent) {
		struct device *dev = &dc_extent->dev;
		u32 id;

		device_initialize(dev);
		device_set_pm_not_required(dev);
		dev->parent = &cxlr_dax->dev;
		dev->type = &dc_extent_type;

		rc = xa_alloc(&cxlr_dax->dc_extents, &id, dc_extent,
			      xa_limit_32b, GFP_KERNEL);
		if (rc < 0) {
			put_device(dev);
			break;
		}
		dev->id = id;

		rc = dev_set_name(dev, "extent%d.%d", cxlr_dax->cxlr->id,
				  dev->id);
		if (rc) {
			xa_erase(&cxlr_dax->dc_extents, dev->id);
			put_device(dev);
			break;
		}

		rc = device_add(dev);
		if (rc) {
			xa_erase(&cxlr_dax->dc_extents, dev->id);
			put_device(dev);
			break;
		}

		dev_dbg(dev, "dc_extent HPA %pra (%pU)\n",
			&dc_extent->hpa_range, &group->uuid);

		rc = devm_add_action_or_reset(&cxlr_dax->dev,
					      dc_extent_unregister, dc_extent);
		if (rc)
			break;
	}

	if (rc) {
		/*
		 * Unwind every remaining dc_extent in the group.  The pin
		 * above keeps @group alive across this walk.  Distinguish
		 * onlined dc_extents (have a devm action) from pending ones
		 * via devm_remove_action_nowarn(): a 0 return means the
		 * action was installed and is now consumed, so we run the
		 * unregister ourselves; -ENOENT means pending.
		 */
		xa_for_each(&group->dc_extents, index, dc_extent) {
			int r = devm_remove_action_nowarn(&cxlr_dax->dev,
							  dc_extent_unregister,
							  dc_extent);
			if (r == 0)
				dc_extent_unregister(dc_extent);
			else
				cleanup_pending_dc_extent(dc_extent);
		}
	}

	/* Drop the pin; if nothing else still references @group, free it. */
	group->nr_extents--;
	if (!group->nr_extents)
		free_tag_group(group);
	return rc;
}

static bool extents_contain(struct cxl_dax_region *cxlr_dax,
			    struct cxl_endpoint_decoder *cxled,
			    struct range *new_range)
{
	struct dc_extent *entry;
	unsigned long i;

	xa_for_each(&cxlr_dax->dc_extents, i, entry) {
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
	struct dc_extent *entry;
	unsigned long i;

	xa_for_each(&cxlr_dax->dc_extents, i, entry) {
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

int cxl_rm_extent(struct cxl_memdev_state *mds, struct cxl_extent *extent)
{
	u64 start_dpa = le64_to_cpu(extent->start_dpa);
	struct cxl_memdev *cxlmd = mds->cxlds.cxlmd;
	struct cxl_endpoint_decoder *cxled;
	struct cxl_dax_region *cxlr_dax;
	struct cxl_dc_tag_group *group;
	struct dc_extent *dc_extent;
	struct cxl_region *cxlr;
	struct range dpa_range;
	unsigned long idx;
	uuid_t tag;

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

	cxlr_dax = cxlr->cxlr_dax;
	import_uuid(&tag, extent->uuid);

	/*
	 * Find the dc_extent whose DPA range covers the released range and
	 * whose tag matches.  The release targets the entire containing
	 * tag group atomically; partial release is not supported.
	 */
	group = NULL;
	xa_for_each(&cxlr_dax->dc_extents, idx, dc_extent) {
		if (dc_extent->cxled != cxled)
			continue;
		if (!range_contains(&dc_extent->dpa_range, &dpa_range))
			continue;
		if (!uuid_equal(&dc_extent->group->uuid, &tag))
			continue;
		group = dc_extent->group;
		break;
	}
	if (!group) {
		dev_err(&cxlr_dax->dev,
			"release DPA %pra (%pU) matches no dc_extent\n",
			&dpa_range, &tag);
		return -EINVAL;
	}


	/* Release the entire tag group */
	rm_tag_group(group);
	return 0;
}

static int cxlr_add_extent(struct cxl_memdev_state *mds,
			   struct cxl_dax_region *cxlr_dax,
			   struct cxl_endpoint_decoder *cxled,
			   struct dc_extent *dc_extent)
{
	struct cxl_dc_tag_group **group = &mds->add_ctx.group;
	int rc;

	if (!*group) {
		dev_dbg(&cxlr_dax->dev, "Alloc new tag group\n");
		*group = alloc_tag_group(cxlr_dax, &dc_extent->uuid);
		if (IS_ERR(*group)) {
			rc = PTR_ERR(*group);
			*group = NULL;
			kfree(dc_extent);
			return rc;
		}
	} else {
		dev_dbg(&cxlr_dax->dev, "Append dc_extent to tag group\n");
	}

	dc_extent->group = *group;

	/*
	 * Key by shared_extn_seq so iteration order = assembly order.
	 * Sharable groups have unique 1..n seqs (cxl_check_group_seq);
	 * non-sharable groups carry seq 0 and the group is expected to be
	 * a single extent.  A collision here signals a cxl-side validation
	 * gap.
	 */
	rc = xa_insert(&(*group)->dc_extents, dc_extent->shared_extn_seq,
		       dc_extent, GFP_KERNEL);
	if (rc) {
		dev_WARN_ONCE(&cxlr_dax->dev, rc == -EBUSY,
			"duplicate shared_extn_seq %u in tag %pUb\n",
			dc_extent->shared_extn_seq, &dc_extent->uuid);
		kfree(dc_extent);
		return rc;
	}

	return 0;
}

/* Callers are expected to ensure cxled has been attached to a region */
int cxl_add_extent(struct cxl_memdev_state *mds, struct cxl_extent *extent)
{
	u64 start_dpa = le64_to_cpu(extent->start_dpa);
	struct cxl_memdev *cxlmd = mds->cxlds.cxlmd;
	struct cxl_dc_tag_group *pending_group = mds->add_ctx.group;
	struct cxl_endpoint_decoder *cxled;
	struct range ed_range, ext_range;
	struct cxl_dax_region *cxlr_dax;
	struct dc_extent *dc_extent;
	struct cxl_region *cxlr;
	struct range hpa_range;
	struct device *dev;

	ext_range = (struct range) {
		.start = start_dpa,
		.end = start_dpa + le64_to_cpu(extent->length) - 1,
	};

	guard(rwsem_read)(&cxl_rwsem.region);
	cxlr = cxl_dpa_to_region(cxlmd, start_dpa, &cxled);
	if (!cxlr)
		return -ENXIO;

	cxlr_dax = cxlr->cxlr_dax;

	if (pending_group &&
	    !uuid_equal((uuid_t *)extent->uuid, &pending_group->uuid)) {
		return -EINVAL;
	}

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

	calc_hpa_range(cxled, cxlr_dax, &ext_range, &hpa_range);

	dc_extent = kzalloc(sizeof(*dc_extent), GFP_KERNEL);
	if (!dc_extent)
		return -ENOMEM;

	dc_extent->cxled = cxled;
	dc_extent->dpa_range = ext_range;
	dc_extent->hpa_range = hpa_range;
	dc_extent->shared_extn_seq = le16_to_cpu(extent->shared_extn_seq);
	import_uuid(&dc_extent->uuid, extent->uuid);

	dev_dbg(dev, "Add extent %pra (%pU)\n", &dc_extent->dpa_range,
		&dc_extent->uuid);

	return cxlr_add_extent(mds, cxlr_dax, cxled, dc_extent);
}

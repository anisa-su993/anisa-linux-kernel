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
	/* Drop the pin taken in alloc_tag_group(). */
	put_device(&group->cxlr_dax->dev);
	kfree(group);
}

static void dc_extent_release(struct device *dev)
{
	struct dc_extent *dc_extent = to_dc_extent(dev);
	struct cxl_dc_tag_group *group;

	if (!dc_extent)
		return;

	group = dc_extent->group;
	if (!group->skip_device_release)
		cxled_release_extent(dc_extent->cxled, dc_extent);
	xa_erase(&group->cxlr_dax->dc_extents, dc_extent->dev.id);
	xa_erase(&group->dc_extents, dc_extent->seq_num);
	group->nr_extents--;
	if (!group->nr_extents)
		free_tag_group(group);
	kfree_rcu(dc_extent, rcu);
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

	/*
	 * Pin cxlr_dax: it is used after cxl_rwsem.region is dropped, so a
	 * refcount must keep it alive.  Released in free_tag_group().
	 */
	get_device(&cxlr_dax->dev);

	return no_free_ptr(group);
}

/*
 * Find the DC (Dynamic Capacity) partition that fully contains @ext_range,
 * or NULL if the extent falls outside every DC partition on this memdev.
 * The returned pointer is owned by mds->cxlds.part[] and lives for the
 * lifetime of the memdev.
 */
const struct cxl_dpa_partition *
cxl_extent_dc_partition(struct cxl_memdev_state *mds,
			struct cxl_extent *extent,
			struct range *ext_range)
{
	struct cxl_dev_state *cxlds = &mds->cxlds;
	struct device *dev = mds->cxlds.dev;

	/*
	 * A device-side error could cause end < start, which range_contains()
	 * would treat as contained in any partition.
	 */
	if (ext_range->end < ext_range->start) {
		dev_err_ratelimited(dev,
				    "DC extent DPA %pra (%pU) has invalid length (firmware bug)\n",
				    ext_range, extent->uuid);
		return NULL;
	}

	for (int i = 0; i < cxlds->nr_partitions; i++) {
		struct cxl_dpa_partition *part = &cxlds->part[i];
		struct range partition_range = {
			.start = part->res.start,
			.end = part->res.end,
		};

		if (part->mode != CXL_PARTMODE_DYNAMIC_RAM)
			continue;

		if (range_contains(&partition_range, ext_range)) {
			dev_dbg(dev, "DC extent DPA %pra (DCR:%pra)(%pU)\n",
				ext_range, &partition_range, extent->uuid);
			return part;
		}
	}

	dev_err_ratelimited(dev,
			    "DC extent DPA %pra (%pU) is not in a valid DC partition\n",
			    ext_range, extent->uuid);
	return NULL;
}

/*
 * Stage 1 of the add pipeline: pure, no allocation.  Resolve the extent
 * to its region/endpoint decoder and ext_range, and verify the range
 * fits in the resolved endpoint decoder's DPA resource.
 *
 * Caller must hold cxl_rwsem.region for read (cxl_dpa_to_region()).
 * On success, @out_cxled / @out_cxlr_dax / @out_ext_range carry the
 * resolved handles consumed by the rest of the pipeline.
 */
static int cxl_validate_extent(struct cxl_memdev_state *mds,
			       struct cxl_extent *extent,
			       struct cxl_endpoint_decoder **out_cxled,
			       struct cxl_dax_region **out_cxlr_dax,
			       struct range *out_ext_range)
{
	u64 start_dpa = le64_to_cpu(extent->start_dpa);
	struct cxl_memdev *cxlmd = mds->cxlds.cxlmd;
	struct device *dev = mds->cxlds.dev;
	const struct cxl_dpa_partition *part;
	struct cxl_endpoint_decoder *cxled;
	struct cxl_region *cxlr;
	struct range ext_range = (struct range) {
		.start = start_dpa,
		.end = start_dpa + le64_to_cpu(extent->length) - 1,
	};
	struct range ed_range;
	uuid_t uuid;

	import_uuid(&uuid, extent->uuid);

	part = cxl_extent_dc_partition(mds, extent, &ext_range);
	if (!part)
		return -ENXIO;

	if (part->shareable) {
		if (uuid_is_null(&uuid)) {
			dev_err_ratelimited(dev,
				"DC extent DPA %pra: sharable-partition extent has null tag (firmware bug)\n",
				&ext_range);
			return -ENXIO;
		}
	} else if (le16_to_cpu(extent->shared_extn_seq)) {
		dev_err_ratelimited(dev,
			"DC extent DPA %pra (%pU): non-sharable partition but shared_extn_seq=%u (firmware bug)\n",
			&ext_range, &uuid, le16_to_cpu(extent->shared_extn_seq));
		return -ENXIO;
	}

	cxlr = cxl_dpa_to_region(cxlmd, start_dpa, &cxled);
	if (!cxlr || !cxlr->cxlr_dax)
		return -ENXIO;

	ed_range = (struct range) {
		.start = cxled->dpa_res->start,
		.end = cxled->dpa_res->end,
	};
	if (!range_contains(&ed_range, &ext_range)) {
		dev_err_ratelimited(&cxled->cxld.dev,
				    "DC extent DPA %pra (%pU) is not fully in ED %pra\n",
				    &ext_range, extent->uuid, &ed_range);
		return -ENXIO;
	}

	*out_cxled = cxled;
	*out_cxlr_dax = cxlr->cxlr_dax;
	*out_ext_range = ext_range;
	return 0;
}

enum cxl_extent_class {
	CXL_EXT_NEW,
	CXL_EXT_DUPLICATE,
	CXL_EXT_OVERLAP,
};

/*
 * Stage 2: classify @ext_range against extents already accepted on this
 * cxlr_dax+cxled.  Walks cxlr_dax->dc_extents once: a stored extent that
 * fully contains @ext_range means a duplicate accept (idempotent, fine);
 * a stored extent that only overlaps means an inconsistent offer.
 */
static enum cxl_extent_class
cxlr_dax_classify_extent(struct cxl_dax_region *cxlr_dax,
			 struct cxl_endpoint_decoder *cxled,
			 const struct range *ext_range)
{
	struct dc_extent *entry;
	unsigned long i;

	/* kfree_rcu() defers the free; hold RCU so entries stay live while walked */
	guard(rcu)();
	xa_for_each(&cxlr_dax->dc_extents, i, entry) {
		if (entry->cxled != cxled)
			continue;
		if (range_contains(&entry->dpa_range, ext_range))
			return CXL_EXT_DUPLICATE;
		if (range_overlaps(&entry->dpa_range, ext_range))
			return CXL_EXT_OVERLAP;
	}
	return CXL_EXT_NEW;
}

/*
 * Stage 3: allocate and populate a dc_extent for an already-validated,
 * already-classified-as-new @ext_range.  Only -ENOMEM can fail here.
 */
static struct dc_extent *
dc_extent_build(struct cxl_endpoint_decoder *cxled,
		struct cxl_dax_region *cxlr_dax,
		struct cxl_extent *extent,
		const struct range *ext_range, u16 seq_num)
{
	resource_size_t dpa_offset = ext_range->start - cxled->dpa_res->start;
	resource_size_t hpa = cxled->cxld.hpa_range.start + dpa_offset;
	struct dc_extent *dc_extent;

	dc_extent = kzalloc(sizeof(*dc_extent), GFP_KERNEL);
	if (!dc_extent)
		return ERR_PTR(-ENOMEM);

	dc_extent->cxled = cxled;
	dc_extent->dpa_range = *ext_range;
	dc_extent->hpa_range.start = hpa - cxlr_dax->hpa_range.start;
	dc_extent->hpa_range.end = dc_extent->hpa_range.start +
				   range_len(ext_range) - 1;
	dc_extent->seq_num = seq_num;
	import_uuid(&dc_extent->uuid, extent->uuid);
	return dc_extent;
}

/*
 * Stage 4: insert @dc_extent into the pending tag group.  All extents in
 * one More-chain group share a UUID — enforced here as the group is
 * either being created (first extent) or appended to.  On any failure
 * the dc_extent is freed.
 *
 * Returns 1 on success to allow caller (cxl_add_extent) to distinguish
 * between accepting a new extent, accepting a duplicate, or error.
 */
static int cxlr_add_extent(struct cxl_memdev_state *mds,
			   struct cxl_dax_region *cxlr_dax,
			   struct dc_extent *dc_extent)
{
	struct cxl_dc_tag_group **group = &mds->add_ctx.group;
	int rc;

	if (*group && !uuid_equal(&(*group)->uuid, &dc_extent->uuid)) {
		kfree(dc_extent);
		return -EINVAL;
	}

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
	 * Key by @seq_num so iteration order equals assembly order.  @seq_num
	 * is a dense 0..n-1 index (see &struct dc_extent), so a collision
	 * here signals a cxl-side validation gap.
	 */
	rc = xa_insert(&(*group)->dc_extents, dc_extent->seq_num,
		       dc_extent, GFP_KERNEL);
	if (rc) {
		dev_WARN_ONCE(&cxlr_dax->dev, rc == -EBUSY,
			"duplicate seq_num %u in tag %pUb\n",
			dc_extent->seq_num, &dc_extent->uuid);
		kfree(dc_extent);
		return rc;
	}

	return 1;
}

/*
 * Returns 1 for a successfully added extent, 0 for a duplicate extent,
 * and <0 on error
 */
int cxl_add_extent(struct cxl_memdev_state *mds, struct cxl_extent *extent,
		   u16 seq_num)
{
	struct cxl_endpoint_decoder *cxled;
	struct cxl_dax_region *cxlr_dax;
	struct dc_extent *dc_extent;
	struct range ext_range;
	int rc;

	guard(rwsem_read)(&cxl_rwsem.region);

	rc = cxl_validate_extent(mds, extent, &cxled, &cxlr_dax, &ext_range);
	if (rc)
		return rc;

	switch (cxlr_dax_classify_extent(cxlr_dax, cxled, &ext_range)) {
	case CXL_EXT_DUPLICATE:
		/*
		 * Idempotent accept simplifies the dax-side scan for existing
		 * extents on region creation; reply success without duplicating.
		 */
		dev_warn_ratelimited(&cxled->cxld.dev,
				     "Extent %pra exists; accept again\n",
				     &ext_range);
		return 0;
	case CXL_EXT_OVERLAP:
		return -ENXIO;
	case CXL_EXT_NEW:
		break;
	}

	dc_extent = dc_extent_build(cxled, cxlr_dax, extent, &ext_range,
				    seq_num);
	if (IS_ERR(dc_extent))
		return PTR_ERR(dc_extent);

	dev_dbg(&cxled->cxld.dev, "Add extent %pra (%pU)\n",
		&dc_extent->dpa_range, &dc_extent->uuid);

	/* returns 1 on success, <0 error*/
	return cxlr_add_extent(mds, cxlr_dax, dc_extent);
}

static void dc_extent_unregister(void *ext)
{
	struct dc_extent *dc_extent = ext;

	dev_dbg(&dc_extent->dev, "DAX region rm extent HPA %pra\n",
		&dc_extent->hpa_range);
	device_unregister(&dc_extent->dev);
}

/* shared_extn_seq is reserved outside sharable partitions (CXL r4.0 Table 8-230) */
static bool cxled_seq_matters(struct cxl_endpoint_decoder *cxled)
{
	struct cxl_dev_state *cxlds = cxled_to_memdev(cxled)->cxlds;

	return cxlds->part[cxled->part].shareable;
}

/**
 * cxl_resolve_extent() - locate the tag group a released extent belongs to
 * @mds: memdev state
 * @extent: extent from a DC Release-Capacity record
 * @cxlrp: returns the region owning the DPA, or NULL if untracked
 * @groupp: returns the matching tag group, or NULL if none
 *
 * Pure lookup, no side effects: the caller validates the whole chain before
 * anything is torn down.
 *
 * Return: 0 on a successful lookup (with *@groupp possibly NULL), -ENXIO if
 * the host is not tracking this DPA at all (no region, or no dax region).
 * The latter is not an error for the chain: the host holds no capacity for
 * it, so it can simply be acknowledged.
 */
int cxl_resolve_extent(struct cxl_memdev_state *mds, struct cxl_extent *extent,
		       struct cxl_region **cxlrp,
		       struct cxl_dc_tag_group **groupp)
{
	u64 start_dpa = le64_to_cpu(extent->start_dpa);
	struct cxl_memdev *cxlmd = mds->cxlds.cxlmd;
	struct cxl_endpoint_decoder *cxled;
	struct cxl_dax_region *cxlr_dax;
	struct dc_extent *dc_extent;
	struct cxl_region *cxlr;
	struct range dpa_range;
	unsigned long idx;
	bool seq_matters;
	uuid_t tag;

	*cxlrp = NULL;
	*groupp = NULL;

	dpa_range = (struct range) {
		.start = start_dpa,
		.end = start_dpa + le64_to_cpu(extent->length) - 1,
	};

	cxlr = cxl_dpa_to_region(cxlmd, start_dpa, &cxled);
	if (!cxlr)
		return -ENXIO;

	cxlr_dax = cxlr->cxlr_dax;
	if (!cxlr_dax)
		return -ENXIO;

	*cxlrp = cxlr;
	import_uuid(&tag, extent->uuid);
	seq_matters = cxled_seq_matters(cxled);

	/* RCU keeps entries live during the walk; teardown happens later. */
	scoped_guard(rcu) {
		xa_for_each(&cxlr_dax->dc_extents, idx, dc_extent) {
			if (dc_extent->cxled != cxled)
				continue;
			if (!range_contains(&dc_extent->dpa_range, &dpa_range))
				continue;
			if (!uuid_equal(&dc_extent->group->uuid, &tag))
				continue;
			if (seq_matters && dc_extent->seq_num !=
			    le16_to_cpu(extent->shared_extn_seq))
				continue;
			*groupp = dc_extent->group;
			return 0;
		}
	}
	return 0;
}

/**
 * cxl_group_fully_named() - does @chain name every extent of @group?
 * @group: host-side tag group
 * @chain: staged release chain
 *
 * Partial release is not supported: a release must name a whole tag group.
 * Compare as a set — the device is free to order a chain however it likes.
 * A chain entry names the dc_extent that contains its range; the host cannot
 * split an extent, so a release of part of one releases the whole extent.
 *
 * Return: true when every extent of @group is named by @chain.
 */
bool cxl_group_fully_named(struct cxl_dc_tag_group *group,
			   struct list_head *chain)
{
	struct cxl_extent_list_node *pos;
	struct dc_extent *dc_extent;
	unsigned long idx;
	unsigned int named = 0;

	scoped_guard(rcu) {
		xa_for_each(&group->dc_extents, idx, dc_extent) {
			bool seq_matters = cxled_seq_matters(dc_extent->cxled);
			bool found = false;

			list_for_each_entry(pos, chain, list) {
				struct range r = {
					.start = le64_to_cpu(pos->extent->start_dpa),
				};

				r.end = r.start +
					le64_to_cpu(pos->extent->length) - 1;
				if (!range_contains(&dc_extent->dpa_range, &r))
					continue;
				if (seq_matters &&
				    le16_to_cpu(pos->extent->shared_extn_seq) !=
				    dc_extent->seq_num)
					continue;
				found = true;
				break;
			}
			if (!found)
				return false;
			named++;
		}
	}

	return named == group->nr_extents;
}

/**
 * cxl_release_tag_group() - tear a validated tag group down
 * @cxlr: region owning the group
 * @group: the group to release
 *
 * Return: 0 when the group is gone, negative when the caller must leave it
 * intact and let the device retry.
 */
int cxl_release_tag_group(struct cxl_region *cxlr,
			  struct cxl_dc_tag_group *group)
{
	int rc;

	/*
	 * Invalidate CPU caches for the region before releasing the capacity
	 * back to the device so it cannot reassign the range while stale
	 * cached data lingers.  On failure do not release: leave the tag
	 * group intact and let the device retry.
	 */
	rc = cxl_region_invalidate_memregion(cxlr);
	if (rc)
		return rc;

	rm_tag_group(group);
	return 0;
}

static void cleanup_pending_dc_extent(struct dc_extent *dc_extent)
{
	struct cxl_dc_tag_group *group = dc_extent->group;

	if (!group->skip_device_release)
		cxled_release_extent(dc_extent->cxled, dc_extent);
	xa_erase(&group->dc_extents, dc_extent->seq_num);
	group->nr_extents--;
	if (!group->nr_extents)
		free_tag_group(group);
	kfree(dc_extent);
}

void rm_tag_group(struct cxl_dc_tag_group *group)
{
	struct device *region_dev = &group->cxlr_dax->dev;
	struct dc_extent *dc_extent;
	unsigned long index;

	/*
	 * Pin @group across the walk: each devm_release_action runs the
	 * dc_extent_unregister action synchronously, which drops the last
	 * reference on the dc_extent device and fires dc_extent_release.
	 * The release decrements group->nr_extents and, on the final
	 * decrement, frees @group.  Without the pin the next iteration's
	 * xa_find_after() dereferences a freed xarray.
	 */
	group->nr_extents++;
	xa_for_each(&group->dc_extents, index, dc_extent)
		devm_release_action(region_dev, dc_extent_unregister, dc_extent);
	group->nr_extents--;
	if (!group->nr_extents)
		free_tag_group(group);
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
		/*
		 * put_device() fires dc_extent_release().  On xa_alloc failure
		 * dev->id is still its invalid init value (0), but the xarray is
		 * declared XA_FLAGS_ALLOC1 so 0 is never a valid id and erasing
		 * it cannot remove another extent.
		 */
		if (rc < 0) {
			put_device(dev);
			break;
		}
		dev->id = id;

		rc = dev_set_name(dev, "extent%d.%d", cxlr_dax->cxlr->id,
				  dev->id);
		if (rc) {
			put_device(dev);
			break;
		}

		rc = device_add(dev);
		if (rc) {
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
		 * unregister ourselves; -ENOENT means pending.  Teardown
		 * honors the caller's skip_device_release.
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

// SPDX-License-Identifier: GPL-2.0
/*  Copyright(c) 2024 Intel Corporation. All rights reserved. */

#include <linux/device.h>
#include <cxl.h>

#include "core.h"

/*
 * Host-wide list of online tag groups.  An add checks it for capacity the
 * host already holds and a region's teardown drains its groups from it; a
 * group is on it from online until rm_tag_group(), whatever the state of
 * the region's own pointers.  A non-null tag appears on it once: a tag
 * uuid names one allocation across all regions and memdevs.
 */
static DEFINE_MUTEX(cxl_dc_group_lock);
static LIST_HEAD(cxl_dc_groups);

/* The orchestrator owns tag allocation; a repeated tag is a firmware bug */
static bool tag_online(const uuid_t *uuid)
{
	struct cxl_dc_tag_group *g;

	lockdep_assert_held(&cxl_dc_group_lock);

	if (uuid_is_null(uuid))
		return false;
	list_for_each_entry(g, &cxl_dc_groups, node)
		if (uuid_equal(&g->uuid, uuid))
			return true;
	return false;
}

static int register_tag_group(struct cxl_dc_tag_group *group)
{
	guard(mutex)(&cxl_dc_group_lock);
	if (tag_online(&group->uuid)) {
		dev_warn_ratelimited(&group->cxlr_dax->dev,
				     "Tag %pUb already online on this host (firmware/orchestrator bug)\n",
				     &group->uuid);
		return -EBUSY;
	}
	list_add_tail(&group->node, &cxl_dc_groups);
	return 0;
}

static void unregister_tag_group(struct cxl_dc_tag_group *group)
{
	guard(mutex)(&cxl_dc_group_lock);
	list_del_init(&group->node);
}

/* First online group of @cxlr_dax, or NULL */
static struct cxl_dc_tag_group *
cxlr_dax_first_group(struct cxl_dax_region *cxlr_dax)
{
	struct cxl_dc_tag_group *group;

	guard(mutex)(&cxl_dc_group_lock);
	list_for_each_entry(group, &cxl_dc_groups, node)
		if (group->cxlr_dax == cxlr_dax)
			return group;
	return NULL;
}

static struct cxl_dc_tag_group *to_dc_tag_group(struct device *dev)
{
	return container_of(dev, struct cxl_dc_tag_group, dev);
}

static void dc_tag_group_release(struct device *dev)
{
	struct cxl_dc_tag_group *group = to_dc_tag_group(dev);

	xa_destroy(&group->dc_extents);
	/* Drop the pin taken in alloc_tag_group(). */
	put_device(&group->cxlr_dax->dev);
	kfree(group);
}

static const struct device_type dc_tag_group_type = {
	.name = "tag_group",
	.release = dc_tag_group_release,
};

/* A tagged group is a tag_groupX.Y device, parent of its extents */
static int dc_tag_group_add(struct cxl_dc_tag_group *group)
{
	struct cxl_dax_region *cxlr_dax = group->cxlr_dax;
	struct device *dev = &group->dev;
	int id, rc;

	id = ida_alloc(&cxlr_dax->tag_group_ida, GFP_KERNEL);
	if (id < 0)
		return id;
	dev->id = id;

	rc = dev_set_name(dev, "tag_group%d.%d", cxlr_dax->cxlr->id, id);
	if (!rc)
		rc = device_add(dev);
	if (rc)
		ida_free(&cxlr_dax->tag_group_ida, id);
	return rc;
}

/* Called once the group's extents are gone; a no-op for untagged groups */
static void dc_tag_group_del(struct cxl_dc_tag_group *group)
{
	if (!device_is_registered(&group->dev))
		return;
	device_del(&group->dev);
	ida_free(&group->cxlr_dax->tag_group_ida, group->dev.id);
}

static void dc_extent_release(struct device *dev)
{
	struct dc_extent *dc_extent = to_dc_extent(dev);

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

static struct cxl_dc_tag_group *
alloc_tag_group(struct cxl_dax_region *cxlr_dax, uuid_t *uuid)
{
	struct cxl_dc_tag_group *group __free(kfree) = kzalloc_obj(*group);
	if (!group)
		return ERR_PTR(-ENOMEM);

	group->cxlr_dax = cxlr_dax;
	uuid_copy(&group->uuid, uuid);
	xa_init(&group->dc_extents);
	INIT_LIST_HEAD(&group->pending_online);
	INIT_LIST_HEAD(&group->node);

	/*
	 * Pin cxlr_dax: it is used after cxl_rwsem.region is dropped, so a
	 * refcount must keep it alive until the group is freed.
	 */
	get_device(&cxlr_dax->dev);

	/* Added by online_tag_group() for a tagged group, see dc_tag_group_add() */
	device_initialize(&group->dev);
	device_set_pm_not_required(&group->dev);
	group->dev.parent = &cxlr_dax->dev;
	group->dev.type = &dc_tag_group_type;

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

		if (range_contains(&partition_range, ext_range))
			return part;
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
 * Caller must hold cxl_rwsem.region and cxl_rwsem.dpa for read:
 * cxl_dpa_to_region() walks every decoder's dpa_res.
 * On success, @out_cxled / @out_cxlr_dax / @out_ext_range carry the
 * resolved handles consumed by the rest of the pipeline.
 */
static int cxl_validate_extent(struct cxl_memdev_state *mds,
			       struct cxl_extent *extent,
			       struct cxl_endpoint_decoder **out_cxled,
			       struct cxl_dax_region **out_cxlr_dax,
			       struct range *out_ext_range, bool existing)
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
	dev_dbg(dev, "DC extent DPA %pra (DCR:%pR)(%pU)\n", &ext_range,
		&part->res, &uuid);

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

	/*
	 * New adds wait for a bound dax driver that has read the device's
	 * pre-existing extents, so a tag already in use is never added twice.
	 */
	if (!existing && !smp_load_acquire(&cxlr->cxlr_dax->extents_scanned)) {
		dev_warn_ratelimited(dev,
				     "DC extent DPA %pra: dax driver not ready, refusing\n",
				     &ext_range);
		return -EBUSY;
	}

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
 * cxlr_dax.  Walks the region's online groups once: a stored extent that
 * fully contains @ext_range means the device re-offered accepted capacity;
 * a stored extent that only overlaps means an inconsistent offer.
 */
static enum cxl_extent_class
cxlr_dax_classify_extent(struct cxl_dax_region *cxlr_dax,
			 const struct range *ext_range)
{
	struct cxl_dc_tag_group *group;
	struct dc_extent *entry;
	unsigned long i;

	guard(mutex)(&cxl_dc_group_lock);
	list_for_each_entry(group, &cxl_dc_groups, node) {
		if (group->cxlr_dax != cxlr_dax)
			continue;
		xa_for_each(&group->dc_extents, i, entry) {
			if (range_contains(&entry->dpa_range, ext_range))
				return CXL_EXT_DUPLICATE;
			if (range_overlaps(&entry->dpa_range, ext_range))
				return CXL_EXT_OVERLAP;
		}
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

	dc_extent = kzalloc_obj(*dc_extent);
	if (!dc_extent)
		return ERR_PTR(-ENOMEM);

	dc_extent->dpa_range = *ext_range;
	dc_extent->hpa_range.start = hpa - cxlr_dax->hpa_range.start;
	dc_extent->hpa_range.end = dc_extent->hpa_range.start +
				   range_len(ext_range) - 1;
	dc_extent->seq_num = seq_num;
	import_uuid(&dc_extent->uuid, extent->uuid);
	return dc_extent;
}

/*
 * Hand a tag group to the dax driver.  Runs under cxl_rwsem.region for
 * read, which pins the hook: cxl_dax_region_set_notify() changes it under
 * the write lock.  No hook means no DAX devices over the region, and
 * nothing to coordinate.
 */
int cxlr_notify_extent(struct cxl_dc_tag_group *group, enum dc_event event)
{
	struct cxl_dax_region *cxlr_dax = group->cxlr_dax;
	struct cxl_notify_data notify_data = {
		.event = event,
		.group = group,
	};

	lockdep_assert_held(&cxl_rwsem.region);

	if (!cxlr_dax->notify)
		return 0;

	dev_dbg(&cxlr_dax->dev, "Notify: type %d tag %pUb\n", event,
		&group->uuid);
	return cxlr_dax->notify(&cxlr_dax->dev, &notify_data);
}

/*
 * Stage 4: insert @dc_extent into the pending tag group.  All extents in
 * one More-chain group share a UUID and a region — enforced here as the
 * group is either being created (first extent) or appended to.  On any
 * failure the dc_extent is freed.
 *
 * Returns 0 on success, <0 on error.
 */
static int cxlr_add_extent(struct cxl_memdev_state *mds,
			   struct cxl_dax_region *cxlr_dax,
			   struct dc_extent *dc_extent)
{
	struct cxl_dc_tag_group **group = &mds->dc_chain.group;
	int rc;

	/* Several decoders may map one DC region (r4.0 9.13.3) */
	if (*group && (!uuid_equal(&(*group)->uuid, &dc_extent->uuid) ||
		       (*group)->cxlr_dax != cxlr_dax)) {
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
	(*group)->nr_extents++;

	return 0;
}

/*
 * Returns 0 for a successfully added extent and <0 on error.
 */
int cxl_add_extent(struct cxl_memdev_state *mds, struct cxl_extent *extent,
		   u16 seq_num, bool existing)
{
	struct cxl_endpoint_decoder *cxled;
	struct cxl_dax_region *cxlr_dax;
	struct dc_extent *dc_extent;
	struct range ext_range;
	int rc;

	/* The caller holds both across the whole group, through online */
	lockdep_assert_held(&cxl_rwsem.region);
	lockdep_assert_held(&cxl_rwsem.dpa);

	rc = cxl_validate_extent(mds, extent, &cxled, &cxlr_dax, &ext_range,
				 existing);
	if (rc)
		return rc;

	switch (cxlr_dax_classify_extent(cxlr_dax, &ext_range)) {
	case CXL_EXT_DUPLICATE:
		/*
		 * Never re-reported: the device rejects a DPA range already
		 * added by a previous response (CXL r4.0 8.2.10.9.9.3).
		 */
		dev_warn_ratelimited(&cxled->cxld.dev,
				     "Extent %pra already accepted; dropping group\n",
				     &ext_range);
		return -EEXIST;
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

	return cxlr_add_extent(mds, cxlr_dax, dc_extent);
}

/**
 * cxl_resolve_extent() - locate the tag group a released extent belongs to
 * @mds: memdev state
 * @extent: extent from a DC Release-Capacity record
 * @groupp: returns the matching tag group
 *
 * Pure lookup, no side effects.  A record names the dc_extent that contains
 * its range: the host cannot split an extent.  The memdev's groups are found
 * on the host-wide list, so a group stays resolvable while its region is
 * torn down; the caller holds cxl_rwsem.region for read, which excludes
 * that teardown, so the group outlives the lookup.
 *
 * Return: 0 when @extent matches an extent the host owns.  -ENXIO when the
 * extent overlaps nothing the host owns, so the release can simply be
 * acknowledged.  -EINVAL when it overlaps owned capacity without matching
 * any single host-owned extent: it straddles multiple extents, or the tag
 * doesn't match.
 */
int cxl_resolve_extent(struct cxl_memdev_state *mds, struct cxl_extent *extent,
		       struct cxl_dc_tag_group **groupp)
{
	u64 start_dpa = le64_to_cpu(extent->start_dpa);
	struct cxl_memdev *cxlmd = mds->cxlds.cxlmd;
	struct cxl_dc_tag_group *group;
	struct dc_extent *dc_extent;
	struct range dpa_range;
	unsigned long idx;
	uuid_t tag;

	lockdep_assert_held(&cxl_rwsem.region);

	*groupp = NULL;

	dpa_range = (struct range) {
		.start = start_dpa,
		.end = start_dpa + le64_to_cpu(extent->length) - 1,
	};
	import_uuid(&tag, extent->uuid);

	guard(mutex)(&cxl_dc_group_lock);
	list_for_each_entry(group, &cxl_dc_groups, node) {
		if (cxled_to_memdev(group->cxlr_dax->cxled) != cxlmd)
			continue;
		xa_for_each(&group->dc_extents, idx, dc_extent) {
			if (!range_overlaps(&dc_extent->dpa_range, &dpa_range))
				continue;
			if (!range_contains(&dc_extent->dpa_range, &dpa_range))
				return -EINVAL;
			if (!uuid_equal(&group->uuid, &tag))
				return -EINVAL;
			*groupp = group;
			return 0;
		}
	}
	return -ENXIO;
}

/**
 * cxl_release_tag_group() - tear a tag group down for a device release
 * @group: the group to release
 *
 * The caller acknowledges the group to the device as a whole; the group is
 * dropped without a Release DC of its own.
 *
 * Return: 0 when the group is gone, negative when the caller must leave it
 * intact and let the device retry.
 */
int cxl_release_tag_group(struct cxl_dc_tag_group *group)
{
	int rc;

	/*
	 * Invalidate CPU caches for the region before releasing the capacity
	 * back to the device so it cannot reassign the range while stale
	 * cached data lingers.  On failure do not release: leave the tag
	 * group intact and let the device retry.
	 */
	rc = cxl_region_invalidate_memregion(group->cxlr_dax->cxlr);
	if (rc)
		return rc;

	rm_tag_group(group);
	return 0;
}

/*
 * Take @dc_extent out of the group, then drop it in whatever state the
 * online got it to: registered, initialized but not added, or never touched.
 */
static void dc_extent_destroy(struct dc_extent *dc_extent)
{
	struct cxl_dc_tag_group *group = dc_extent->group;
	struct device *dev = &dc_extent->dev;

	/* dev->id is 0 until the online allocates one */
	if (dev->id)
		ida_free(&group->cxlr_dax->extent_ida, dev->id);
	xa_erase(&group->dc_extents, dc_extent->seq_num);
	if (device_is_registered(dev))
		device_unregister(dev);
	else if (dev->kobj.state_initialized)
		put_device(dev);
	else
		kfree(dc_extent);
}

/*
 * Drop @group without telling the device anything: the caller has already
 * decided what, if anything, the device is told about this capacity.  Every
 * member leaves here, synchronously, so exactly one path accounts for the
 * group and the final put_device() needs no count.  A tagged group's memory
 * outlives this until its last child device release drops the parent
 * reference.
 */
void rm_tag_group(struct cxl_dc_tag_group *group)
{
	struct dc_extent *dc_extent;
	unsigned long index;

	unregister_tag_group(group);
	xa_for_each(&group->dc_extents, index, dc_extent) {
		dev_dbg(&dc_extent->dev, "DAX region rm extent HPA %pra\n",
			&dc_extent->hpa_range);
		dc_extent_destroy(dc_extent);
	}
	dc_tag_group_del(group);
	put_device(&group->dev);
}

/*
 * Region teardown: the host gives every group of @cxlr_dax back to the
 * device.  Flush the region's cached lines first; once the Release DC goes
 * out the device may reassign the range.  The write lock excludes a release
 * flush, which holds it for read, so a group is released by one path only.
 */
void cxl_dax_region_release_groups(struct cxl_dax_region *cxlr_dax)
{
	struct cxl_dc_tag_group *group;

	guard(rwsem_write)(&cxl_rwsem.region);
	group = cxlr_dax_first_group(cxlr_dax);
	if (!group)
		return;
	cxl_region_invalidate_memregion(cxlr_dax->cxlr);
	do {
		memdev_release_group(group);
		rm_tag_group(group);
	} while ((group = cxlr_dax_first_group(cxlr_dax)));
}
EXPORT_SYMBOL_NS_GPL(cxl_dax_region_release_groups, "CXL");

int online_tag_group(struct cxl_dc_tag_group *group)
{
	struct cxl_dax_region *cxlr_dax = group->cxlr_dax;
	struct device *parent = &cxlr_dax->dev;
	struct dc_extent *dc_extent;
	unsigned long index;
	int rc = 0;

	rc = register_tag_group(group);
	if (rc)
		goto unwind;

	/* A tagged group parents its extents; an untagged one sits under the region */
	if (!uuid_is_null(&group->uuid)) {
		rc = dc_tag_group_add(group);
		if (rc)
			goto unwind;
		parent = &group->dev;
	}

	xa_for_each(&group->dc_extents, index, dc_extent) {
		struct device *dev = &dc_extent->dev;
		int id;

		device_initialize(dev);
		device_set_pm_not_required(dev);
		dev->parent = parent;
		dev->type = &dc_extent_type;

		/* From 1: the unwind reads 0 as "never allocated" */
		id = ida_alloc_min(&cxlr_dax->extent_ida, 1, GFP_KERNEL);
		if (id < 0) {	/* the unwind owns every member, this one too */
			rc = id;
			break;
		}
		dev->id = id;

		rc = dev_set_name(dev, "extent%d.%d", cxlr_dax->cxlr->id,
				  dev->id);
		if (rc)
			break;

		rc = device_add(dev);
		if (rc)
			break;

		dev_dbg(dev, "dc_extent HPA %pra (%pU)\n",
			&dc_extent->hpa_range, &group->uuid);
	}

unwind:
	if (rc) {
		xa_for_each(&group->dc_extents, index, dc_extent)
			dc_extent_destroy(dc_extent);
		dc_tag_group_del(group);
		unregister_tag_group(group);
		put_device(&group->dev);
	}
	return rc;
}

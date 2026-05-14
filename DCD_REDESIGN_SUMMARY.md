# DCD redesign — `cxl_dc_tag_group` / `dc_extent`

Branch: **`dcd-jg-fixes-redesign`** (tip `d3a49adcb292`) — a rebase of
`dcd-jg-fixes` that replaces the buggy "one region_extent device per
tag group with an aggregate HPA bounding box" model with one
`dc_extent` device per backing extent, grouped logically by an
internal-only `cxl_dc_tag_group` container.

## Motivation

The original `dcd-jg-fixes` series modelled a tagged DC allocation as
a single `struct region_extent` carrying:

```
struct region_extent {
    struct device dev;
    struct range hpa_range;     /* aggregate */
    uuid_t uuid;
    struct xarray decoder_extents;
};
```

The `hpa_range` was computed as `min(start) .. max(end)` over the
member decoder extents.  When a tagged allocation contains multiple
DPA-discontiguous extents (which decode to discontiguous HPAs), the
bounding box covers HPA gaps that are not backed by any extent.  The
DAX layer then created one `dax_resource` over that bounding box;
subsequent carving from that `dax_resource` could land in the
unbacked gap.

The second issue: the cxl side sorts a tag group by `shared_extn_seq`
before realization, but that ordering was not carried onto the
realized objects.  By the time the dax layer saw the group there was
no way to claim its extents in sequence order.

## New structure

```
struct dc_extent {              /* was cxled_extent */
    struct device dev;          /* registered as child of cxlr_dax->dev */
    struct cxl_dc_tag_group *group;
    struct cxl_endpoint_decoder *cxled;
    struct range dpa_range;
    struct range hpa_range;     /* per-extent; no aggregate */
    uuid_t uuid;                /* matches group->uuid */
    u16 shared_extn_seq;        /* 0 untagged/non-sharable, 1..n sharable */
};

struct cxl_dc_tag_group {       /* was region_extent */
    struct cxl_dax_region *cxlr_dax;
    uuid_t uuid;
    struct xarray dc_extents;   /* keyed by shared_extn_seq */
    unsigned int nr_extents;    /* manual refcount */
};
```

Key invariants:

* No aggregate HPA range exists; each `dc_extent` carries its own
  `hpa_range`.
* `group->dc_extents` is keyed by `shared_extn_seq`, so iteration
  order equals assembly order.  Sharable groups use the dense 1..n
  set the spec requires.
* `cxl_dc_tag_group` has no sysfs identity — userspace sees one
  `extentX.Y` device per `dc_extent` directly under `dax_regionX`.
* `nr_extents` is incremented by `online_tag_group()` (with a
  function-scoped +1 pin so the body can't free `@group` mid-loop) and
  decremented by `dc_extent_release` / `cleanup_pending_dc_extent`;
  the group is freed when the count hits zero.
* `cxl_region_invalidate_memregion()` runs **once per tag group**, not
  once per dc_extent — at the top of `rm_tag_group` and in the add
  path's `cxl_add_pending` before `online_tag_group`.

## Sysfs

Unchanged paths:

```
/sys/bus/cxl/devices/dax_regionX/extentX.Y/
    offset      # dc_extent->hpa_range.start
    length      # range_len(&dc_extent->hpa_range)
    uuid        # dc_extent->group->uuid  (hidden for the null tag)
```

Now `extentX.Y` is per-dc_extent, not per tag group, so when a tagged
allocation contains multiple discontiguous extents each surfaces its
own `offset` / `length`.

## DAX bridge (`drivers/dax/cxl.c`)

* `__cxl_dax_add_resource()` now operates on a single `dc_extent`
  (passes its `hpa_range` and `shared_extn_seq` to
  `dax_region_add_resource`).
* `cxl_dax_add_resource()` (probe-time walk) iterates the dc_extent
  device children of `cxlr_dax->dev` via `device_for_each_child`.
* `cxl_dax_region_notify()` `DCD_ADD_CAPACITY` iterates
  `notify_data->group->dc_extents` and adds one dax_resource per
  member; on failure it unwinds via `dax_region_rm_resource()`.
* `cxl_dax_region_notify()` `DCD_RELEASE_CAPACITY` collects all the
  group's dc_extent devices into an array and calls
  `dax_region_rm_resources()` for refuse-all-or-none semantics.

## DAX core (`drivers/dax/bus.c`, `drivers/dax/dax-private.h`)

* `struct dax_resource` gains `u16 shared_extn_seq`.
* `dax_region_add_resource()` signature gains a `shared_extn_seq`
  parameter; stores it on the resource.
* New `dax_region_rm_resources(dax_region, devs[], n)` — atomic
  remove of a set of dax_resources under `dax_region_rwsem` with
  refuse-all-or-none semantics: first pass checks `use_cnt` across
  every member, second pass releases them.  Used by the tag-group
  release path so a partial release is impossible.
* `uuid_store()` split into:
  * `uuid_claim_untagged()` — single-pick from the null-uuid pool
    (unchanged semantics).
  * `uuid_claim_tagged()` — collect every dax_resource whose uuid
    matches the request, sort by `shared_extn_seq`, enforce the
    dense `1..n` invariant, then carve each via `__dev_dax_resize`
    in seq order so `dev_dax->ranges[]` is dense and ordered.

## Per-commit buildability

Each commit on `dcd-jg-fixes-redesign` builds cleanly when checked
out in isolation (`make drivers/cxl/ drivers/dax/`).  This is a
bisectability improvement over the original `dcd-jg-fixes`, which did
not build at `8c855006f10b` (mbox.c called `cxlr_notify_extent` /
`region_rm_extent` before their declarations / definitions were
introduced by `7d0ed83a8e09`, and used `cxl_region_invalidate_memregion`
while it was still `static`).

To preserve bisectability the redesign:

* Defers the `cxlr_notify_extent` / `rm_tag_group` calls in mbox.c
  from `8c855006f10b` to `7d0ed83a8e09`.
* Exports `cxl_region_invalidate_memregion` (drops `static`, adds a
  declaration to `drivers/cxl/core/core.h`) inside the
  `8c855006f10b` fixup, so 8c-and-onward all link.

## Commit chain (top of `dcd-jg-fixes-redesign`)

```
d3a49adcb292 Documentation/cxl: Document DCD extent handling and sparse DAX regions
5b5809253d2d tools/testing/cxl: Add DC Regions to mock mem data
b649d6fc2338 tools/testing/cxl: Make event logs dynamic
98d183f0d681 cxl/mem: Trace Dynamic capacity Event Record
83e073521a30 cxl/region: Read existing extents on region creation
9159722fcd40 dax/region: Surface dc_extents as DAX resources and claim by tag uuid
bad05f58f420 dax/bus: Add uuid sysfs attribute to dax devices
bc8a2319eaca dax/bus: Factor out dev dax resize logic
b7c6d09a8652 cxl/region/extent: Expose dc_extent information in sysfs
52fd06088179 cxl/extent: Process dynamic partition events and realize tagged allocations
eb0b66318639 cxl/core: Return endpoint decoder information from region search   (unchanged)
... (pre-DCD commits unchanged)
```

Three commits have new bodies that describe the
`cxl_dc_tag_group` / `dc_extent` design rather than the original
`region_extent` design:

* **`52fd06088179`** — *cxl/extent: Process dynamic partition events
  and realize tagged allocations* (rewritten from the original
  "realize region extents" message).
* **`b7c6d09a8652`** — *cxl/region/extent: Expose dc_extent
  information in sysfs* (rewritten from "Expose region extent
  information").
* **`9159722fcd40`** — *dax/region: Surface dc_extents as DAX
  resources and claim by tag uuid* (rewritten from "Create resources
  on DAX regions").

## Dropped commit

The original `b304e03c23c4` (`dax/bus.c: make DC regions driver type
DAXDRV_DEVICE_TYPE`) was empty after replay because its one-line
change is already incorporated into the `9159722fcd40` rewrite of
`drivers/dax/bus.c`.  Net behaviour is preserved.

## How the rebase was performed

1. Saved final-state working tree from a prior reflog entry
   (`9e0b3f05c6ac`) into `/home/anisa/.cache/dcd-fixup-v3/`.
2. `git checkout 8c855006f10b`, applied targeted edits (struct
   renames, per-dc_extent device registration, no `cxlr_notify_extent`
   yet), built cleanly, `git commit --amend` with the new message.
3. `git cherry-pick e2302fb52c5d` — conflict in `extent.c` resolved
   by replacing with the prepared 8c-fixup + sysfs version; committed
   with new message.
4. `git cherry-pick 097cc6bc06c2 b630fd146eb0` — clean.
5. `git cherry-pick 7d0ed83a8e09` — conflicts in `extent.c`, `core.h`;
   resolved by replacing all 7d-touched files with the final-state
   versions and re-adding the `cxlr_notify_extent` / `rm_tag_group`
   call back into `mbox.c` (which the 8c fixup had deferred);
   committed with new message.
6. `git cherry-pick e17aad1b48ba 4d38e3cd079e c6da0702f817
   5c56961b7433 b304e03c23c4 7f967b55e071` — the first five clean;
   `b304e03c23c4` empty (skipped); documentation clean.
7. Verified each commit in the chain builds in isolation.
8. Created branch `dcd-jg-fixes-redesign` at the new tip; restored
   `dcd-jg-fixes` to its original tip (`7f967b55e071`).

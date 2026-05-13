.. SPDX-License-Identifier: GPL-2.0

====================
DAX Driver Operation
====================
The `Direct Access Device` driver was originally designed to provide a
memory-like access mechanism to memory-like block-devices.  It was
extended to support CXL Memory Devices, which provide user-configured
memory devices.

The CXL subsystem depends on the DAX subsystem to either:

- Generate a file-like interface to userland via :code:`/dev/daxN.Y`, or
- Engage the memory-hotplug interface to add CXL memory to page allocator.

The DAX subsystem exposes this ability through the `cxl_dax_region` driver.
A `dax_region` provides the translation between a CXL `memory_region` and
a `DAX Device`.

DAX Device
==========
A `DAX Device` is a file-like interface exposed in :code:`/dev/daxN.Y`. A
memory region exposed via dax device can be accessed via userland software
via the :code:`mmap()` system-call.  The result is direct mappings to the
CXL capacity in the task's page tables.

Users wishing to manually handle allocation of CXL memory should use this
interface.

Dynamic Capacity (Sparse) Regions
=================================
A region backed by a CXL `Dynamic Capacity Device (DCD)` is `sparse`: its
HPA window is fixed at probe time, but the DPA capacity that fills the
window arrives and departs at runtime as the device offers and reclaims
`extents`.  Sparse regions are distinguished from static regions by the
:code:`IORESOURCE_DAX_SPARSE_CAP` flag on the :code:`dax_region`.

For the CXL-side rules governing when an offered extent is accepted or a
release request is honoured, see :doc:`cxl-driver`.  This section covers
the DAX-side mapping between accepted extents and DAX devices.

The Extent Layering Model
-------------------------
Three objects sit between the wire-level CXL extent and the user-visible
DAX device.  Understanding the cardinality between them is the key to
the sparse-region model.

::

    device extents       region_extent       dax_resource         DAX device
    (CXL wire)           (CXL core)          (DAX bus)            (/dev/daxN.Y)
    -----------------    ---------------     ---------------      ------------
    e1 ─┐
    e2 ─┼─── tag A ──►   re_A ──────────►    res_A ──────►       daxN.0
    e3 ─┘

    e4 ─── tag B ────►   re_B ──────────►    res_B ──────►       daxN.1

    e5 ─── null tag ─►   re_(∅,1) ──────►    res_(∅,1) ──►       daxN.2
    e6 ─── null tag ─►   re_(∅,2) ──────►    res_(∅,2) ──►       daxN.3

`Device extent`
  The unit the CXL device delivers over the mailbox: a `(DPA, length,
  tag, shared_extn_seq)` tuple inside an Add-Capacity event.  The tag
  is either a non-null UUID (a `tagged allocation`) or the null UUID
  (`untagged`).

`region_extent`
  A `tagged allocation` as the CXL core sees it.  One
  :code:`region_extent` corresponds to `one or more` device extents
  that share the same tag — the CXL spec says all extents bearing a
  given tag form one logical allocation, and the kernel honours that
  by folding every device extent in a tag group into a single
  :code:`region_extent` whose :code:`hpa_range` spans the union of
  member ranges (see :code:`cxlr_add_extent` in
  :code:`drivers/cxl/core/extent.c`).

  For a `non-null tag`, the cross-More-chain uniqueness check
  (:doc:`cxl-driver`) guarantees there is at most one
  :code:`region_extent` per tag per region.

  For the `null tag` there is no cross-event identity — the spec is
  silent on aggregating untagged extents across Add-Capacity events.
  Each Add-Capacity delivery of untagged extents produces its own
  independent untagged :code:`region_extent`; two untagged extents
  delivered separately are two distinct allocations.

:code:`dax_resource`
  The DAX bus's per-allocation view, one-to-one with
  :code:`region_extent`.  When the CXL DAX driver receives a
  :code:`DCD_ADD_CAPACITY` notification it calls
  :code:`dax_region_add_resource()` once, creating a single
  :code:`dax_resource` that inherits the :code:`region_extent`'s HPA
  range and tag (copied via :code:`uuid_copy()` from
  :code:`region_extent->uuid`).  Tagged → tagged
  :code:`dax_resource`; untagged → untagged :code:`dax_resource`.

`DAX device` (:code:`/dev/daxN.Y`)
  Created by userspace claiming a :code:`dax_resource` via the
  :code:`uuid` sysfs attribute.  Each DAX device corresponds to
  exactly one allocation:

  * A `tagged` DAX device is built from the single
    :code:`dax_resource` carrying that tag, and its size equals the
    sum of the device extents that made up the tagged allocation.
  * An `untagged` DAX device is built from one untagged
    :code:`dax_resource`, and its size equals the size of that one
    delivery's worth of capacity.

So the end-to-end rule is: **one tagged allocation = one
region_extent = one dax_resource = one DAX device**.  An untagged
device extent (or untagged Add-Capacity delivery) becomes its own
:code:`region_extent`, its own :code:`dax_resource`, and ultimately
its own DAX device, claimed one at a time.

Release follows the same layering in reverse.  When the CXL core
unregisters a :code:`region_extent` (after the device asks for
release and the DAX layer consents), the matching
:code:`dax_resource` is dropped, the HPA capacity returns to the
region's free pool, and any DAX device that had claimed it is left
with no backing capacity.  Userspace tears the DAX device down via
:code:`daxctl destroy-device` (size=0, then write the device name to
the region's :code:`delete` attribute).

UUID-Based DAX Device Creation
------------------------------
A DAX device on a sparse region is created by writing a UUID to the
seed device's :code:`uuid` attribute
(:code:`/sys/bus/dax/devices/daxN.Y/uuid`).  The seed starts at
size 0; writing :code:`uuid` is a `claim` operation that resolves
the layering above and populates the device:

* A `non-null UUID` claims the (at most one) :code:`dax_resource`
  whose tag matches and binds it to the device.  The resulting DAX
  device represents exactly the tagged allocation: its size equals
  the sum of the device extents the CXL core folded into the
  matching :code:`region_extent`.

  uuid_store walks every matching :code:`dax_resource` for defence
  in depth, but with the cross-More uniqueness gate in place the
  match set is normally a singleton.

* The value :code:`"0"` is shorthand for the null UUID and claims
  exactly `one` untagged :code:`dax_resource`.  Untagged
  :code:`dax_resource`\ s correspond to independent untagged
  allocations; collapsing several into one device would aggregate
  unrelated capacity, so each :code:`uuid` write consumes a single
  untagged resource.

* A write that matches no :code:`dax_resource` returns
  :code:`-ENOENT` and the device remains at size 0.

* Writes to the :code:`uuid` attribute on non-sparse regions return
  :code:`-EOPNOTSUPP`; the attribute itself is read-only (0444) on
  non-sparse devices.

The device's size is determined entirely by the backing allocation:
users do not choose a size on sparse regions.  Accordingly, the
:code:`size` attribute on a sparse DAX device rejects grow requests
with :code:`-EOPNOTSUPP`.  Writing :code:`0` is still permitted and is
how :code:`daxctl destroy-device` returns each claimed extent to the
region's available pool before the device's name is written to the
region's :code:`delete` attribute.

Reads of :code:`uuid` report the tag identifying the capacity
backing the device:

* For a non-null-UUID-claimed sparse DAX device, :code:`uuid` reads
  back the claimed UUID.
* For a sparse DAX device claimed via :code:`"0"`, or for any
  non-DCD DAX device, :code:`uuid` reads :code:`0`.

See :code:`Documentation/ABI/testing/sysfs-bus-dax` for the
authoritative attribute contracts.

kmem conversion
===============
The :code:`dax_kmem` driver converts a `DAX Device` into a series of `hotplug
memory blocks` managed by :code:`kernel/memory-hotplug.c`.  This capacity
will be exposed to the kernel page allocator in the user-selected memory
zone.

The :code:`memmap_on_memory` setting (both global and DAX device local)
dictates where the kernell will allocate the :code:`struct folio` descriptors
for this memory will come from.  If :code:`memmap_on_memory` is set, memory
hotplug will set aside a portion of the memory block capacity to allocate
folios. If unset, the memory is allocated via a normal :code:`GFP_KERNEL`
allocation - and as a result will most likely land on the local NUM node of the
CPU executing the hotplug operation.

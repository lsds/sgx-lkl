SGX-LKL Virtio interface
==============

LKL supports
[virtio](https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-610007)
driver-device communication through a `virtio_dev` data structures in the shared
memory (accessible by both the guest driver and the host device), one or more
Virtqueues for each device, and a bound buffer (shared by all virtio drivers)
managed by the guest side virtio code. The Virtqueues and the bound buffer also
reside in the shared memory.

```C
struct virtio_dev
{
    /* device_id reported by the host */
    uint32_t device_id;
    /* vendor_id reported by the host */
    uint32_t vendor_id;
    /* device_feature reported by the host */
    uint64_t device_features;
    /* the guest driver sets device_features_sel to read from the hi/low word
     * of device_features
     */
    _Atomic(uint32_t) device_features_sel;
    /* the guest driver sets driver_feature based on the device_feature of the
     * device and the guest driver's capability
     */
    uint64_t driver_features;
    /* the guest driver sets driver_features_sel to write to the hi/low word of
     * device_features
     */
    _Atomic(uint32_t) driver_features_sel;
    /* the guest driver sets queue_sel to select a virtqueue from the virtqueue
     * array
     */
    _Atomic(uint32_t) queue_sel;
    /* pointer to the virtqueue structure array allocated by the host in the
     * shared memory
     */
    struct virtq* queue;
    /* Not used */
    uint32_t queue_notify;
    /* device interrupt status, the guest driver reads/writes */
    _Atomic(uint32_t) int_status;
    /* device status, the guest driver reads/writes */
    _Atomic(uint32_t) status;
    /* generation count for the device configuration space, which will change
     * whenever there is a possibility that two accesses to the device
     * configuration space can see different versions of that space
     */
    uint32_t config_gen;
    /* LKL implementation specific, host use only */
    struct virtio_dev_ops* ops;
    /* LKL implementation specific, guest driver sets irq number, for the host
     * side to use when triggering interrupt. In SGX-LKL, guest side use only
     */
    int irq;
    /* pointer to the MMIO device configuration region */
    void* config_data;
    /* Length of the MMIO device configuration region */
    int config_len;
    /* LKL implementation specific, a handle used to index a IOMMU info array
     * to locate a device's MMIO device configuration region info, guest use
     * only
     **/
    void* base;
    /* ? TODO:Need to confirm. Seems to be used for device unmount log, not
     * supported in SGX-LKL
     */
    uint32_t virtio_mmio_id;
};
```

The host allocates `virtio_dev` data structure and provides the address of the
data structure to the guest. Within `virtio_dev`,  certain fields are guest
read-only, for example, `device_id`, `vendor_id`, `device_feature` and
`config_gen`, and certain fields are host-read-only, for example,
`driver_features` and `queue_sel`. This interface emulates MMIO interface
exposed by a HW device, including the limitation of certain HW device. For
example, the guest driver has to write to `device_features_sel` or
`driver_features_sel` to specify the targeted a 32bit word within the 64-bit
`device_features` or `driver_features` when access them. LKL also adds several
implementation specific fields in `virtio_dev`. For example, `base` is a handle
used by the guest side LKL virtio code to index an array of MMIO device
configuration data, which is not necessary to be part of the share memory
interface in a different implementation. The guest side virtio code access the
interface through
[`virtio_write`](https://github.com/lsds/sgx-lkl/blob/9ff342fdf9e1c77c34f8bdde437c2cbccf24785c/src/lkl/virtio.c#L212)
and
[`virtio_read`](https://github.com/lsds/sgx-lkl/blob/9ff342fdf9e1c77c34f8bdde437c2cbccf24785c/src/lkl/virtio.c#L66)
functions.

The pointer `config_data` points to a device type specific configuration region.
Depending on the device type, some fields of the configuration region are
defined as a drover-to-device communication interface, and writable by the guest
driver, while other fields are defined as device configuration data the guest
driver should only read. Some devices support run-time configuration change. The
host device is supposed to deliver a CONFIGURATION_CHANGE_NOTIFICATION interrupt
to the guest driver when any configuration data is changed.

The Virtqueue pointer `queue` points to a Virtqueue structure array allocated by
the host in the shared memory. The size of the array (number of the Virtqueue
structures) is device specific. Certain virtio devices have fixed number of
Virtqueues, while other virtio devices report the size of the array through the
device specific configuration.

```C
struct virtq
{
    /* max queue length supported by the device, reported by the host */
    uint32_t num_max;
    /* the guest driver sets `num` to indicate the queue length selected */
    _Atomic(uint32_t) num;
    /* guest driver sets `ready` to indicate whether the queue is ready for use */
    _Atomic(uint32_t) ready;
    /* LKL implementation specific, host use only */
    uint32_t max_merge_len;

    /* pointer to the Descriptor array (`num` entries), allocated by the guest
     * driver from the shared memory
     */
    _Atomic(struct virtq_desc*) desc;
    /* pointer to the Available array (`num` entries) in Split Virtqueue or the
     * Driver Event Suppression data structure in Packed Virtqueue, allocated
     * by the guest driver from the shared memory
     */
    _Atomic(struct virtq_avail*) avail;
    /* pointer to the Used array (`num` entries) in Split Virtqueue or the
     * Device Event Suppression data structure in Packed Virtqueue, allocated
     * by the guest driver from the shared memory
     */
    _Atomic(struct virtq_used*) used;
    /* LKL implementation specific, host use only */
    uint16_t last_avail_idx;
    /* LKL implementation specific, host use only */
    uint16_t last_used_idx_signaled;
};

```

Each Virtqueue structure contains pointers to three buffers allocated by the
guest driver, in the shared memory. Two types of Virtqueue are supported, one
called Split Virtqueue, the other called Packed Virtqueue. For both the Split
Virtqueue and the Packed Virtqueue, the `desc` pointer points to an array of
buffer descriptors. The buffers themselves are allocated by the guest driver
from a sub-region within the shared memory, called Bounce Buffer region. The
guest driver sends/receives command/data to/from the host device using those
buffers, in a indirect ("bouncing") manner. Command/data for the device is first
filled in a buffer inside the guest memory and copied to a bounce buffer in the
shared memory. Response/data from the device filled in a bounce buffer by the
host device is copied to a receiving buffer inside guest memory, before the rest
of the guest code can access them.  The  `desc` buffer descriptor contains
address and length of the bounce buffer and other meta data. Multiple bounce
buffers can be chained together to exchange large amount of data, without
relying on a large chunk of contiguous free memory within the Bounce Buffer
region. For the Split Virtqueue, the `next` field of the buffer descriptor can
be set to the array index of the next descriptor for the bounce buffer to follow
the current bounce buffer, forming a link list. For the Packed Virtqueue, the
next descriptor of chained buffers is the next item in the descriptor array.
With the Split Virtqueue, the guest driver use an `avail` buffer to inform the
host device about bounce buffers availability (to be processed or filled), and
the host device update a `used` buffer to inform the guest device about bounce
buffers already used (processed or filled). With the Packed Virtqueue, instead
of using the `avail` buffer and `used` buffer, the guest driver and the host
device inform each other about bounce buffer status (available or used) through
updates to the buffer descriptors directly, plus a 32-bit Device Event
Suppression data structure and a 32-bit Driver Event Suppression data structure.
The definition of desc/avail/used buffers of a Split Virtqueue points is listed
below. For more details on the Split Virtqueue and Packed Virtqueue, the readers
should consult the
[virtio](https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-610007)
spec.

```C
struct virtq_desc
{
    /* Address (guest-physical). */
    uint64_t addr;
    /* Length. */
    uint32_t len;
    /* The flags as indicated above. */
    uint16_t flags;
    /* We chain unused descriptors via this, too */
    uint16_t next;
};

struct virtq_avail
{
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[];
};

struct virtq_used_elem
{
    /* Index of start of used descriptor chain. */
    uint32_t id;
    /* Total length of the descriptor chain which was used (written to) */
    uint32_t len;
};

struct virtq_used
{
    uint16_t flags;
    uint16_t idx;
    struct virtq_used_elem ring[];
};
```

Most of the kernel implementation of Virtqueue on the guest side are in
[lkl/driver/virtio/virt_ring.c](https://github.com/lsds/lkl/blob/0a2ae194203695b257992768aca44323fd114488/drivers/virtio/virtio_ring.c#L2))
and
[lkl/kernel/dma/swiotlb](https://github.com/lsds/lkl/blob/0a2ae194203695b257992768aca44323fd114488/kernel/dma/swiotlb.c#L23).
Guest side SGX-LKL code manages the virtio device interface primarily through
the functions in
[src/lkl/virtio.c](https://github.com/lsds/sgx-lkl/blob/9ff342fdf9e1c77c34f8bdde437c2cbccf24785c/src/lkl/virtio.c#L2).

Security Implication of Untrusted Host Threat Model
---------------------------------------------------

In SGX-LKL threat model, the host is not trusted and can be malicious. The
original virtio implementation in Linux kernel and LKL was not designed for this
threat model.

With the untrusted host threat model, assumptions made by the original virtio
implementation, for example, `virtio_dev.base` is for guest used only and holds
the handle to index a guest side array, might not hold anymore. A malicious
host can overwrite `virtio_dev.base` and cause buffer overflow inside the guest
when the guest code uses it to access the array. Another example is the
`virtio_dev.config_data` pointer, which is supposed to be set by the host side
to point to a host device's MMIO configuration region. A malicious host can
change it at run time to point to different guest memory locations to cause the
guest code to overwrite its own code/data when attempting to write device
configuration data to a host device. The Split Virtqueue's buffer descriptors
can be manipulated to cause the guest code to access unintended memory when
attempting to assemble data from the host device from a chain of bounce buffers.

Secure the Virtio Interface with Shadow Data Structure
------------------------------------------------------

Instead of going through all guest side virtio code to identify implementations
vulnerable to attacks from a malicious host and fix them, a more efficient
mitigation is to ensure the assumptions made by the guest side virtio code about
the expected host behavior is preserved.

For each `virtio_dev` data structure in the shared memory and its Virtqueue
array, shadow structures for `virtio_dev`, the associated device configuration
region and the associated Virtqueue array are allocated in the guest memory when
the virtio device is registered. The shadow structure are initialized based on
the info provided by the host, after the info is verified. The verification
shall make sure the buffers, including arrays, referenced by a pointer, are
indeed within the shared memory. Specifically, for the virtio_net and
virtio_console devices supported by SGX-LKL, the verification logic shall check
that the whole Virtqueue array, with size specified in
`virtio_net_config.max_virtqueue_pairs` or `virtio_console_config.max_nr_ports`,
is within the shared memory. As the SGX-LKL implementation only support selected
type of virtio devices and certain part of the verification logic is device type
specific, the verification logics shall interpret the device type, reported in
`virtio_dev.device_id`, and only accept supported device types. To mitigate
potential TOCTOU attack, the verification logic implementation can copy the info
provided by the host to the shadow structures first, perform verification on the
unverified shadow structure in the guest memory and only proceed to register the
virtio device after the verification passes.

Afterwards, when
the
[`virtio_write`](https://github.com/lsds/sgx-lkl/blob/9ff342fdf9e1c77c34f8bdde437c2cbccf24785c/src/lkl/virtio.c#L212)
and
[`virtio_read`](https://github.com/lsds/sgx-lkl/blob/9ff342fdf9e1c77c34f8bdde437c2cbccf24785c/src/lkl/virtio.c#L66)
functions access a field in the `virtio_dev` interface or the Virtqueue, the
following rules are followed, based on the designation of the field's
access-control policy:

- host-write-once: read from the shadow structure;
- host-read-only: write to the shadow structure and then copy to the shared
  structure, read from the shadow structure;
- host-read-write: write to the shadow structure and then copy to the shared
  structure, read from the shared structure and then copy to the shadow structure;
- host-read-write-int: read from the shadow structure; write to the shadow
  structure and then copy to the shared structure; copy from the shared
  structure to the shadow structure on CONFIGURATION_CHANGE_NOTIFICATION
  interrupt only  
- host-use-only: set to 0s in the shadow structure
- guest-use-only: read/write from/to the shadow structure only

```C
struct virtio_dev
{
    /* device_id reported by the host */
    uint32_t device_id; //host-write-once
    /* vendor_id reported by the host */
    uint32_t vendor_id; //host-write-once
    /* device_feature reported by the host*/
    uint64_t device_features; //host-write-once
    /* the guest driver sets device_features_sel to read from the hi/low word
     * of device_features
     */
    _Atomic(uint32_t) device_features_sel; //host-read-only
    /* the guest driver sets driver_feature based on the device_feature of the
     * device and the guest driver's capability
     */
    uint64_t driver_features; //host-read-only
    /* the guest driver sets driver_features_sel to write to the hi/low word of
     * device_features,
     */
    _Atomic(uint32_t) driver_features_sel; //host-read-only
    /* the guest driver sets queue_sel to select a Virtqueue from the Virtqueue
     * array
     */
    _Atomic(uint32_t) queue_sel; //host-read-only
    /* pointer to the Virtqueue structure array allocated by the host in the
     * shared memory
     */
    //host-write-once; virtq itself contains fields with different
    //access-control policies; in the shadow virtio_dev, the pointer points to
    //the shadow Virtqueue structure array in guest memory
    struct virtq* queue;
    /* Not used in SGX-LKL */
    uint32_t queue_notify;
    /* device interrupt status, the guest driver reads/writes */
    _Atomic(uint32_t) int_status;  //host-read-write
    /* device status, the guest driver reads/writes */
    _Atomic(uint32_t) status;  //host-read-write
    /* generation count for the device configuration space, which will change
     * whenever there is a possibility that two accesses to the device
     * configuration space can see different versions of that space
     */
    uint32_t config_gen;  //host-read-write-int
    /* LKL implementation specific, host use only */
    struct virtio_dev_ops* ops;
    /* LKL implementation specific, guest driver sets irq number, for the host
     * side to use when triggering interrupt. In SGX-LKL, guest side use only
     */
    int irq; //host-read-only
    /* pointer to the MMIO device configuration region */
    //host-write-once; the MMIO device config region itself is
    //host-read-write-int; in the shadow virtio_dev, the pointer points to the
    //shadow configuration region in the guest memory
    void* config_data;
    /* Length of the MMIO device configuration region */
    int config_len;  //host-write-once
    /* LKL implementation specific, a handle used to index a IOMMU info array
     * to locate a device's MMIO device configuration region info, guest use
     * only
     **/
    void* base; //guest-use-only
    /* ? TODO:Need to confirm. Seems to be used for device unmount log, not
     * supported in SGX-LKL
     */
    uint32_t virtio_mmio_id;
};

struct virtq
{
    /* max queue length supported by the device, reported by the host */
    uint32_t num_max; //host-write-once
    /* the guest driver sets `num` to indicate the queue length selected */
    _Atomic(uint32_t) num;  //host-read-only
    /* guest driver sets `ready` to indicate whether the queue is ready for use */
    _Atomic(uint32_t) ready; //host-read-only
    /* LKL implementation specific, host use only */
    uint32_t max_merge_len;  //host-use-only

    /* pointer to the Descriptor array (`num` entries), allocated by the guest
     * driver from the shared memory
     */
    //host-read-only; desc array itself is host-read-only for Split Virtqueue
    //and host-read-write for Packed Virtqueue
    _Atomic(struct virtq_desc*) desc;
    /* pointer to the Available array (`num` entries) in Split Virtqueue or the
     * Device Event Suppression data structure in Packed Virtqueue, allocated
     * by the guest driver from the shared memory
     */
    //host-read-only; Avail array for Split Virtqueue or Device Event
    //Suppression data structure for Packed Virtqueue is host-ready-only
    _Atomic(struct virtq_avail*) avail;
    /* pointer to the Used array (`num` entries) in Split Virtqueue or the
     * Driver Event Suppression data structure in Packed Virtqueue, allocated
     * by the guest driver from the shared memory
     */
    //host-read-only; Used array for Split Virtqueue or Driver Event
    //Suppression data structure for Packed Virtqueue is guest-ready-only
    _Atomic(struct virtq_used*) used;
    /* LKL implementation specific, host use only */
    uint16_t last_avail_idx;  //host-use-only
    /* LKL implementation specific, host use only */
    uint16_t last_used_idx_signaled;  //host-use-only
};
```

To localize the required changes in [src/lkl/virtio.c](https://github.com/lsds/sgx-lkl/blob/9ff342fdf9e1c77c34f8bdde437c2cbccf24785c/src/lkl/virtio.c#L2) and to make it easy to
detect unexpected direct access to fields of `virtio_dev` (instead of through
`virtio_read` and `virtio_write`),
[`lkl_virtio_device_setup`](https://github.com/lsds/sgx-lkl/blob/9ff342fdf9e1c77c34f8bdde437c2cbccf24785c/src/lkl/virtio.c#L311)
registers a `virtio_dev_handle` pointer, instead of a `virtio_dev` pointer with
the rest of the virtio code. The handle contains two `virtio_dev` pointers, one
for the shadow `virtio_dev` in guest memory, one for the `virtio_dev` in the
shared memory:

 ```C
struct virtio_dev_handle
{
    struct virtio_dev *dev; //shadow structure in guest memory
    struct virtio_dev *dev_host;
}
```

The `virtio_read` and `virtio_write` functions are invoked with a
`virtio_dev_handle` pointer, so they must convert the access to access to the
shadow `virtio_dev` and/or the shared `virtio_dev`.

The shadow structure technique can be used to secure the Virtqueue
desc/avail/used arrays interface too. But to initialize the shadow structures
and enforce the access control rules, many code flows in
lkl/drivers/virtio/virtio_ring.c must be changed. Upstreaming the complex
changes would be challenging. Fortunately, the Packed Virtqueue implementation
in virtio_ring.c is not vulnerable to most host attacks through the
desc/driver/device interface.  

For Packed Virtqueue, the code in virtio_ring.c still allocates the [desc
array](https://github.com/lsds/lkl/blob/385f721b339fe48b188b4924c2663e1ea2cdeb13/drivers/virtio/virtio_ring.c#L1575)
in the host memory and reads flag and used buffer length from the desc array,
but it keeps a copy of the bounce buffer addr/len in a private data structure
['desc_extra'](https://github.com/lsds/lkl/blob/385f721b339fe48b188b4924c2663e1ea2cdeb13/drivers/virtio/virtio_ring.c#L1034),
and only reads the bounce buffer addr from the private data structure. For
Packed Virtqueue, "avail"/"driver" points to a 32-bit Driver Event Suppression
data structure, and "used"/"device" points to a 32-bit Driver Event Suppression
data structure, both in the shared memory. The guest side code only writes to
"avail"/"driver" and host side manipulation of "used"/"device" value can only
affect functionality, not security.

Ensuring the guest side virtio code only uses Packed Virtqueue will be sufficient
to protect against attacks from the host side on the Virtqueue desc/avail/used
arrays interface itself. This can be accomplished by verifying that any virtio
device to be registered supports Packed Virtqueue. The LKL host side code does
need to be changed to support Packed Virtqueue.

The Packed Virtqueue implementation in virtio_ring reads q->desc[].length as the
size of the data written to the "used" buffer by the host side. Sanity check
that q->desc[].length does not exceed the size of the bounce buffers allocated
might still need to be added.
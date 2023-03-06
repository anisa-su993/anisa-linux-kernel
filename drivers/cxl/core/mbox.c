// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2020 Intel Corporation. All rights reserved. */
#include <linux/security.h>
#include <linux/debugfs.h>
#include <linux/ktime.h>
#include <linux/mutex.h>
#include <linux/unaligned.h>
#include <linux/list.h>
#include <linux/list_sort.h>
#include <linux/sizes.h>
#include <cxlpci.h>
#include <cxlmem.h>
#include <cxl.h>

#include "core.h"
#include "trace.h"
#include "mce.h"

static bool cxl_raw_allow_all;

/**
 * DOC: cxl mbox
 *
 * Core implementation of the CXL 2.0 Type-3 Memory Device Mailbox. The
 * implementation is used by the cxl_pci driver to initialize the device
 * and implement the cxl_mem.h IOCTL UAPI. It also implements the
 * backend of the cxl_pmem_ctl() transport for LIBNVDIMM.
 */

#define cxl_for_each_cmd(cmd)                                                  \
	for ((cmd) = &cxl_mem_commands[0];                                     \
	     ((cmd) - cxl_mem_commands) < ARRAY_SIZE(cxl_mem_commands); (cmd)++)

#define CXL_CMD(_id, sin, sout, _flags)                                        \
	[CXL_MEM_COMMAND_ID_##_id] = {                                         \
	.info =	{                                                              \
			.id = CXL_MEM_COMMAND_ID_##_id,                        \
			.size_in = sin,                                        \
			.size_out = sout,                                      \
		},                                                             \
	.opcode = CXL_MBOX_OP_##_id,                                           \
	.flags = _flags,                                                       \
	}

#define CXL_VARIABLE_PAYLOAD	~0U
/*
 * This table defines the supported mailbox commands for the driver. This table
 * is made up of a UAPI structure. Non-negative values as parameters in the
 * table will be validated against the user's input. For example, if size_in is
 * 0, and the user passed in 1, it is an error.
 */
static struct cxl_mem_command cxl_mem_commands[CXL_MEM_COMMAND_ID_MAX] = {
	CXL_CMD(IDENTIFY, 0, 0x43, CXL_CMD_FLAG_FORCE_ENABLE),
#ifdef CONFIG_CXL_MEM_RAW_COMMANDS
	CXL_CMD(RAW, CXL_VARIABLE_PAYLOAD, CXL_VARIABLE_PAYLOAD, 0),
#endif
	CXL_CMD(GET_SUPPORTED_LOGS, 0, CXL_VARIABLE_PAYLOAD, CXL_CMD_FLAG_FORCE_ENABLE),
	CXL_CMD(GET_FW_INFO, 0, 0x50, 0),
	CXL_CMD(GET_PARTITION_INFO, 0, 0x20, 0),
	CXL_CMD(GET_LSA, 0x8, CXL_VARIABLE_PAYLOAD, 0),
	CXL_CMD(GET_HEALTH_INFO, 0, 0x12, 0),
	CXL_CMD(GET_LOG, 0x18, CXL_VARIABLE_PAYLOAD, CXL_CMD_FLAG_FORCE_ENABLE),
	CXL_CMD(GET_LOG_CAPS, 0x10, 0x4, 0),
	CXL_CMD(CLEAR_LOG, 0x10, 0, 0),
	CXL_CMD(GET_SUP_LOG_SUBLIST, 0x2, CXL_VARIABLE_PAYLOAD, 0),
	CXL_CMD(SET_PARTITION_INFO, 0x0a, 0, 0),
	CXL_CMD(SET_LSA, CXL_VARIABLE_PAYLOAD, 0, 0),
	CXL_CMD(GET_ALERT_CONFIG, 0, 0x10, 0),
	CXL_CMD(SET_ALERT_CONFIG, 0xc, 0, 0),
	CXL_CMD(GET_SHUTDOWN_STATE, 0, 0x1, 0),
	CXL_CMD(SET_SHUTDOWN_STATE, 0x1, 0, 0),
	CXL_CMD(GET_SCAN_MEDIA_CAPS, 0x10, 0x4, 0),
	CXL_CMD(GET_TIMESTAMP, 0, 0x8, 0),
};

/*
 * Commands that RAW doesn't permit. The rationale for each:
 *
 * CXL_MBOX_OP_ACTIVATE_FW: Firmware activation requires adjustment /
 * coordination of transaction timeout values at the root bridge level.
 *
 * CXL_MBOX_OP_SET_PARTITION_INFO: The device memory map may change live
 * and needs to be coordinated with HDM updates.
 *
 * CXL_MBOX_OP_SET_LSA: The label storage area may be cached by the
 * driver and any writes from userspace invalidates those contents.
 *
 * CXL_MBOX_OP_SET_SHUTDOWN_STATE: Set shutdown state assumes no writes
 * to the device after it is marked clean, userspace can not make that
 * assertion.
 *
 * CXL_MBOX_OP_[GET_]SCAN_MEDIA: The kernel provides a native error list that
 * is kept up to date with patrol notifications and error management.
 *
 * CXL_MBOX_OP_[GET_,INJECT_,CLEAR_]POISON: These commands require kernel
 * driver orchestration for safety.
 */
static u16 cxl_disabled_raw_commands[] = {
	CXL_MBOX_OP_ACTIVATE_FW,
	CXL_MBOX_OP_SET_PARTITION_INFO,
	CXL_MBOX_OP_SET_LSA,
	CXL_MBOX_OP_SET_SHUTDOWN_STATE,
	CXL_MBOX_OP_SCAN_MEDIA,
	CXL_MBOX_OP_GET_SCAN_MEDIA,
	CXL_MBOX_OP_GET_POISON,
	CXL_MBOX_OP_INJECT_POISON,
	CXL_MBOX_OP_CLEAR_POISON,
};

/*
 * Command sets that RAW doesn't permit. All opcodes in this set are
 * disabled because they pass plain text security payloads over the
 * user/kernel boundary. This functionality is intended to be wrapped
 * behind the keys ABI which allows for encrypted payloads in the UAPI
 */
static u8 security_command_sets[] = {
	0x44, /* Sanitize */
	0x45, /* Persistent Memory Data-at-rest Security */
	0x46, /* Security Passthrough */
};

static bool cxl_is_security_command(u16 opcode)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(security_command_sets); i++)
		if (security_command_sets[i] == (opcode >> 8))
			return true;
	return false;
}

static void cxl_set_security_cmd_enabled(struct cxl_security_state *security,
					 u16 opcode)
{
	switch (opcode) {
	case CXL_MBOX_OP_SANITIZE:
		set_bit(CXL_SEC_ENABLED_SANITIZE, security->enabled_cmds);
		break;
	case CXL_MBOX_OP_SECURE_ERASE:
		set_bit(CXL_SEC_ENABLED_SECURE_ERASE,
			security->enabled_cmds);
		break;
	case CXL_MBOX_OP_GET_SECURITY_STATE:
		set_bit(CXL_SEC_ENABLED_GET_SECURITY_STATE,
			security->enabled_cmds);
		break;
	case CXL_MBOX_OP_SET_PASSPHRASE:
		set_bit(CXL_SEC_ENABLED_SET_PASSPHRASE,
			security->enabled_cmds);
		break;
	case CXL_MBOX_OP_DISABLE_PASSPHRASE:
		set_bit(CXL_SEC_ENABLED_DISABLE_PASSPHRASE,
			security->enabled_cmds);
		break;
	case CXL_MBOX_OP_UNLOCK:
		set_bit(CXL_SEC_ENABLED_UNLOCK, security->enabled_cmds);
		break;
	case CXL_MBOX_OP_FREEZE_SECURITY:
		set_bit(CXL_SEC_ENABLED_FREEZE_SECURITY,
			security->enabled_cmds);
		break;
	case CXL_MBOX_OP_PASSPHRASE_SECURE_ERASE:
		set_bit(CXL_SEC_ENABLED_PASSPHRASE_SECURE_ERASE,
			security->enabled_cmds);
		break;
	default:
		break;
	}
}

static bool cxl_is_dcd_command(u16 opcode)
{
#define CXL_MBOX_OP_DCD_CMDS 0x48

	return (opcode >> 8) == CXL_MBOX_OP_DCD_CMDS;
}

static void cxl_set_dcd_cmd_enabled(struct cxl_memdev_state *mds, u16 opcode,
				    unsigned long *cmd_mask)
{
	switch (opcode) {
	case CXL_MBOX_OP_GET_DC_CONFIG:
		set_bit(CXL_DCD_ENABLED_GET_CONFIG, cmd_mask);
		break;
	case CXL_MBOX_OP_GET_DC_EXTENT_LIST:
		set_bit(CXL_DCD_ENABLED_GET_EXTENT_LIST, cmd_mask);
		break;
	case CXL_MBOX_OP_ADD_DC_RESPONSE:
		set_bit(CXL_DCD_ENABLED_ADD_RESPONSE, cmd_mask);
		break;
	case CXL_MBOX_OP_RELEASE_DC:
		set_bit(CXL_DCD_ENABLED_RELEASE, cmd_mask);
		break;
	default:
		break;
	}
}

static bool cxl_verify_dcd_cmds(struct cxl_memdev_state *mds, unsigned long *cmds_seen)
{
	DECLARE_BITMAP(all_cmds, CXL_DCD_ENABLED_MAX);

	bitmap_fill(all_cmds, CXL_DCD_ENABLED_MAX);
	return bitmap_equal(cmds_seen, all_cmds, CXL_DCD_ENABLED_MAX);
}

static bool cxl_is_poison_command(u16 opcode)
{
#define CXL_MBOX_OP_POISON_CMDS 0x43

	if ((opcode >> 8) == CXL_MBOX_OP_POISON_CMDS)
		return true;

	return false;
}

static void cxl_set_poison_cmd_enabled(struct cxl_poison_state *poison,
				       u16 opcode)
{
	switch (opcode) {
	case CXL_MBOX_OP_GET_POISON:
		set_bit(CXL_POISON_ENABLED_LIST, poison->enabled_cmds);
		break;
	case CXL_MBOX_OP_INJECT_POISON:
		set_bit(CXL_POISON_ENABLED_INJECT, poison->enabled_cmds);
		break;
	case CXL_MBOX_OP_CLEAR_POISON:
		set_bit(CXL_POISON_ENABLED_CLEAR, poison->enabled_cmds);
		break;
	case CXL_MBOX_OP_GET_SCAN_MEDIA_CAPS:
		set_bit(CXL_POISON_ENABLED_SCAN_CAPS, poison->enabled_cmds);
		break;
	case CXL_MBOX_OP_SCAN_MEDIA:
		set_bit(CXL_POISON_ENABLED_SCAN_MEDIA, poison->enabled_cmds);
		break;
	case CXL_MBOX_OP_GET_SCAN_MEDIA:
		set_bit(CXL_POISON_ENABLED_SCAN_RESULTS, poison->enabled_cmds);
		break;
	default:
		break;
	}
}

static struct cxl_mem_command *cxl_mem_find_command(u16 opcode)
{
	struct cxl_mem_command *c;

	cxl_for_each_cmd(c)
		if (c->opcode == opcode)
			return c;

	return NULL;
}

static const char *cxl_mem_opcode_to_name(u16 opcode)
{
	struct cxl_mem_command *c;

	c = cxl_mem_find_command(opcode);
	if (!c)
		return NULL;

	return cxl_command_names[c->info.id].name;
}

/**
 * cxl_internal_send_cmd() - Kernel internal interface to send a mailbox command
 * @cxl_mbox: CXL mailbox context
 * @mbox_cmd: initialized command to execute
 *
 * Context: Any context.
 * Return:
 *  * %>=0	- Number of bytes returned in @out.
 *  * %-E2BIG	- Payload is too large for hardware.
 *  * %-EBUSY	- Couldn't acquire exclusive mailbox access.
 *  * %-EFAULT	- Hardware error occurred.
 *  * %-ENXIO	- Command completed, but device reported an error.
 *  * %-EIO	- Unexpected output size.
 *
 * Mailbox commands may execute successfully yet the device itself reported an
 * error. While this distinction can be useful for commands from userspace, the
 * kernel will only be able to use results when both are successful.
 */
int cxl_internal_send_cmd(struct cxl_mailbox *cxl_mbox,
			  struct cxl_mbox_cmd *mbox_cmd)
{
	size_t out_size, min_out;
	int rc;

	if (mbox_cmd->size_in > cxl_mbox->payload_size ||
	    mbox_cmd->size_out > cxl_mbox->payload_size)
		return -E2BIG;

	out_size = mbox_cmd->size_out;
	min_out = mbox_cmd->min_out;
	rc = cxl_mbox->mbox_send(cxl_mbox, mbox_cmd);
	/*
	 * EIO is reserved for a payload size mismatch and mbox_send()
	 * may not return this error.
	 */
	if (WARN_ONCE(rc == -EIO, "Bad return code: -EIO"))
		return -ENXIO;
	if (rc)
		return rc;

	if (mbox_cmd->return_code != CXL_MBOX_CMD_RC_SUCCESS &&
	    mbox_cmd->return_code != CXL_MBOX_CMD_RC_BACKGROUND)
		return cxl_mbox_cmd_rc2errno(mbox_cmd);

	if (!out_size)
		return 0;

	/*
	 * Variable sized output needs to at least satisfy the caller's
	 * minimum if not the fully requested size.
	 */
	if (min_out == 0)
		min_out = out_size;

	if (mbox_cmd->size_out < min_out)
		return -EIO;
	return 0;
}
EXPORT_SYMBOL_NS_GPL(cxl_internal_send_cmd, "CXL");

static bool cxl_mem_raw_command_allowed(u16 opcode)
{
	int i;

	if (!IS_ENABLED(CONFIG_CXL_MEM_RAW_COMMANDS))
		return false;

	if (security_locked_down(LOCKDOWN_PCI_ACCESS))
		return false;

	if (cxl_raw_allow_all)
		return true;

	if (cxl_is_security_command(opcode))
		return false;

	for (i = 0; i < ARRAY_SIZE(cxl_disabled_raw_commands); i++)
		if (cxl_disabled_raw_commands[i] == opcode)
			return false;

	return true;
}

/**
 * cxl_payload_from_user_allowed() - Check contents of in_payload.
 * @opcode: The mailbox command opcode.
 * @payload_in: Pointer to the input payload passed in from user space.
 * @in_size: Size of @payload_in in bytes.
 *
 * Return:
 *  * true	- payload_in passes check for @opcode.
 *  * false	- payload_in contains invalid or unsupported values.
 *
 * The driver may inspect payload contents before sending a mailbox
 * command from user space to the device. The intent is to reject
 * commands with input payloads that are known to be unsafe. This
 * check is not intended to replace the users careful selection of
 * mailbox command parameters and makes no guarantee that the user
 * command will succeed, nor that it is appropriate.
 *
 * The specific checks are determined by the opcode.
 */
static bool cxl_payload_from_user_allowed(u16 opcode, void *payload_in,
					  size_t in_size)
{
	switch (opcode) {
	case CXL_MBOX_OP_SET_PARTITION_INFO: {
		struct cxl_mbox_set_partition_info *pi = payload_in;

		if (in_size < sizeof(*pi))
			return false;
		if (pi->flags & CXL_SET_PARTITION_IMMEDIATE_FLAG)
			return false;
		break;
	}
	case CXL_MBOX_OP_CLEAR_LOG: {
		const uuid_t *uuid = (uuid_t *)payload_in;

		if (in_size < sizeof(uuid_t))
			return false;
		/*
		 * Restrict the ‘Clear log’ action to only apply to
		 * Vendor debug logs.
		 */
		return uuid_equal(uuid, &DEFINE_CXL_VENDOR_DEBUG_UUID);
	}
	default:
		break;
	}
	return true;
}

static int cxl_mbox_cmd_ctor(struct cxl_mbox_cmd *mbox_cmd,
			     struct cxl_mailbox *cxl_mbox, u16 opcode,
			     size_t in_size, size_t out_size, u64 in_payload)
{
	*mbox_cmd = (struct cxl_mbox_cmd) {
		.opcode = opcode,
		.size_in = in_size,
	};

	if (in_size) {
		mbox_cmd->payload_in = vmemdup_user(u64_to_user_ptr(in_payload),
						    in_size);
		if (IS_ERR(mbox_cmd->payload_in))
			return PTR_ERR(mbox_cmd->payload_in);

		if (!cxl_payload_from_user_allowed(opcode, mbox_cmd->payload_in,
						  in_size)) {
			dev_dbg(cxl_mbox->host, "%s: input payload not allowed\n",
				cxl_mem_opcode_to_name(opcode));
			kvfree(mbox_cmd->payload_in);
			return -EBUSY;
		}
	}

	/* Prepare to handle a full payload for variable sized output */
	if (out_size == CXL_VARIABLE_PAYLOAD)
		mbox_cmd->size_out = cxl_mbox->payload_size;
	else
		mbox_cmd->size_out = out_size;

	if (mbox_cmd->size_out) {
		mbox_cmd->payload_out = kvzalloc(mbox_cmd->size_out, GFP_KERNEL);
		if (!mbox_cmd->payload_out) {
			kvfree(mbox_cmd->payload_in);
			return -ENOMEM;
		}
	}
	return 0;
}

static void cxl_mbox_cmd_dtor(struct cxl_mbox_cmd *mbox)
{
	kvfree(mbox->payload_in);
	kvfree(mbox->payload_out);
}

static int cxl_to_mem_cmd_raw(struct cxl_mem_command *mem_cmd,
			      const struct cxl_send_command *send_cmd,
			      struct cxl_mailbox *cxl_mbox)
{
	if (send_cmd->raw.rsvd)
		return -EINVAL;

	/*
	 * Unlike supported commands, the output size of RAW commands
	 * gets passed along without further checking, so it must be
	 * validated here.
	 */
	if (send_cmd->out.size > cxl_mbox->payload_size)
		return -EINVAL;

	if (!cxl_mem_raw_command_allowed(send_cmd->raw.opcode))
		return -EPERM;

	dev_WARN_ONCE(cxl_mbox->host, true, "raw command path used\n");

	*mem_cmd = (struct cxl_mem_command) {
		.info = {
			.id = CXL_MEM_COMMAND_ID_RAW,
			.size_in = send_cmd->in.size,
			.size_out = send_cmd->out.size,
		},
		.opcode = send_cmd->raw.opcode
	};

	return 0;
}

static int cxl_to_mem_cmd(struct cxl_mem_command *mem_cmd,
			  const struct cxl_send_command *send_cmd,
			  struct cxl_mailbox *cxl_mbox)
{
	struct cxl_mem_command *c = &cxl_mem_commands[send_cmd->id];
	const struct cxl_command_info *info = &c->info;

	if (send_cmd->flags & ~CXL_MEM_COMMAND_FLAG_MASK)
		return -EINVAL;

	if (send_cmd->rsvd)
		return -EINVAL;

	if (send_cmd->in.rsvd || send_cmd->out.rsvd)
		return -EINVAL;

	/* Check that the command is enabled for hardware */
	if (!test_bit(info->id, cxl_mbox->enabled_cmds))
		return -ENOTTY;

	/* Check that the command is not claimed for exclusive kernel use */
	if (test_bit(info->id, cxl_mbox->exclusive_cmds))
		return -EBUSY;

	/* Check the input buffer is the expected size */
	if ((info->size_in != CXL_VARIABLE_PAYLOAD) &&
	    (info->size_in != send_cmd->in.size))
		return -ENOMEM;

	/* Check the output buffer is at least large enough */
	if ((info->size_out != CXL_VARIABLE_PAYLOAD) &&
	    (send_cmd->out.size < info->size_out))
		return -ENOMEM;

	*mem_cmd = (struct cxl_mem_command) {
		.info = {
			.id = info->id,
			.flags = info->flags,
			.size_in = send_cmd->in.size,
			.size_out = send_cmd->out.size,
		},
		.opcode = c->opcode
	};

	return 0;
}

/**
 * cxl_validate_cmd_from_user() - Check fields for CXL_MEM_SEND_COMMAND.
 * @mbox_cmd: Sanitized and populated &struct cxl_mbox_cmd.
 * @cxl_mbox: CXL mailbox context
 * @send_cmd: &struct cxl_send_command copied in from userspace.
 *
 * Return:
 *  * %0	- @out_cmd is ready to send.
 *  * %-ENOTTY	- Invalid command specified.
 *  * %-EINVAL	- Reserved fields or invalid values were used.
 *  * %-ENOMEM	- Input or output buffer wasn't sized properly.
 *  * %-EPERM	- Attempted to use a protected command.
 *  * %-EBUSY	- Kernel has claimed exclusive access to this opcode
 *
 * The result of this command is a fully validated command in @mbox_cmd that is
 * safe to send to the hardware.
 */
static int cxl_validate_cmd_from_user(struct cxl_mbox_cmd *mbox_cmd,
				      struct cxl_mailbox *cxl_mbox,
				      const struct cxl_send_command *send_cmd)
{
	struct cxl_mem_command mem_cmd;
	int rc;

	if (send_cmd->id == 0 || send_cmd->id >= CXL_MEM_COMMAND_ID_MAX)
		return -ENOTTY;

	/*
	 * The user can never specify an input payload larger than what hardware
	 * supports, but output can be arbitrarily large (simply write out as
	 * much data as the hardware provides).
	 */
	if (send_cmd->in.size > cxl_mbox->payload_size)
		return -EINVAL;

	/* Sanitize and construct a cxl_mem_command */
	if (send_cmd->id == CXL_MEM_COMMAND_ID_RAW)
		rc = cxl_to_mem_cmd_raw(&mem_cmd, send_cmd, cxl_mbox);
	else
		rc = cxl_to_mem_cmd(&mem_cmd, send_cmd, cxl_mbox);

	if (rc)
		return rc;

	/* Sanitize and construct a cxl_mbox_cmd */
	return cxl_mbox_cmd_ctor(mbox_cmd, cxl_mbox, mem_cmd.opcode,
				 mem_cmd.info.size_in, mem_cmd.info.size_out,
				 send_cmd->in.payload);
}

int cxl_query_cmd(struct cxl_mailbox *cxl_mbox,
		  struct cxl_mem_query_commands __user *q)
{
	struct device *dev = cxl_mbox->host;
	struct cxl_mem_command *cmd;
	u32 n_commands;
	int j = 0;

	dev_dbg(dev, "Query IOCTL\n");

	if (get_user(n_commands, &q->n_commands))
		return -EFAULT;

	/* returns the total number if 0 elements are requested. */
	if (n_commands == 0)
		return put_user(ARRAY_SIZE(cxl_mem_commands), &q->n_commands);

	/*
	 * otherwise, return min(n_commands, total commands) cxl_command_info
	 * structures.
	 */
	cxl_for_each_cmd(cmd) {
		struct cxl_command_info info = cmd->info;

		if (test_bit(info.id, cxl_mbox->enabled_cmds))
			info.flags |= CXL_MEM_COMMAND_FLAG_ENABLED;
		if (test_bit(info.id, cxl_mbox->exclusive_cmds))
			info.flags |= CXL_MEM_COMMAND_FLAG_EXCLUSIVE;

		if (copy_to_user(&q->commands[j++], &info, sizeof(info)))
			return -EFAULT;

		if (j == n_commands)
			break;
	}

	return 0;
}

/**
 * handle_mailbox_cmd_from_user() - Dispatch a mailbox command for userspace.
 * @cxl_mbox: The mailbox context for the operation.
 * @mbox_cmd: The validated mailbox command.
 * @out_payload: Pointer to userspace's output payload.
 * @size_out: (Input) Max payload size to copy out.
 *            (Output) Payload size hardware generated.
 * @retval: Hardware generated return code from the operation.
 *
 * Return:
 *  * %0	- Mailbox transaction succeeded. This implies the mailbox
 *		  protocol completed successfully not that the operation itself
 *		  was successful.
 *  * %-ENOMEM  - Couldn't allocate a bounce buffer.
 *  * %-EFAULT	- Something happened with copy_to/from_user.
 *  * %-EINTR	- Mailbox acquisition interrupted.
 *  * %-EXXX	- Transaction level failures.
 *
 * Dispatches a mailbox command on behalf of a userspace request.
 * The output payload is copied to userspace.
 *
 * See cxl_send_cmd().
 */
static int handle_mailbox_cmd_from_user(struct cxl_mailbox *cxl_mbox,
					struct cxl_mbox_cmd *mbox_cmd,
					u64 out_payload, s32 *size_out,
					u32 *retval)
{
	struct device *dev = cxl_mbox->host;
	int rc;

	dev_dbg(dev,
		"Submitting %s command for user\n"
		"\topcode: %x\n"
		"\tsize: %zx\n",
		cxl_mem_opcode_to_name(mbox_cmd->opcode),
		mbox_cmd->opcode, mbox_cmd->size_in);

	rc = cxl_mbox->mbox_send(cxl_mbox, mbox_cmd);
	if (rc)
		goto out;

	/*
	 * @size_out contains the max size that's allowed to be written back out
	 * to userspace. While the payload may have written more output than
	 * this it will have to be ignored.
	 */
	if (mbox_cmd->size_out) {
		dev_WARN_ONCE(dev, mbox_cmd->size_out > *size_out,
			      "Invalid return size\n");
		if (copy_to_user(u64_to_user_ptr(out_payload),
				 mbox_cmd->payload_out, mbox_cmd->size_out)) {
			rc = -EFAULT;
			goto out;
		}
	}

	*size_out = mbox_cmd->size_out;
	*retval = mbox_cmd->return_code;

out:
	cxl_mbox_cmd_dtor(mbox_cmd);
	return rc;
}

int cxl_send_cmd(struct cxl_mailbox *cxl_mbox, struct cxl_send_command __user *s)
{
	struct device *dev = cxl_mbox->host;
	struct cxl_send_command send;
	struct cxl_mbox_cmd mbox_cmd;
	int rc;

	dev_dbg(dev, "Send IOCTL\n");

	if (copy_from_user(&send, s, sizeof(send)))
		return -EFAULT;

	rc = cxl_validate_cmd_from_user(&mbox_cmd, cxl_mbox, &send);
	if (rc)
		return rc;

	rc = handle_mailbox_cmd_from_user(cxl_mbox, &mbox_cmd, send.out.payload,
					  &send.out.size, &send.retval);
	if (rc)
		return rc;

	if (copy_to_user(s, &send, sizeof(send)))
		return -EFAULT;

	return 0;
}

static int cxl_xfer_log(struct cxl_memdev_state *mds, uuid_t *uuid,
			u32 *size, u8 *out)
{
	struct cxl_mailbox *cxl_mbox = &mds->cxlds.cxl_mbox;
	u32 remaining = *size;
	u32 offset = 0;

	while (remaining) {
		u32 xfer_size = min_t(u32, remaining, cxl_mbox->payload_size);
		struct cxl_mbox_cmd mbox_cmd;
		struct cxl_mbox_get_log log;
		int rc;

		log = (struct cxl_mbox_get_log) {
			.uuid = *uuid,
			.offset = cpu_to_le32(offset),
			.length = cpu_to_le32(xfer_size),
		};

		mbox_cmd = (struct cxl_mbox_cmd) {
			.opcode = CXL_MBOX_OP_GET_LOG,
			.size_in = sizeof(log),
			.payload_in = &log,
			.size_out = xfer_size,
			.payload_out = out,
		};

		rc = cxl_internal_send_cmd(cxl_mbox, &mbox_cmd);

		/*
		 * The output payload length that indicates the number
		 * of valid bytes can be smaller than the Log buffer
		 * size.
		 */
		if (rc == -EIO && mbox_cmd.size_out < xfer_size) {
			offset += mbox_cmd.size_out;
			break;
		}

		if (rc < 0)
			return rc;

		out += xfer_size;
		remaining -= xfer_size;
		offset += xfer_size;
	}

	*size = offset;

	return 0;
}

static int check_features_opcodes(u16 opcode, int *ro_cmds, int *wr_cmds)
{
	switch (opcode) {
	case CXL_MBOX_OP_GET_SUPPORTED_FEATURES:
	case CXL_MBOX_OP_GET_FEATURE:
		(*ro_cmds)++;
		return 1;
	case CXL_MBOX_OP_SET_FEATURE:
		(*wr_cmds)++;
		return 1;
	default:
		return 0;
	}
}

/* 'Get Supported Features' and 'Get Feature' */
#define MAX_FEATURES_READ_CMDS	2
static void set_features_cap(struct cxl_mailbox *cxl_mbox,
			     int ro_cmds, int wr_cmds)
{
	/* Setting up Features capability while walking the CEL */
	if (ro_cmds == MAX_FEATURES_READ_CMDS) {
		if (wr_cmds)
			cxl_mbox->feat_cap = CXL_FEATURES_RW;
		else
			cxl_mbox->feat_cap = CXL_FEATURES_RO;
	}
}

/**
 * cxl_walk_cel() - Walk through the Command Effects Log.
 * @mds: The driver data for the operation
 * @size: Length of the Command Effects Log.
 * @cel: CEL
 *
 * Iterate over each entry in the CEL and determine if the driver supports the
 * command. If so, the command is enabled for the device and can be used later.
 */
static void cxl_walk_cel(struct cxl_memdev_state *mds, size_t size, u8 *cel)
{
	struct cxl_mailbox *cxl_mbox = &mds->cxlds.cxl_mbox;
	struct cxl_cel_entry *cel_entry;
	const int cel_entries = size / sizeof(*cel_entry);
	DECLARE_BITMAP(dcd_cmds, CXL_DCD_ENABLED_MAX);
	struct device *dev = mds->cxlds.dev;
	int i, ro_cmds = 0, wr_cmds = 0;

	cel_entry = (struct cxl_cel_entry *) cel;

	for (i = 0; i < cel_entries; i++) {
		u16 opcode = le16_to_cpu(cel_entry[i].opcode);
		struct cxl_mem_command *cmd = cxl_mem_find_command(opcode);
		int enabled = 0;

		if (cmd) {
			set_bit(cmd->info.id, cxl_mbox->enabled_cmds);
			enabled++;
		}

		enabled += check_features_opcodes(opcode, &ro_cmds,
						  &wr_cmds);

		if (cxl_is_poison_command(opcode)) {
			cxl_set_poison_cmd_enabled(&mds->poison, opcode);
			enabled++;
		}

		if (cxl_is_security_command(opcode)) {
			cxl_set_security_cmd_enabled(&mds->security, opcode);
			enabled++;
		}

		if (cxl_is_dcd_command(opcode)) {
			cxl_set_dcd_cmd_enabled(mds, opcode, dcd_cmds);
			enabled++;
		}

		dev_dbg(dev, "Opcode 0x%04x %s\n", opcode,
			enabled ? "enabled" : "unsupported by driver");
	}

	set_features_cap(cxl_mbox, ro_cmds, wr_cmds);
	mds->dcd_supported = cxl_verify_dcd_cmds(mds, dcd_cmds);
}

static struct cxl_mbox_get_supported_logs *cxl_get_gsl(struct cxl_memdev_state *mds)
{
	struct cxl_mailbox *cxl_mbox = &mds->cxlds.cxl_mbox;
	struct cxl_mbox_get_supported_logs *ret;
	struct cxl_mbox_cmd mbox_cmd;
	int rc;

	ret = kvmalloc(cxl_mbox->payload_size, GFP_KERNEL);
	if (!ret)
		return ERR_PTR(-ENOMEM);

	mbox_cmd = (struct cxl_mbox_cmd) {
		.opcode = CXL_MBOX_OP_GET_SUPPORTED_LOGS,
		.size_out = cxl_mbox->payload_size,
		.payload_out = ret,
		/* At least the record number field must be valid */
		.min_out = 2,
	};
	rc = cxl_internal_send_cmd(cxl_mbox, &mbox_cmd);
	if (rc < 0) {
		kvfree(ret);
		return ERR_PTR(rc);
	}


	return ret;
}

enum {
	CEL_UUID,
	VENDOR_DEBUG_UUID,
};

/* See CXL 2.0 Table 170. Get Log Input Payload */
static const uuid_t log_uuid[] = {
	[CEL_UUID] = DEFINE_CXL_CEL_UUID,
	[VENDOR_DEBUG_UUID] = DEFINE_CXL_VENDOR_DEBUG_UUID,
};

/**
 * cxl_enumerate_cmds() - Enumerate commands for a device.
 * @mds: The driver data for the operation
 *
 * Returns 0 if enumerate completed successfully.
 *
 * CXL devices have optional support for certain commands. This function will
 * determine the set of supported commands for the hardware and update the
 * enabled_cmds bitmap in the @mds.
 */
int cxl_enumerate_cmds(struct cxl_memdev_state *mds)
{
	struct cxl_mailbox *cxl_mbox = &mds->cxlds.cxl_mbox;
	struct cxl_mbox_get_supported_logs *gsl;
	struct device *dev = mds->cxlds.dev;
	struct cxl_mem_command *cmd;
	int i, rc;

	gsl = cxl_get_gsl(mds);
	if (IS_ERR(gsl))
		return PTR_ERR(gsl);

	rc = -ENOENT;
	for (i = 0; i < le16_to_cpu(gsl->entries); i++) {
		u32 size = le32_to_cpu(gsl->entry[i].size);
		uuid_t uuid = gsl->entry[i].uuid;
		u8 *log;

		dev_dbg(dev, "Found LOG type %pU of size %d", &uuid, size);

		if (!uuid_equal(&uuid, &log_uuid[CEL_UUID]))
			continue;

		log = kvmalloc(size, GFP_KERNEL);
		if (!log) {
			rc = -ENOMEM;
			goto out;
		}

		rc = cxl_xfer_log(mds, &uuid, &size, log);
		if (rc) {
			kvfree(log);
			goto out;
		}

		cxl_walk_cel(mds, size, log);
		kvfree(log);

		/* In case CEL was bogus, enable some default commands. */
		cxl_for_each_cmd(cmd)
			if (cmd->flags & CXL_CMD_FLAG_FORCE_ENABLE)
				set_bit(cmd->info.id, cxl_mbox->enabled_cmds);

		/* Found the required CEL */
		rc = 0;
	}
out:
	kvfree(gsl);
	return rc;
}
EXPORT_SYMBOL_NS_GPL(cxl_enumerate_cmds, "CXL");

/*
 * Find the DC (Dynamic Capacity) partition that fully contains @ext_range,
 * or NULL if the extent falls outside every DC partition on this memdev.
 * The returned pointer is owned by mds->cxlds.part[] and lives for the
 * lifetime of the memdev.
 */
static const struct cxl_dpa_partition *
cxl_extent_dc_partition(struct cxl_memdev_state *mds,
			struct cxl_extent *extent,
			struct range *ext_range)
{
	struct cxl_dev_state *cxlds = &mds->cxlds;
	struct device *dev = mds->cxlds.dev;

	for (int i = 0; i < cxlds->nr_partitions; i++) {
		struct cxl_dpa_partition *part = &cxlds->part[i];
		struct range partition_range = {
			.start = part->res.start,
			.end = part->res.end,
		};

		if (part->mode != CXL_PARTMODE_DYNAMIC_RAM_A)
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
 * Per-extent validation for an Add-Capacity event.  Two regimes, chosen
 * by the DC partition's CDAT-advertised sharability:
 *
 *   Sharable partition (DSMAS flag ACPI_CDAT_DSMAS_SHAREABLE,
 *   reflected in part->perf.shareable):
 *     - A non-null tag (UUID) is required.  The tag is the allocation
 *       identity that every host sharing the allocation uses.
 *     - shared_extn_seq must be non-zero.  Together with the other
 *       members of the tag group it forms the 1..n contiguous set that
 *       cxl_check_group_seq() enforces.
 *
 *   Non-sharable partition:
 *     - The tag is optional; null UUID is permitted.
 *     - shared_extn_seq must be 0.  Sequencing is meaningless when
 *       only one host consumes the allocation.
 *
 * Any cross-mixing (sharable partition with null tag or seq == 0;
 * non-sharable partition with non-zero seq) is a device firmware bug.
 * Partition-boundary and region-attachment checks are separate.
 */
static int cxl_validate_extent(struct cxl_memdev_state *mds,
			       struct cxl_extent_list_node *pos)
{
	struct device *dev = mds->cxlds.dev;
	struct cxl_extent *extent = pos->extent;
	struct range ext_range = (struct range) {
		.start = le64_to_cpu(extent->start_dpa),
		.end = le64_to_cpu(extent->start_dpa) +
			le64_to_cpu(extent->length) - 1,
	};
	uuid_t *uuid = (uuid_t *)extent->uuid;
	const struct cxl_dpa_partition *part;
	u16 seq = le16_to_cpu(extent->shared_extn_seq);

	part = cxl_extent_dc_partition(mds, extent, &ext_range);
	if (!part)
		return -ENXIO;

	if (part->perf.shareable) {
		if (uuid_is_null(uuid)) {
			dev_err_ratelimited(dev,
				"DC extent DPA %pra: sharable-partition extent has null tag (firmware bug)\n",
				&ext_range);
			return -ENXIO;
		}
		if (seq == 0) {
			dev_err_ratelimited(dev,
				"DC extent DPA %pra (%pU): sharable-partition extent missing shared_extn_seq (firmware bug)\n",
				&ext_range, uuid);
			return -ENXIO;
		}
		return 0;
	}

	/* Non-sharable partition. */
	if (seq != 0) {
		dev_err_ratelimited(dev,
			"DC extent DPA %pra (%pU): non-sharable partition but shared_extn_seq=%u (firmware bug)\n",
			&ext_range, uuid, seq);
		return -ENXIO;
	}

	return 0;
}

void cxl_event_trace_record(const struct cxl_memdev *cxlmd,
			    enum cxl_event_log_type type,
			    enum cxl_event_type event_type,
			    const uuid_t *uuid, union cxl_event *evt)
{
	if (event_type == CXL_CPER_EVENT_MEM_MODULE) {
		trace_cxl_memory_module(cxlmd, type, &evt->mem_module);
		return;
	}
	if (event_type == CXL_CPER_EVENT_GENERIC) {
		trace_cxl_generic_event(cxlmd, type, uuid, &evt->generic);
		return;
	}
	if (event_type == CXL_CPER_EVENT_MEM_SPARING) {
		trace_cxl_memory_sparing(cxlmd, type, &evt->mem_sparing);
		return;
	}

	if (trace_cxl_general_media_enabled() || trace_cxl_dram_enabled()) {
		u64 dpa, hpa = ULLONG_MAX, hpa_alias = ULLONG_MAX;
		struct cxl_region *cxlr;

		/*
		 * These trace points are annotated with HPA and region
		 * translations. Take topology mutation locks and lookup
		 * { HPA, REGION } from { DPA, MEMDEV } in the event record.
		 */
		guard(rwsem_read)(&cxl_rwsem.region);
		guard(rwsem_read)(&cxl_rwsem.dpa);

		dpa = le64_to_cpu(evt->media_hdr.phys_addr) & CXL_DPA_MASK;
		cxlr = cxl_dpa_to_region(cxlmd, dpa, NULL);
		if (cxlr) {
			u64 cache_size = cxlr->params.cache_size;

			hpa = cxl_dpa_to_hpa(cxlr, cxlmd, dpa);
			if (cache_size)
				hpa_alias = hpa - cache_size;
		}

		if (event_type == CXL_CPER_EVENT_GEN_MEDIA) {
			if (cxl_store_rec_gen_media((struct cxl_memdev *)cxlmd, evt))
				dev_dbg(&cxlmd->dev, "CXL store rec_gen_media failed\n");

			if (evt->gen_media.media_hdr.descriptor &
			    CXL_GMER_EVT_DESC_THRESHOLD_EVENT)
				WARN_ON_ONCE((evt->gen_media.media_hdr.type &
					      CXL_GMER_MEM_EVT_TYPE_AP_CME_COUNTER_EXPIRE) &&
					     !get_unaligned_le24(evt->gen_media.cme_count));
			else
				WARN_ON_ONCE(evt->gen_media.media_hdr.type &
					     CXL_GMER_MEM_EVT_TYPE_AP_CME_COUNTER_EXPIRE);

			trace_cxl_general_media(cxlmd, type, cxlr, hpa,
						hpa_alias, &evt->gen_media);
		} else if (event_type == CXL_CPER_EVENT_DRAM) {
			if (cxl_store_rec_dram((struct cxl_memdev *)cxlmd, evt))
				dev_dbg(&cxlmd->dev, "CXL store rec_dram failed\n");

			if (evt->dram.media_hdr.descriptor &
			    CXL_GMER_EVT_DESC_THRESHOLD_EVENT)
				WARN_ON_ONCE((evt->dram.media_hdr.type &
					      CXL_DER_MEM_EVT_TYPE_AP_CME_COUNTER_EXPIRE) &&
					     !get_unaligned_le24(evt->dram.cvme_count));
			else
				WARN_ON_ONCE(evt->dram.media_hdr.type &
					     CXL_DER_MEM_EVT_TYPE_AP_CME_COUNTER_EXPIRE);

			trace_cxl_dram(cxlmd, type, cxlr, hpa, hpa_alias,
				       &evt->dram);
		}
	}
}
EXPORT_SYMBOL_NS_GPL(cxl_event_trace_record, "CXL");

static void __cxl_event_trace_record(const struct cxl_memdev *cxlmd,
				     enum cxl_event_log_type type,
				     struct cxl_event_record_raw *record)
{
	enum cxl_event_type ev_type = CXL_CPER_EVENT_GENERIC;
	const uuid_t *uuid = &record->id;

	if (uuid_equal(uuid, &CXL_EVENT_GEN_MEDIA_UUID))
		ev_type = CXL_CPER_EVENT_GEN_MEDIA;
	else if (uuid_equal(uuid, &CXL_EVENT_DRAM_UUID))
		ev_type = CXL_CPER_EVENT_DRAM;
	else if (uuid_equal(uuid, &CXL_EVENT_MEM_MODULE_UUID))
		ev_type = CXL_CPER_EVENT_MEM_MODULE;
	else if (uuid_equal(uuid, &CXL_EVENT_MEM_SPARING_UUID))
		ev_type = CXL_CPER_EVENT_MEM_SPARING;
	else if (uuid_equal(uuid, &CXL_EVENT_DC_EVENT_UUID)) {
/* FIXME still valid? */
		trace_cxl_dynamic_capacity(cxlmd, type, &record->event.dcd);
		return;
	}

	cxl_event_trace_record(cxlmd, type, ev_type, uuid, &record->event);
}

static int cxl_clear_event_record(struct cxl_memdev_state *mds,
				  enum cxl_event_log_type log,
				  struct cxl_get_event_payload *get_pl)
{
	struct cxl_mailbox *cxl_mbox = &mds->cxlds.cxl_mbox;
	struct cxl_mbox_clear_event_payload *payload;
	u16 total = le16_to_cpu(get_pl->record_count);
	u8 max_handles = CXL_CLEAR_EVENT_MAX_HANDLES;
	size_t pl_size = struct_size(payload, handles, max_handles);
	struct cxl_mbox_cmd mbox_cmd;
	u16 cnt;
	int rc = 0;
	int i;

	/* Payload size may limit the max handles */
	if (pl_size > cxl_mbox->payload_size) {
		max_handles = (cxl_mbox->payload_size - sizeof(*payload)) /
			      sizeof(__le16);
		pl_size = struct_size(payload, handles, max_handles);
	}

	payload = kvzalloc(pl_size, GFP_KERNEL);
	if (!payload)
		return -ENOMEM;

	*payload = (struct cxl_mbox_clear_event_payload) {
		.event_log = log,
	};

	mbox_cmd = (struct cxl_mbox_cmd) {
		.opcode = CXL_MBOX_OP_CLEAR_EVENT_RECORD,
		.payload_in = payload,
		.size_in = pl_size,
	};

	/*
	 * Clear Event Records uses u8 for the handle cnt while Get Event
	 * Record can return up to 0xffff records.
	 */
	i = 0;
	for (cnt = 0; cnt < total; cnt++) {
		struct cxl_event_record_raw *raw = &get_pl->records[cnt];
		struct cxl_event_generic *gen = &raw->event.generic;

		payload->handles[i++] = gen->hdr.handle;
		dev_dbg(mds->cxlds.dev, "Event log '%d': Clearing %u\n", log,
			le16_to_cpu(payload->handles[i - 1]));

		if (i == max_handles) {
			payload->nr_recs = i;
			rc = cxl_internal_send_cmd(cxl_mbox, &mbox_cmd);
			if (rc)
				goto free_pl;
			i = 0;
		}
	}

	/* Clear what is left if any */
	if (i) {
		payload->nr_recs = i;
		mbox_cmd.size_in = struct_size(payload, handles, i);
		rc = cxl_internal_send_cmd(cxl_mbox, &mbox_cmd);
		if (rc)
			goto free_pl;
	}

free_pl:
	kvfree(payload);
	return rc;
}

static int send_one_response(struct cxl_mailbox *cxl_mbox,
			     struct cxl_mbox_dc_response *response,
			     int opcode, u32 extent_list_size, u8 flags)
{
	struct cxl_mbox_cmd mbox_cmd = (struct cxl_mbox_cmd) {
		.opcode = opcode,
		.size_in = struct_size(response, extent_list, extent_list_size),
		.payload_in = response,
	};

	response->extent_list_size = cpu_to_le32(extent_list_size);
	response->flags = flags;
	return cxl_internal_send_cmd(cxl_mbox, &mbox_cmd);
}

static int cxl_send_dc_response(struct cxl_memdev_state *mds, int opcode,
				struct list_head *extent_list, int cnt)
{
	struct cxl_mailbox *cxl_mbox = &mds->cxlds.cxl_mbox;
	struct cxl_mbox_dc_response *p;
	struct cxl_extent_list_node *pos, *tmp;
	struct cxl_extent *extent;
	u32 pl_index;

	size_t pl_size = struct_size(p, extent_list, cnt);
	u32 max_extents = cnt;

	/* May have to use more bit on response. */
	if (pl_size > cxl_mbox->payload_size) {
		max_extents = (cxl_mbox->payload_size - sizeof(*p)) /
			      sizeof(struct updated_extent_list);
		pl_size = struct_size(p, extent_list, max_extents);
	}

	struct cxl_mbox_dc_response *response __free(kfree) =
						kzalloc(pl_size, GFP_KERNEL);
	if (!response)
		return -ENOMEM;

	if (cnt == 0)
		return send_one_response(cxl_mbox, response, opcode, 0, 0);

	pl_index = 0;
	list_for_each_entry_safe(pos, tmp, extent_list, list) {
		extent = pos->extent;
		response->extent_list[pl_index].dpa_start = extent->start_dpa;
		response->extent_list[pl_index].length = extent->length;
		pl_index++;

		if (pl_index == max_extents) {
			u8 flags = 0;
			int rc;

			if (pl_index < cnt)
				flags |= CXL_DCD_EVENT_MORE;
			rc = send_one_response(cxl_mbox, response, opcode,
					       pl_index, flags);
			if (rc)
				return rc;
			cnt -= pl_index;
			if (cnt < max_extents)
				max_extents = cnt;
			pl_index = 0;
		}
	}

	if (!pl_index) /* nothing more to do */
		return 0;
	return send_one_response(cxl_mbox, response, opcode, pl_index, 0);
}

static void delete_extent_node(struct cxl_extent_list_node *node)
{
	list_del(&node->list);
	kfree(node->extent);
	kfree(node);
}

void memdev_release_extent(struct cxl_memdev_state *mds, struct range *range)
{
	struct device *dev = mds->cxlds.dev;
	struct cxl_extent_list_node *node;
	LIST_HEAD(extent_list);

	dev_dbg(dev, "Release response dpa %pra\n", range);

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return;

	node->extent = kzalloc(sizeof(*node->extent), GFP_KERNEL);
	if (!node->extent) {
		kfree(node);
		return;
	}

	node->extent->start_dpa = cpu_to_le64(range->start);
	node->extent->length = cpu_to_le64(range_len(range));
	list_add_tail(&node->list, &extent_list);

	if (cxl_send_dc_response(mds, CXL_MBOX_OP_RELEASE_DC, &extent_list, 1))
		dev_dbg(dev, "Failed to release %pra\n", range);

	delete_extent_node(node);
}

static void clear_pending_extents(void *_mds)
{
	struct cxl_memdev_state *mds = _mds;
	struct cxl_extent_list_node *pos, *tmp;

	list_for_each_entry_safe(pos, tmp, &mds->add_ctx.pending_extents, list) {
                delete_extent_node(pos);
        }
	mds->add_ctx.group = NULL;
}

/*
 * Device-dax requires extent boundaries aligned to its mapping granularity.
 * Use SZ_2M as a conservative default; a tighter check that queries the
 * cxl_dax_region / cxl_endpoint_decoder for its actual alignment would be
 * strictly more correct, but SZ_2M is the minimum device-dax supports on
 * every architecture that enables CXL DCD today.
 */
#define CXL_DCD_EXTENT_ALIGN	SZ_2M

static bool cxl_extent_dcd_aligned(const struct cxl_extent *extent)
{
	u64 start = le64_to_cpu(extent->start_dpa);
	u64 len = le64_to_cpu(extent->length);

	return IS_ALIGNED(start, CXL_DCD_EXTENT_ALIGN) &&
	       IS_ALIGNED(len, CXL_DCD_EXTENT_ALIGN);
}

/*
 * Compare two extents by shared_extn_seq (ascending).
 *
 * Per CXL 3.1 Table 8-51, shared_extn_seq is defined only for extents in
 * *sharable* CDAT regions: those extents are required to carry both a
 * non-null tag and a per-allocation sequence number so multiple hosts
 * reading the same allocation assemble the extents into the same order.
 *
 * Extents in non-sharable regions do not carry a sequence number
 * (shared_extn_seq == 0 on every extent); for those, a single host's
 * arrival order is a sufficient definition of "the order the device
 * sent them."  list_sort() is stable, so when every element in a group
 * has shared_extn_seq == 0, ties fall back to list order — which is
 * arrival order via list_add_tail() in add_to_pending_list().  One
 * comparator, both regimes.
 */
static int extent_seq_compare(void *priv,
			      const struct list_head *a,
			      const struct list_head *b)
{
	const struct cxl_extent_list_node *ea =
		list_entry(a, struct cxl_extent_list_node, list);
	const struct cxl_extent_list_node *eb =
		list_entry(b, struct cxl_extent_list_node, list);
	u16 sa = le16_to_cpu(ea->extent->shared_extn_seq);
	u16 sb = le16_to_cpu(eb->extent->shared_extn_seq);

	if (sa < sb)
		return -1;
	if (sa > sb)
		return 1;
	return 0;
}

/*
 * Move every pending extent whose tag matches @tag onto @group, preserving
 * the order they appear in @pending.  @group is left in arrival order so
 * the caller can then sort it by shared_extn_seq with list_sort()'s stable
 * ordering guarantee.
 */
static void extract_tag_group(struct list_head *pending,
			      const uuid_t *tag,
			      struct list_head *group)
{
	struct cxl_extent_list_node *pos, *tmp;

	list_for_each_entry_safe(pos, tmp, pending, list) {
		uuid_t t;

		import_uuid(&t, pos->extent->uuid);
		if (uuid_equal(&t, tag))
			list_move_tail(&pos->list, group);
	}
}

/*
 * Detect a tagged allocation re-appearing after its More-chain closed.
 *
 * A More-chain (the sequence of Add-Capacity events terminated by
 * More=0) guarantees completeness for every tag it carries: once the
 * chain ends, no extent bearing a tag that appeared inside it may
 * arrive in any later chain.  This is true for tagged extents whether
 * or not they carry shared_extn_seq — sequencing is a sharable-region
 * concern, completeness is a general one.
 *
 * Detection here is a linear walk of cxlr_dax->dc_extents (keyed by
 * allocator-assigned IDs, not by UUID) comparing each stored
 * dc_extent's containing tag against the incoming tag.
 *
 * Returns true iff @tag is non-null AND a dc_extent whose tag group
 * uuid matches already exists on the target region.  For an untagged
 * (null-UUID) extent the check is skipped: the spec is silent on
 * aggregating untagged extents across More-chains, so we don't
 * manufacture a rule here.
 */
static bool cxl_tag_already_committed(struct cxl_memdev_state *mds,
				      struct cxl_extent *extent,
				      const uuid_t *tag)
{
	u64 start_dpa = le64_to_cpu(extent->start_dpa);
	struct cxl_memdev *cxlmd = mds->cxlds.cxlmd;
	struct cxl_dax_region *cxlr_dax;
	struct dc_extent *dce;
	struct cxl_region *cxlr;
	unsigned long idx;

	if (uuid_is_null(tag))
		return false;

	guard(rwsem_read)(&cxl_rwsem.region);
	cxlr = cxl_dpa_to_region(cxlmd, start_dpa, NULL);
	if (!cxlr)
		return false;

	cxlr_dax = cxlr->cxlr_dax;
	xa_for_each(&cxlr_dax->dc_extents, idx, dce) {
		if (uuid_equal(&dce->group->uuid, tag))
			return true;
	}
	return false;
}

/*
 * Validate shared_extn_seq across a tag group already sorted ascending.
 *
 * Per CXL 3.1 Table 8-51, shared_extn_seq is the per-allocation
 * extent sequence number.  Interpretation:
 *
 *   - For extents in non-sharable regions the field is unused; every
 *     extent of the allocation carries shared_extn_seq == 0.
 *   - For extents in sharable regions the field carries the device's
 *     stamped position within the allocation.  Valid values are 1..n
 *     where n is the number of extents in the allocation; the set
 *     must be contiguous (no gaps), unique (no duplicates), and
 *     complete (no missing positions).  0 is reserved as the
 *     "non-sharable" marker and is not a valid sharable sequence
 *     number.
 *
 * Hence a tag group is well-formed iff either (a) every extent has
 * shared_extn_seq == 0, or (b) the sorted group is exactly 1, 2, ...,
 * n.  Anything else — a mix of 0 and non-zero values, a non-zero set
 * that does not start at 1, a gap, or a duplicate — is a device
 * firmware bug.  Reject the whole group in those cases; partial
 * acceptance would surface a dax device whose backing layout does
 * not reflect the device's allocation.
 *
 * cxl_validate_extent() enforces the per-extent partition/sharable
 * consistency (sharable partition -> non-null tag + non-zero seq;
 * non-sharable -> seq == 0), so by the time a group reaches this
 * check all members agree on regime.  This helper then enforces the
 * group-level invariants the per-extent check cannot see: that
 * sharable groups form an exact 1..n set with no gap or duplicate.
 */
static int cxl_check_group_seq(struct device *dev,
			       const uuid_t *tag,
			       const struct list_head *group)
{
	struct cxl_extent_list_node *pos;
	u16 first, expected;

	if (list_empty(group))
		return 0;

	pos = list_first_entry(group, struct cxl_extent_list_node, list);
	first = le16_to_cpu(pos->extent->shared_extn_seq);

	if (first == 0) {
		/* Non-sharable: every member must be 0. */
		list_for_each_entry(pos, group, list) {
			if (le16_to_cpu(pos->extent->shared_extn_seq) != 0) {
				dev_warn(dev,
					 "Tag %pUb: shared_extn_seq mixed 0/non-zero in one allocation (firmware bug)\n",
					 tag);
				return -EINVAL;
			}
		}
		return 0;
	}

	/* Sharable: group must be exactly 1, 2, ..., n (contiguous). */
	if (first != 1) {
		dev_warn(dev,
			 "Tag %pUb: shared_extn_seq starts at %u, expected 1 (firmware bug)\n",
			 tag, first);
		return -EINVAL;
	}

	expected = 1;
	list_for_each_entry(pos, group, list) {
		u16 s = le16_to_cpu(pos->extent->shared_extn_seq);

		if (s != expected) {
			dev_warn(dev,
				 "Tag %pUb: shared_extn_seq gap/dup: expected %u got %u (firmware bug)\n",
				 tag, expected, s);
			return -EINVAL;
		}
		expected++;
	}
	return 0;
}

/*
 * For tagged groups, reject allocations that span DC partitions.
 *
 * A tag is an allocation identity; the CDAT DSMAS entry that describes
 * the containing DC partition is what tells the host which attributes
 * (sharable, writable, HW cache coherency) apply.  At current driver
 * granularity each DC partition is described by at most one DSMAS and
 * the only plumbed attribute is part->perf.shareable — but partition
 * identity is a sufficient proxy for "same set of CDAT attributes."
 * Comparing the containing cxl_dpa_partition of every extent to the
 * first extent's therefore implicitly enforces attribute equality for
 * all attributes the driver distinguishes today, and will keep doing so
 * as more attributes become CDAT-plumbed.
 *
 * Untagged (null-UUID) groups are not meaningful here: the spec does
 * not define a cross-chain identity for them and the driver aggregates
 * them separately; skip the check.
 */
static int cxl_check_group_partition(struct cxl_memdev_state *mds,
				     const uuid_t *tag,
				     const struct list_head *group)
{
	struct device *dev = mds->cxlds.dev;
	const struct cxl_dpa_partition *first_part = NULL;
	u64 first_dpa = 0;
	struct cxl_extent_list_node *pos;

	if (uuid_is_null(tag) || list_empty(group))
		return 0;

	list_for_each_entry(pos, group, list) {
		struct cxl_extent *extent = pos->extent;
		struct range ext_range = (struct range) {
			.start = le64_to_cpu(extent->start_dpa),
			.end = le64_to_cpu(extent->start_dpa) +
				le64_to_cpu(extent->length) - 1,
		};
		const struct cxl_dpa_partition *part;

		part = cxl_extent_dc_partition(mds, extent, &ext_range);
		if (!part)
			return -ENXIO;

		if (!first_part) {
			first_part = part;
			first_dpa = ext_range.start;
			continue;
		}

		if (part != first_part) {
			dev_warn(dev,
				 "Tag %pUb: extents span DC partitions (DPA:%#llx and DPA:%#llx), firmware bug\n",
				 tag, first_dpa, ext_range.start);
			return -EINVAL;
		}
	}
	return 0;
}

/*
 * Assemble the pending Add-Capacity events into dax devices and send the
 * ADD_DC_RESPONSE.
 *
 * Spec semantics (CXL 3.1 8.2.9.9.9.3 / 8.2.9.2.1.6):
 *
 *   - The unit of allocation is a *tag*, not a More-chain.  All extents
 *     that share the same tag form one allocation and must be assembled
 *     into a single dax device.  For extents in sharable CDAT regions
 *     a non-null tag is required; for extents in non-sharable regions
 *     the tag is optional — the null UUID is a valid "untagged"
 *     allocation identity.
 *
 *   - Within a tag, extents must be ordered by shared_extn_seq (the
 *     per-allocation sequence number, Table 8-51).  shared_extn_seq is
 *     a sharable-region concern: multiple hosts reading the same
 *     allocation need to agree on assembly order, so the device stamps
 *     each extent with its position.  For non-sharable extents the
 *     spec does not provide sequence numbers (shared_extn_seq == 0 on
 *     every extent); the lone host simply assembles in arrival order.
 *     list_sort() is stable, so one comparator handles both cases:
 *     sequence-number order when it is populated, arrival order when
 *     every tie key is zero.
 *
 *     Valid sharable values are 1..n, contiguous and unique across the
 *     n extents of one allocation; 0 is reserved for the non-sharable
 *     marker.  A tag group is well-formed iff either every member is
 *     0 or the sorted group is exactly 1, 2, ..., n.  See
 *     cxl_check_group_seq().
 *
 *   - A More-chain is a delivery boundary, not an allocation boundary:
 *     it may carry extents for several distinct tags.  What More=0
 *     guarantees is completeness — for every tag that appears inside
 *     the chain, all of that tag's extents are delivered by the time
 *     the chain closes.  This completeness guarantee applies to tagged
 *     allocations regardless of whether the extents carry sequence
 *     numbers.  Therefore, receiving an extent bearing a tag that a
 *     previous More-chain already committed is a device firmware bug:
 *     the tag's allocation was supposed to have been complete when its
 *     chain closed.  The untagged case is excluded — the spec does not
 *     define a cross-chain identity for untagged extents.
 *
 *   - An allocation is not required to be DPA-contiguous; extents exist
 *     precisely so the device can satisfy one allocation from scattered
 *     DPA pieces.
 *
 *   - Untagged extents from distinct events: the spec is silent on
 *     aggregation.  Collapsing them into a single untagged dax device
 *     is the simplest conformant choice and is what the existing
 *     cxl_add_extent()/uuid_equal() logic implements for the null-UUID
 *     case.
 *
 * Enforced here, per tag group (in first-appearance order of the tag):
 *
 *     1. Extract the group to a local list, then stable-sort by
 *        shared_extn_seq.  For sharable extents this walks the group
 *        in device-stamped sequence order; for non-sharable extents
 *        every key is 0 and the stable sort preserves arrival order.
 *     2. Cross-More-chain uniqueness — if this (tagged) group's tag
 *        already maps to a committed dc_extent on its target
 *        cxlr_dax, the device has re-sent a completed allocation.
 *        Drop the whole group with a firmware-bug warning.  Skipped
 *        for the null UUID.
 *     3. Sequence-number integrity — either every member carries
 *        shared_extn_seq == 0 (non-sharable allocation) or the sorted
 *        group is exactly 1, 2, ..., n (sharable).  Mix, gap,
 *        duplicate, or a non-zero set that does not start at 1 is a
 *        firmware bug; drop the whole group.
 *     4. Partition equality — for tagged groups, every extent must
 *        resolve to the same DC partition.  CDAT describes a partition
 *        with a DSMAS entry carrying sharable / writable / coherency
 *        attributes; a single allocation cannot span differing CDAT
 *        attributes.  Skipped for the null UUID.
 *     5. Alignment gate — every extent's start_dpa and length must be
 *        CXL_DCD_EXTENT_ALIGN-aligned, else drop the whole group with
 *        a warning.  Partial acceptance would leave an unusable dax
 *        device.
 *     6. Validate + cxl_add_extent() each surviving extent into a fresh
 *        tag group built up in add_ctx.
 *     7. Online + notify the tag group, splice accepted extents into
 *        the response list, clear the add_ctx slot so the next tag's
 *        group can build its own.  online_tag_group() inserts each
 *        member dc_extent into cxlr_dax->dc_extents (an xarray keyed
 *        by an allocator-assigned ID, not by UUID), which is what
 *        allows multiple tagged allocations to surface as independent
 *        sysfs extents under one DAX region.
 */
static int cxl_add_pending(struct cxl_memdev_state *mds)
{
	struct device *dev = mds->cxlds.dev;
	struct list_head *pending = &mds->add_ctx.pending_extents;
	struct cxl_extent_list_node *pos, *tmp;
	LIST_HEAD(accepted);
	int total_accepted = 0;

	while (!list_empty(pending)) {
		LIST_HEAD(group);
		struct cxl_dc_tag_group *tag_group;
		bool aligned = true;
		int group_cnt = 0;
		uuid_t tag;
		int rc;

		/*
		 * (1) Extract this tag's extents from pending, then order
		 * them by shared_extn_seq.  The outer tag is picked by the
		 * first-appearance extent in pending; groups *within* a tag
		 * are ordered by the per-allocation sequence number, which
		 * is the invariant the spec defines.
		 */
		import_uuid(&tag,
			list_first_entry(pending,
					 struct cxl_extent_list_node,
					 list)->extent->uuid);
		extract_tag_group(pending, &tag, &group);
		list_sort(NULL, &group, extent_seq_compare);

		/*
		 * (2) Cross-More-chain uniqueness.  A non-null tag seen in
		 * this group must not already correspond to a committed
		 * tag group on its target cxlr_dax: More=0 was supposed to
		 * close that allocation.  Firmware bug — reject the whole
		 * group.  Any extent in the group maps to the same region
		 * (same tag == same allocation == same target), so checking
		 * the first suffices.
		 */
		pos = list_first_entry(&group, struct cxl_extent_list_node,
				       list);
		if (cxl_tag_already_committed(mds, pos->extent, &tag)) {
			dev_warn(dev,
				 "Tag %pUb: dropping group, tag already committed in a previous More-chain (firmware bug)\n",
				 &tag);
			list_for_each_entry_safe(pos, tmp, &group, list)
				delete_extent_node(pos);
			continue;
		}

		/*
		 * (3) Sequence-number integrity.  All-zero (non-sharable)
		 * or exact 1..n contiguous (sharable).  Anything else is a
		 * firmware bug — reject the whole group; no partial
		 * acceptance.
		 */
		if (cxl_check_group_seq(dev, &tag, &group)) {
			list_for_each_entry_safe(pos, tmp, &group, list)
				delete_extent_node(pos);
			continue;
		}

		/*
		 * (4) Partition equality — tagged allocations cannot span DC
		 * partitions, because a DC partition is the unit at which CDAT
		 * attributes (sharable, writable, coherency) are described.
		 * Skipped for the null UUID.
		 */
		if (cxl_check_group_partition(mds, &tag, &group)) {
			list_for_each_entry_safe(pos, tmp, &group, list)
				delete_extent_node(pos);
			continue;
		}

		/* (5) Alignment gate — abort the group if any member fails */
		list_for_each_entry(pos, &group, list) {
			if (!cxl_extent_dcd_aligned(pos->extent)) {
				dev_warn(dev,
					 "Tag %pUb: dropping group, extent DPA:%#llx LEN:%#llx not %u-aligned\n",
					 &tag,
					 le64_to_cpu(pos->extent->start_dpa),
					 le64_to_cpu(pos->extent->length),
					 CXL_DCD_EXTENT_ALIGN);
				aligned = false;
				break;
			}
		}
		if (!aligned) {
			list_for_each_entry_safe(pos, tmp, &group, list)
				delete_extent_node(pos);
			continue;
		}

		/*
		 * (5) Validate + attach in seq order.  Surviving nodes stay
		 * on @group in seq order; failed nodes are removed.
		 *
		 * Assemble-order index (@logical_seq) increments per iteration
		 * including failures, so the dc_extents handed to the dax
		 * layer carry contiguous 1..n in the success case and a gap
		 * (which the dax-side density check catches and refuses) when
		 * an extent is dropped here.  For sharable extents the device
		 * already stamped 1..n into shared_extn_seq and we use that
		 * directly; for non-sharable extents the device leaves seq=0
		 * and we use @logical_seq instead, giving the dax layer one
		 * uniform 1..n invariant to check.
		 */
		u16 logical_seq = 1;
		list_for_each_entry_safe(pos, tmp, &group, list) {
			u16 raw = le16_to_cpu(pos->extent->shared_extn_seq);
			u16 seq = raw ? raw : logical_seq;

			logical_seq++;

			if (cxl_validate_extent(mds, pos)) {
				delete_extent_node(pos);
				continue;
			}

			if (cxl_add_extent(mds, pos->extent, seq)) {
				dev_dbg(dev,
					"Tag %pUb: failed to add extent DPA:%#llx LEN:%#llx\n",
					&tag,
					le64_to_cpu(pos->extent->start_dpa),
					le64_to_cpu(pos->extent->length));
				delete_extent_node(pos);
				continue;
			}
			group_cnt++;
		}

		/* (6) online the tag group */
		tag_group = mds->add_ctx.group;
		if (!tag_group) {
			/* Every extent in the group was dropped */
			continue;
		}

		rc = cxl_region_invalidate_memregion(tag_group->cxlr_dax->cxlr);
		if (!rc)
			rc = online_tag_group(tag_group);
		if (rc) {
			dev_warn(dev,
				 "Tag %pUb: failed to online tag group (%d)\n",
				 &tag, rc);
			/*
			 * tag group was not onlined; the allocation failed.
			 * Drop its extents so we do not mis-report acceptance
			 * to the device.
			 */
			list_for_each_entry_safe(pos, tmp, &group, list)
				delete_extent_node(pos);
		} else {
			rc = cxlr_notify_extent(tag_group->cxlr_dax->cxlr,
						DCD_ADD_CAPACITY, tag_group);
			if (rc) {
				/*
				 * The dax-side notification failed; the tag
				 * group was torn down by rm_tag_group().  Drop
				 * the extents so we do not mis-report
				 * acceptance to the device.
				 */
				rm_tag_group(tag_group);
				list_for_each_entry_safe(pos, tmp, &group, list)
					delete_extent_node(pos);
			} else {
				/* Keep accepted extents for the response */
				list_splice_tail_init(&group, &accepted);
				total_accepted += group_cnt;
			}
		}

		/* Next tag's group gets a fresh add_ctx slot */
		mds->add_ctx.group = NULL;
	}

	/*
	 * Response payload: all accepted extents, grouped by tag (in the
	 * tag's first-appearance order), each group ordered by
	 * shared_extn_seq.  pending_extents is empty at this point since
	 * every tag group was extracted; splice the accepted list in so
	 * cxl_send_dc_response() can walk a single list.
	 */
	list_splice(&accepted, pending);
	return cxl_send_dc_response(mds, CXL_MBOX_OP_ADD_DC_RESPONSE,
				    pending, total_accepted);
}

static int add_to_pending_list(struct list_head *pending_list,
			       struct cxl_extent *to_add)
{
	struct cxl_extent_list_node *node;
	struct cxl_extent *extent;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return -ENOMEM;
	extent = kmemdup(to_add, sizeof(*extent), GFP_KERNEL);
	if (!extent)
		return -ENOMEM;

	node->extent = extent;
	list_add_tail(&node->list, pending_list);
	return 0;
}

static int handle_add_event(struct cxl_memdev_state *mds,
			    struct cxl_event_dcd *event)
{
	struct device *dev = mds->cxlds.dev;
	int rc;

	rc = add_to_pending_list(&mds->add_ctx.pending_extents, &event->extent);
	if (rc) {
		return rc;
	}

	if (event->flags & CXL_DCD_EVENT_MORE) {
		dev_dbg(dev, "more bit set; delay the surfacing of extent\n");
		return 0;
	}

	rc = cxl_add_pending(mds);
	clear_pending_extents(mds);
	return rc;
}

static char *cxl_dcd_evt_type_str(u8 type)
{
	switch (type) {
	case DCD_ADD_CAPACITY:
		return "add";
	case DCD_RELEASE_CAPACITY:
		return "release";
	case DCD_FORCED_CAPACITY_RELEASE:
		return "force release";
	default:
		break;
	}

	return "<unknown>";
}

static void cxl_handle_dcd_event_records(struct cxl_memdev_state *mds,
					struct cxl_event_record_raw *raw_rec)
{
	struct cxl_event_dcd *event = &raw_rec->event.dcd;
	struct cxl_extent *extent = &event->extent;
	struct device *dev = mds->cxlds.dev;
	uuid_t *id = &raw_rec->id;
	int rc;

	if (!uuid_equal(id, &CXL_EVENT_DC_EVENT_UUID))
		return;

	dev_dbg(dev, "DCD event %s : DPA:%#llx LEN:%#llx\n",
		cxl_dcd_evt_type_str(event->event_type),
		le64_to_cpu(extent->start_dpa), le64_to_cpu(extent->length));

	switch (event->event_type) {
	case DCD_ADD_CAPACITY:
		rc = handle_add_event(mds, event);
		break;
	case DCD_RELEASE_CAPACITY:
		rc = cxl_rm_extent(mds, &event->extent);
		break;
	case DCD_FORCED_CAPACITY_RELEASE:
		dev_err_ratelimited(dev, "Forced release event ignored.\n");
		rc = 0;
		break;
	default:
		rc = -EINVAL;
		break;
	}

	if (rc)
		dev_err_ratelimited(dev, "dcd event failed: %d\n", rc);
}

static void cxl_mem_get_records_log(struct cxl_memdev_state *mds,
				    enum cxl_event_log_type type)
{
	struct cxl_mailbox *cxl_mbox = &mds->cxlds.cxl_mbox;
	struct cxl_memdev *cxlmd = mds->cxlds.cxlmd;
	struct device *dev = mds->cxlds.dev;
	struct cxl_get_event_payload *payload;
	u8 log_type = type;
	u16 nr_rec;

	mutex_lock(&mds->event.log_lock);
	payload = mds->event.buf;

	do {
		int rc, i;
		struct cxl_mbox_cmd mbox_cmd = (struct cxl_mbox_cmd) {
			.opcode = CXL_MBOX_OP_GET_EVENT_RECORD,
			.payload_in = &log_type,
			.size_in = sizeof(log_type),
			.payload_out = payload,
			.size_out = cxl_mbox->payload_size,
			.min_out = struct_size(payload, records, 0),
		};

		rc = cxl_internal_send_cmd(cxl_mbox, &mbox_cmd);
		if (rc) {
			dev_err_ratelimited(dev,
				"Event log '%d': Failed to query event records : %d",
				type, rc);
			break;
		}

		nr_rec = le16_to_cpu(payload->record_count);
		if (!nr_rec)
			break;

		for (i = 0; i < nr_rec; i++) {
			__cxl_event_trace_record(cxlmd, type,
						 &payload->records[i]);
			if (type == CXL_EVENT_TYPE_DCD)
				cxl_handle_dcd_event_records(mds,
							&payload->records[i]);
		}

		if (payload->flags & CXL_GET_EVENT_FLAG_OVERFLOW)
			trace_cxl_overflow(cxlmd, type, payload);

		rc = cxl_clear_event_record(mds, type, payload);
		if (rc) {
			dev_err_ratelimited(dev,
				"Event log '%d': Failed to clear events : %d",
				type, rc);
			break;
		}
	} while (nr_rec);

	mutex_unlock(&mds->event.log_lock);
}

/**
 * cxl_mem_get_event_records - Get Event Records from the device
 * @mds: The driver data for the operation
 * @status: Event Status register value identifying which events are available.
 *
 * Retrieve all event records available on the device, report them as trace
 * events, and clear them.
 *
 * See CXL rev 3.0 @8.2.9.2.2 Get Event Records
 * See CXL rev 3.0 @8.2.9.2.3 Clear Event Records
 */
void cxl_mem_get_event_records(struct cxl_memdev_state *mds, u32 status)
{
	dev_dbg(mds->cxlds.dev, "Reading event logs: %x\n", status);

	if (cxl_dcd_supported(mds) && (status & CXLDEV_EVENT_STATUS_DCD))
		cxl_mem_get_records_log(mds, CXL_EVENT_TYPE_DCD);
	if (status & CXLDEV_EVENT_STATUS_FATAL)
		cxl_mem_get_records_log(mds, CXL_EVENT_TYPE_FATAL);
	if (status & CXLDEV_EVENT_STATUS_FAIL)
		cxl_mem_get_records_log(mds, CXL_EVENT_TYPE_FAIL);
	if (status & CXLDEV_EVENT_STATUS_WARN)
		cxl_mem_get_records_log(mds, CXL_EVENT_TYPE_WARN);
	if (status & CXLDEV_EVENT_STATUS_INFO)
		cxl_mem_get_records_log(mds, CXL_EVENT_TYPE_INFO);
}
EXPORT_SYMBOL_NS_GPL(cxl_mem_get_event_records, "CXL");

/**
 * cxl_mem_get_partition_info - Get partition info
 * @mds: The driver data for the operation
 *
 * Retrieve the current partition info for the device specified.  The active
 * values are the current capacity in bytes.  If not 0, the 'next' values are
 * the pending values, in bytes, which take affect on next cold reset.
 *
 * Return: 0 if no error: or the result of the mailbox command.
 *
 * See CXL @8.2.9.5.2.1 Get Partition Info
 */
static int cxl_mem_get_partition_info(struct cxl_memdev_state *mds)
{
	struct cxl_mailbox *cxl_mbox = &mds->cxlds.cxl_mbox;
	struct cxl_mbox_get_partition_info pi;
	struct cxl_mbox_cmd mbox_cmd;
	int rc;

	mbox_cmd = (struct cxl_mbox_cmd) {
		.opcode = CXL_MBOX_OP_GET_PARTITION_INFO,
		.size_out = sizeof(pi),
		.payload_out = &pi,
	};
	rc = cxl_internal_send_cmd(cxl_mbox, &mbox_cmd);
	if (rc)
		return rc;

	mds->active_volatile_bytes =
		le64_to_cpu(pi.active_volatile_cap) * CXL_CAPACITY_MULTIPLIER;
	mds->active_persistent_bytes =
		le64_to_cpu(pi.active_persistent_cap) * CXL_CAPACITY_MULTIPLIER;

	return 0;
}

/**
 * cxl_dev_state_identify() - Send the IDENTIFY command to the device.
 * @mds: The driver data for the operation
 *
 * Return: 0 if identify was executed successfully or media not ready.
 *
 * This will dispatch the identify command to the device and on success populate
 * structures to be exported to sysfs.
 */
int cxl_dev_state_identify(struct cxl_memdev_state *mds)
{
	struct cxl_mailbox *cxl_mbox = &mds->cxlds.cxl_mbox;
	/* See CXL 2.0 Table 175 Identify Memory Device Output Payload */
	struct cxl_mbox_identify id;
	struct cxl_mbox_cmd mbox_cmd;
	u32 val;
	int rc;

	if (!mds->cxlds.media_ready)
		return 0;

	mbox_cmd = (struct cxl_mbox_cmd) {
		.opcode = CXL_MBOX_OP_IDENTIFY,
		.size_out = sizeof(id),
		.payload_out = &id,
	};
	rc = cxl_internal_send_cmd(cxl_mbox, &mbox_cmd);
	if (rc < 0)
		return rc;

	mds->total_bytes =
		le64_to_cpu(id.total_capacity) * CXL_CAPACITY_MULTIPLIER;
	mds->volatile_only_bytes =
		le64_to_cpu(id.volatile_capacity) * CXL_CAPACITY_MULTIPLIER;
	mds->persistent_only_bytes =
		le64_to_cpu(id.persistent_capacity) * CXL_CAPACITY_MULTIPLIER;
	mds->partition_align_bytes =
		le64_to_cpu(id.partition_align) * CXL_CAPACITY_MULTIPLIER;

	mds->lsa_size = le32_to_cpu(id.lsa_size);
	memcpy(mds->firmware_version, id.fw_revision,
	       sizeof(id.fw_revision));

	if (test_bit(CXL_POISON_ENABLED_LIST, mds->poison.enabled_cmds)) {
		val = get_unaligned_le24(id.poison_list_max_mer);
		mds->poison.max_errors = min_t(u32, val, CXL_POISON_LIST_MAX);
	}

	return 0;
}
EXPORT_SYMBOL_NS_GPL(cxl_dev_state_identify, "CXL");

static int __cxl_mem_sanitize(struct cxl_memdev_state *mds, u16 cmd)
{
	struct cxl_mailbox *cxl_mbox = &mds->cxlds.cxl_mbox;
	int rc;
	u32 sec_out = 0;
	struct cxl_get_security_output {
		__le32 flags;
	} out;
	struct cxl_mbox_cmd sec_cmd = {
		.opcode = CXL_MBOX_OP_GET_SECURITY_STATE,
		.payload_out = &out,
		.size_out = sizeof(out),
	};
	struct cxl_mbox_cmd mbox_cmd = { .opcode = cmd };

	if (cmd != CXL_MBOX_OP_SANITIZE && cmd != CXL_MBOX_OP_SECURE_ERASE)
		return -EINVAL;

	rc = cxl_internal_send_cmd(cxl_mbox, &sec_cmd);
	if (rc < 0) {
		dev_err(cxl_mbox->host, "Failed to get security state : %d", rc);
		return rc;
	}

	/*
	 * Prior to using these commands, any security applied to
	 * the user data areas of the device shall be DISABLED (or
	 * UNLOCKED for secure erase case).
	 */
	sec_out = le32_to_cpu(out.flags);
	if (sec_out & CXL_PMEM_SEC_STATE_USER_PASS_SET)
		return -EINVAL;

	if (cmd == CXL_MBOX_OP_SECURE_ERASE &&
	    sec_out & CXL_PMEM_SEC_STATE_LOCKED)
		return -EINVAL;

	rc = cxl_internal_send_cmd(cxl_mbox, &mbox_cmd);
	if (rc < 0) {
		dev_err(cxl_mbox->host, "Failed to sanitize device : %d", rc);
		return rc;
	}

	return 0;
}


/**
 * cxl_mem_sanitize() - Send a sanitization command to the device.
 * @cxlmd: The device for the operation
 * @cmd: The specific sanitization command opcode
 *
 * Return: 0 if the command was executed successfully, regardless of
 * whether or not the actual security operation is done in the background,
 * such as for the Sanitize case.
 * Error return values can be the result of the mailbox command, -EINVAL
 * when security requirements are not met or invalid contexts, or -EBUSY
 * if the sanitize operation is already in flight.
 *
 * See CXL 3.0 @8.2.9.8.5.1 Sanitize and @8.2.9.8.5.2 Secure Erase.
 */
int cxl_mem_sanitize(struct cxl_memdev *cxlmd, u16 cmd)
{
	struct cxl_memdev_state *mds = to_cxl_memdev_state(cxlmd->cxlds);
	struct cxl_port  *endpoint;

	/* synchronize with cxl_mem_probe() and decoder write operations */
	guard(device)(&cxlmd->dev);
	endpoint = cxlmd->endpoint;
	guard(rwsem_read)(&cxl_rwsem.region);
	/*
	 * Require an endpoint to be safe otherwise the driver can not
	 * be sure that the device is unmapped.
	 */
	if (endpoint && cxl_num_decoders_committed(endpoint) == 0)
		return __cxl_mem_sanitize(mds, cmd);

	return -EBUSY;
}

static int cxl_dc_check(struct device *dev, struct cxl_dc_partition_info *part_array,
			u8 index, struct cxl_dc_partition *dev_part)
{
	size_t blk_size = le64_to_cpu(dev_part->block_size);
	size_t len = le64_to_cpu(dev_part->length);
	u32 handle = le32_to_cpu(dev_part->dsmad_handle);

	part_array[index].start = le64_to_cpu(dev_part->base);
	part_array[index].size = le64_to_cpu(dev_part->decode_length);
	part_array[index].size *= CXL_CAPACITY_MULTIPLIER;
	if (handle & ~0xFF) {
		dev_warn(dev, "DSMAD handle 0x%x has non-zero reserved bits\n", handle);
		return -EINVAL;
	}
	part_array[index].handle = handle;

	/* Check partitions are in increasing DPA order */
	if (index > 0) {
		struct cxl_dc_partition_info *prev_part = &part_array[index - 1];

		if ((prev_part->start + prev_part->size) >
		     part_array[index].start) {
			dev_err(dev,
				"DPA ordering violation for DC partition %d and %d\n",
				index - 1, index);
			return -EINVAL;
		}
	}

	if (!IS_ALIGNED(part_array[index].start, SZ_256M) ||
	    !IS_ALIGNED(part_array[index].start, blk_size)) {
		dev_err(dev, "DC partition %d invalid start %zu blk size %zu\n",
			index, part_array[index].start, blk_size);
		return -EINVAL;
	}

	if (part_array[index].size == 0 || len == 0 ||
	    part_array[index].size < len || !IS_ALIGNED(len, blk_size)) {
		dev_err(dev, "DC partition %d invalid length; size %zu len %zu blk size %zu\n",
			index, part_array[index].size, len, blk_size);
		return -EINVAL;
	}

	if (blk_size == 0 || blk_size % CXL_DCD_BLOCK_LINE_SIZE ||
	    !is_power_of_2(blk_size)) {
		dev_err(dev, "DC partition %d invalid block size; %zu\n",
			index, blk_size);
		return -EINVAL;
	}

	dev_dbg(dev, "DC partition %d start %zu start %zu size %zu\n",
		index, part_array[index].start, part_array[index].size,
		blk_size);

	return 0;
}

/* Returns the number of partitions in dc_resp or -ERRNO */
static int cxl_get_dc_config(struct cxl_mailbox *mbox, u8 start_partition,
			     struct cxl_mbox_get_dc_config_out *dc_resp,
			     size_t dc_resp_size)
{
	struct cxl_mbox_get_dc_config_in get_dc = (struct cxl_mbox_get_dc_config_in) {
		.partition_count = CXL_MAX_DC_PARTITIONS,
		.start_partition_index = start_partition,
	};
	struct cxl_mbox_cmd mbox_cmd = (struct cxl_mbox_cmd) {
		.opcode = CXL_MBOX_OP_GET_DC_CONFIG,
		.payload_in = &get_dc,
		.size_in = sizeof(get_dc),
		.size_out = dc_resp_size,
		.payload_out = dc_resp,
		.min_out = 8,
	};
	int rc;

	rc = cxl_internal_send_cmd(mbox, &mbox_cmd);
	if (rc < 0)
		return rc;

	dev_dbg(mbox->host, "Read %d/%d DC partitions\n",
		dc_resp->partitions_returned, dc_resp->avail_partition_count);
	return dc_resp->partitions_returned;
}

/**
 * cxl_dev_dc_identify() - Reads the dynamic capacity information from the
 *                         device.
 * @mbox: Mailbox to query
 * @dc_info: The dynamic partition information to return
 *
 * Read Dynamic Capacity information from the device and return the partition
 * information.
 *
 * Return: 0 if identify was executed successfully, -ERRNO on error.
 *         on error only dynamic_bytes is left unchanged.
 */
int cxl_dev_dc_identify(struct cxl_mailbox *mbox,
			struct cxl_dc_partition_info *dc_info)
{
	struct cxl_dc_partition_info partitions[CXL_MAX_DC_PARTITIONS];
	struct device *dev = mbox->host;
	size_t dc_resp_size =
		sizeof(struct cxl_mbox_get_dc_config_out) + sizeof(partitions);
	u8 start_partition;
	u8 num_partitions;

	struct cxl_mbox_get_dc_config_out *dc_resp __free(kfree) =
					kmalloc(dc_resp_size, GFP_KERNEL);
	if (!dc_resp)
		return -ENOMEM;

	/**
	 * Read and check all partition information for validity and potential
	 * debugging; see debug output in cxl_dc_check()
	 */
	start_partition = 0;
	num_partitions = 0;
	do {
		int rc, i, j;

		rc = cxl_get_dc_config(mbox, start_partition, dc_resp, dc_resp_size);
		if (rc < 0) {
			dev_err(dev, "Failed to get DC config: %d\n", rc);
			return rc;
		}

		num_partitions += rc;

		if (num_partitions < 1 || num_partitions > CXL_MAX_DC_PARTITIONS) {
			dev_err(dev, "Invalid num of dynamic capacity partitions %d\n",
				num_partitions);
			return -EINVAL;
		}

		for (i = start_partition, j = 0; i < num_partitions; i++, j++) {
			rc = cxl_dc_check(dev, partitions, i,
					  &dc_resp->partition[j]);
			if (rc)
				return rc;
		}

		start_partition = num_partitions;

	} while (num_partitions < dc_resp->avail_partition_count);

	/* Return 1st partition */
	dc_info->start = partitions[0].start;
	dc_info->size = partitions[0].size;
	dc_info->handle = partitions[0].handle;
	dev_dbg(dev, "Returning partition 0 %zu size %zu\n",
		dc_info->start, dc_info->size);

	return 0;
}
EXPORT_SYMBOL_NS_GPL(cxl_dev_dc_identify, "CXL");

/* Return -EAGAIN if the extent list changes while reading */
static int __cxl_process_extent_list(struct cxl_endpoint_decoder *cxled)
{
	u32 current_index, total_read, total_expected, initial_gen_num;
	struct cxl_memdev_state *mds = cxled_to_mds(cxled);
	struct cxl_mailbox *cxl_mbox = &mds->cxlds.cxl_mbox;
	struct device *dev = mds->cxlds.dev;
	struct cxl_mbox_cmd mbox_cmd;
	u32 max_extent_count;
	int latched_rc = 0;
	bool first = true;

	struct cxl_mbox_get_extent_out *extents __free(kvfree) =
				kvmalloc(cxl_mbox->payload_size, GFP_KERNEL);
	if (!extents)
		return -ENOMEM;

	total_read = 0;
	current_index = 0;
	total_expected = 0;
	max_extent_count = (cxl_mbox->payload_size - sizeof(*extents)) /
				sizeof(struct cxl_extent);
	do {
		u32 nr_returned, current_total, current_gen_num;
		struct cxl_mbox_get_extent_in get_extent;
		int rc;

		get_extent = (struct cxl_mbox_get_extent_in) {
			.extent_cnt = cpu_to_le32(max(max_extent_count,
						  total_expected - current_index)),
			.start_extent_index = cpu_to_le32(current_index),
		};

		mbox_cmd = (struct cxl_mbox_cmd) {
			.opcode = CXL_MBOX_OP_GET_DC_EXTENT_LIST,
			.payload_in = &get_extent,
			.size_in = sizeof(get_extent),
			.size_out = cxl_mbox->payload_size,
			.payload_out = extents,
			.min_out = 1,
		};

		rc = cxl_internal_send_cmd(cxl_mbox, &mbox_cmd);
		if (rc < 0)
			return rc;

		/* Save initial data */
		if (first) {
			total_expected = le32_to_cpu(extents->total_extent_count);
			initial_gen_num = le32_to_cpu(extents->generation_num);
			first = false;
		}

		nr_returned = le32_to_cpu(extents->returned_extent_count);
		total_read += nr_returned;
		current_total = le32_to_cpu(extents->total_extent_count);
		current_gen_num = le32_to_cpu(extents->generation_num);

		dev_dbg(dev, "Got extent list %d-%d of %d generation Num:%d\n",
			current_index, total_read - 1, current_total, current_gen_num);

		if (current_gen_num != initial_gen_num || total_expected != current_total) {
			dev_warn(dev, "Extent list change detected; gen %u != %u : cnt %u != %u\n",
				 current_gen_num, initial_gen_num,
				 total_expected, current_total);
			return -EAGAIN;
		}

		for (int i = 0; i < nr_returned ; i++) {
			struct cxl_extent *extent = &extents->extent[i];

			dev_dbg(dev, "Processing extent %d/%d\n",
				current_index + i, total_expected);

			rc = add_to_pending_list(&mds->add_ctx.pending_extents,
						 extent);
			if (rc) {
				latched_rc = rc;
			}
		}

		current_index += nr_returned;
	} while (total_expected > total_read);

	if (!latched_rc && !list_empty(&mds->add_ctx.pending_extents)) {
		latched_rc = cxl_add_pending(mds);
	}
	clear_pending_extents(mds);

	return latched_rc;
}

#define CXL_READ_EXTENT_LIST_RETRY 10

/**
 * cxl_process_extent_list() - Read existing extents
 * @cxled: Endpoint decoder which is part of a region
 *
 * Issue the Get Dynamic Capacity Extent List command to the device
 * and add existing extents if found.
 *
 * A retry of 10 is somewhat arbitrary, however, extent changes should be
 * relatively rare while bringing up a region.  So 10 should be plenty.
 */
int cxl_process_extent_list(struct cxl_endpoint_decoder *cxled)
{
	int retry = CXL_READ_EXTENT_LIST_RETRY;
	int rc;

	do {
		rc = __cxl_process_extent_list(cxled);
	} while (rc == -EAGAIN && retry--);

	return rc;
}

static void add_part(struct cxl_dpa_info *info, u64 start, u64 size, enum cxl_partition_mode mode)
{
	int i = info->nr_partitions;

	if (size == 0)
		return;

	info->part[i].range = (struct range) {
		.start = start,
		.end = start + size - 1,
	};
	info->part[i].mode = mode;
	info->nr_partitions++;
}

int cxl_mem_dpa_fetch(struct cxl_memdev_state *mds, struct cxl_dpa_info *info)
{
	struct cxl_dev_state *cxlds = &mds->cxlds;
	struct device *dev = cxlds->dev;
	int rc;

	if (!cxlds->media_ready) {
		info->size = 0;
		return 0;
	}

	info->size = mds->total_bytes;

	if (mds->partition_align_bytes == 0) {
		add_part(info, 0, mds->volatile_only_bytes, CXL_PARTMODE_RAM);
		add_part(info, mds->volatile_only_bytes,
			 mds->persistent_only_bytes, CXL_PARTMODE_PMEM);
		return 0;
	}

	rc = cxl_mem_get_partition_info(mds);
	if (rc) {
		dev_err(dev, "Failed to query partition information\n");
		return rc;
	}

	add_part(info, 0, mds->active_volatile_bytes, CXL_PARTMODE_RAM);
	add_part(info, mds->active_volatile_bytes, mds->active_persistent_bytes,
		 CXL_PARTMODE_PMEM);

	return 0;
}
EXPORT_SYMBOL_NS_GPL(cxl_mem_dpa_fetch, "CXL");

int cxl_get_dirty_count(struct cxl_memdev_state *mds, u32 *count)
{
	struct cxl_mailbox *cxl_mbox = &mds->cxlds.cxl_mbox;
	struct cxl_mbox_get_health_info_out hi;
	struct cxl_mbox_cmd mbox_cmd;
	int rc;

	mbox_cmd = (struct cxl_mbox_cmd) {
		.opcode = CXL_MBOX_OP_GET_HEALTH_INFO,
		.size_out = sizeof(hi),
		.payload_out = &hi,
	};

	rc = cxl_internal_send_cmd(cxl_mbox, &mbox_cmd);
	if (!rc)
		*count = le32_to_cpu(hi.dirty_shutdown_cnt);

	return rc;
}
EXPORT_SYMBOL_NS_GPL(cxl_get_dirty_count, "CXL");

void cxl_configure_dcd(struct cxl_memdev_state *mds, struct cxl_dpa_info *info)
{
	struct cxl_dc_partition_info dc_info = { 0 };
	struct device *dev = mds->cxlds.dev;
	size_t skip;
	int rc;

	rc = cxl_dev_dc_identify(&mds->cxlds.cxl_mbox, &dc_info);
	if (rc) {
		dev_warn(dev,
			 "Failed to read Dynamic Capacity config: %d\n", rc);
		cxl_disable_dcd(mds);
		return;
	}

	/* Skips between pmem and the dynamic partition are not supported */
	skip = dc_info.start - info->size;
	if (skip) {
		dev_warn(dev,
			 "Dynamic Capacity skip from pmem not supported: %zu\n",
			 skip);
		cxl_disable_dcd(mds);
		return;
	}

	info->size += dc_info.size;
	dev_dbg(dev, "Adding dynamic ram partition A; %zu size %zu\n",
		dc_info.start, dc_info.size);
	add_part(info, dc_info.start, dc_info.size, CXL_PARTMODE_DYNAMIC_RAM_A);
}
EXPORT_SYMBOL_NS_GPL(cxl_configure_dcd, "CXL");

int cxl_arm_dirty_shutdown(struct cxl_memdev_state *mds)
{
	struct cxl_mailbox *cxl_mbox = &mds->cxlds.cxl_mbox;
	struct cxl_mbox_cmd mbox_cmd;
	struct cxl_mbox_set_shutdown_state_in in = {
		.state = 1
	};

	mbox_cmd = (struct cxl_mbox_cmd) {
		.opcode = CXL_MBOX_OP_SET_SHUTDOWN_STATE,
		.size_in = sizeof(in),
		.payload_in = &in,
	};

	return cxl_internal_send_cmd(cxl_mbox, &mbox_cmd);
}
EXPORT_SYMBOL_NS_GPL(cxl_arm_dirty_shutdown, "CXL");

int cxl_set_timestamp(struct cxl_memdev_state *mds)
{
	struct cxl_mailbox *cxl_mbox = &mds->cxlds.cxl_mbox;
	struct cxl_mbox_cmd mbox_cmd;
	struct cxl_mbox_set_timestamp_in pi;
	int rc;

	pi.timestamp = cpu_to_le64(ktime_get_real_ns());
	mbox_cmd = (struct cxl_mbox_cmd) {
		.opcode = CXL_MBOX_OP_SET_TIMESTAMP,
		.size_in = sizeof(pi),
		.payload_in = &pi,
	};

	rc = cxl_internal_send_cmd(cxl_mbox, &mbox_cmd);
	/*
	 * Command is optional. Devices may have another way of providing
	 * a timestamp, or may return all 0s in timestamp fields.
	 * Don't report an error if this command isn't supported
	 */
	if (rc && (mbox_cmd.return_code != CXL_MBOX_CMD_RC_UNSUPPORTED))
		return rc;

	return 0;
}
EXPORT_SYMBOL_NS_GPL(cxl_set_timestamp, "CXL");

int cxl_mem_get_poison(struct cxl_memdev *cxlmd, u64 offset, u64 len,
		       struct cxl_region *cxlr)
{
	struct cxl_memdev_state *mds = to_cxl_memdev_state(cxlmd->cxlds);
	struct cxl_mailbox *cxl_mbox = &cxlmd->cxlds->cxl_mbox;
	struct cxl_mbox_poison_out *po;
	struct cxl_mbox_poison_in pi;
	int nr_records = 0;
	int rc;

	ACQUIRE(mutex_intr, lock)(&mds->poison.mutex);
	if ((rc = ACQUIRE_ERR(mutex_intr, &lock)))
		return rc;

	po = mds->poison.list_out;
	pi.offset = cpu_to_le64(offset);
	pi.length = cpu_to_le64(len / CXL_POISON_LEN_MULT);

	do {
		struct cxl_mbox_cmd mbox_cmd = (struct cxl_mbox_cmd){
			.opcode = CXL_MBOX_OP_GET_POISON,
			.size_in = sizeof(pi),
			.payload_in = &pi,
			.size_out = cxl_mbox->payload_size,
			.payload_out = po,
			.min_out = struct_size(po, record, 0),
		};

		rc = cxl_internal_send_cmd(cxl_mbox, &mbox_cmd);
		if (rc)
			break;

		for (int i = 0; i < le16_to_cpu(po->count); i++)
			trace_cxl_poison(cxlmd, cxlr, &po->record[i],
					 po->flags, po->overflow_ts,
					 CXL_POISON_TRACE_LIST);

		/* Protect against an uncleared _FLAG_MORE */
		nr_records = nr_records + le16_to_cpu(po->count);
		if (nr_records >= mds->poison.max_errors) {
			dev_dbg(&cxlmd->dev, "Max Error Records reached: %d\n",
				nr_records);
			break;
		}
	} while (po->flags & CXL_POISON_FLAG_MORE);

	return rc;
}
EXPORT_SYMBOL_NS_GPL(cxl_mem_get_poison, "CXL");

static void free_poison_buf(void *buf)
{
	kvfree(buf);
}

/* Get Poison List output buffer is protected by mds->poison.lock */
static int cxl_poison_alloc_buf(struct cxl_memdev_state *mds)
{
	struct cxl_mailbox *cxl_mbox = &mds->cxlds.cxl_mbox;

	mds->poison.list_out = kvmalloc(cxl_mbox->payload_size, GFP_KERNEL);
	if (!mds->poison.list_out)
		return -ENOMEM;

	return devm_add_action_or_reset(mds->cxlds.dev, free_poison_buf,
					mds->poison.list_out);
}

int cxl_poison_state_init(struct cxl_memdev_state *mds)
{
	int rc;

	if (!test_bit(CXL_POISON_ENABLED_LIST, mds->poison.enabled_cmds))
		return 0;

	rc = cxl_poison_alloc_buf(mds);
	if (rc) {
		clear_bit(CXL_POISON_ENABLED_LIST, mds->poison.enabled_cmds);
		return rc;
	}

	mutex_init(&mds->poison.mutex);
	return 0;
}
EXPORT_SYMBOL_NS_GPL(cxl_poison_state_init, "CXL");

int cxl_mailbox_init(struct cxl_mailbox *cxl_mbox, struct device *host)
{
	if (!cxl_mbox || !host)
		return -EINVAL;

	cxl_mbox->host = host;
	mutex_init(&cxl_mbox->mbox_mutex);
	rcuwait_init(&cxl_mbox->mbox_wait);

	return 0;
}
EXPORT_SYMBOL_NS_GPL(cxl_mailbox_init, "CXL");

struct cxl_memdev_state *cxl_memdev_state_create(struct device *dev)
{
	struct cxl_memdev_state *mds;
	int rc;

	mds = devm_kzalloc(dev, sizeof(*mds), GFP_KERNEL);
	if (!mds) {
		dev_err(dev, "No memory available\n");
		return ERR_PTR(-ENOMEM);
	}

	mutex_init(&mds->event.log_lock);
	mds->cxlds.dev = dev;
	mds->cxlds.reg_map.host = dev;
	mds->cxlds.cxl_mbox.host = dev;
	mds->cxlds.reg_map.resource = CXL_RESOURCE_NONE;
	mds->cxlds.type = CXL_DEVTYPE_CLASSMEM;
	INIT_LIST_HEAD(&mds->add_ctx.pending_extents);

	rc = devm_add_action_or_reset(dev, clear_pending_extents, mds);
	if (rc)
		return ERR_PTR(rc);

	rc = devm_cxl_register_mce_notifier(dev, &mds->mce_notifier);
	if (rc == -EOPNOTSUPP)
		dev_warn(dev, "CXL MCE unsupported\n");
	else if (rc)
		return ERR_PTR(rc);

	return mds;
}
EXPORT_SYMBOL_NS_GPL(cxl_memdev_state_create, "CXL");

void __init cxl_mbox_init(void)
{
	struct dentry *mbox_debugfs;

	mbox_debugfs = cxl_debugfs_create_dir("mbox");
	debugfs_create_bool("raw_allow_all", 0600, mbox_debugfs,
			    &cxl_raw_allow_all);
}

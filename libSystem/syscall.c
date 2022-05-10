#include "../mach/vm_map.h"
#include "../mach/mach_port.h"
#include <mach/mach.h>
#include <mach/mach_traps.h>

extern kern_return_t _kernelrpc_mach_vm_allocate_trap(
	mach_port_name_t target,
	mach_vm_offset_t *addr,
	mach_vm_size_t size,
	int flags);

extern kern_return_t _kernelrpc_mach_vm_deallocate_trap(
	mach_port_name_t target,
	mach_vm_address_t address,
	mach_vm_size_t size
	);

extern kern_return_t _kernelrpc_mach_vm_protect_trap(
	mach_port_name_t target,
	mach_vm_address_t address,
	mach_vm_size_t size,
	boolean_t set_maximum,
	vm_prot_t new_protection
	);

extern kern_return_t _kernelrpc_mach_vm_map_trap(
	mach_port_name_t target,
	mach_vm_offset_t *address,
	mach_vm_size_t size,
	mach_vm_offset_t mask,
	int flags,
	vm_prot_t cur_protection
	);

extern kern_return_t _kernelrpc_mach_vm_allocate(
	vm_map_t target,
	mach_vm_address_t *address,
	mach_vm_size_t size,
	int flags
);

extern kern_return_t _kernelrpc_mach_vm_deallocate(
	vm_map_t target,
	mach_vm_address_t address,
	mach_vm_size_t size
);

extern kern_return_t _kernelrpc_mach_vm_protect(
	vm_map_t target_task,
	mach_vm_address_t address,
	mach_vm_size_t size,
	boolean_t set_maximum,
	vm_prot_t new_protection
);

extern kern_return_t _kernelrpc_mach_vm_read(
	vm_map_read_t target_task,
	mach_vm_address_t address,
	mach_vm_size_t size,
	vm_offset_t *data,
	mach_msg_type_number_t *dataCnt
);

extern kern_return_t _kernelrpc_mach_vm_map(
	vm_map_t target_task,
	mach_vm_address_t *address,
	mach_vm_size_t size,
	mach_vm_offset_t mask,
	int flags,
	mem_entry_name_port_t object,
	memory_object_offset_t offset,
	boolean_t copy,
	vm_prot_t cur_protection,
	vm_prot_t max_protection,
	vm_inherit_t inheritance
);

extern kern_return_t _kernelrpc_mach_vm_remap(
	vm_map_t target_task,
	mach_vm_address_t *target_address,
	mach_vm_size_t size,
	mach_vm_offset_t mask,
	int flags,
	vm_map_t src_task,
	mach_vm_address_t src_address,
	boolean_t copy,
	vm_prot_t *cur_protection,
	vm_prot_t *max_protection,
	vm_inherit_t inheritance
);

extern kern_return_t _kernelrpc_mach_vm_purgable_control(
	vm_map_t target_task,
	mach_vm_address_t address,
	vm_purgable_t control,
	int *state
);

extern kern_return_t _kernelrpc_mach_vm_purgable_control_trap(
	mach_port_name_t target,
	mach_vm_offset_t address,
	vm_purgable_t control,
	int *state);

extern kern_return_t _kernelrpc_mach_port_allocate_trap(
	mach_port_name_t target,
	mach_port_right_t right,
	mach_port_name_t *name
	);

extern kern_return_t _kernelrpc_mach_port_deallocate_trap(
	mach_port_name_t target,
	mach_port_name_t name
	);

extern kern_return_t _kernelrpc_mach_port_mod_refs_trap(
	mach_port_name_t target,
	mach_port_name_t name,
	mach_port_right_t right,
	mach_port_delta_t delta
	);

extern kern_return_t _kernelrpc_mach_port_move_member_trap(
	mach_port_name_t target,
	mach_port_name_t member,
	mach_port_name_t after
	);

extern kern_return_t _kernelrpc_mach_port_insert_right_trap(
	mach_port_name_t target,
	mach_port_name_t name,
	mach_port_name_t poly,
	mach_msg_type_name_t polyPoly
	);

extern kern_return_t _kernelrpc_mach_port_get_attributes_trap(
	mach_port_name_t target,
	mach_port_name_t name,
	mach_port_flavor_t flavor,
	mach_port_info_t port_info_out,
	mach_msg_type_number_t *port_info_outCnt
	);

extern kern_return_t _kernelrpc_mach_port_insert_member_trap(
	mach_port_name_t target,
	mach_port_name_t name,
	mach_port_name_t pset
	);

extern kern_return_t _kernelrpc_mach_port_extract_member_trap(
	mach_port_name_t target,
	mach_port_name_t name,
	mach_port_name_t pset
	);

extern kern_return_t _kernelrpc_mach_port_construct_trap(
	mach_port_name_t target,
	mach_port_options_t *options,
	uint64_t context,
	mach_port_name_t *name
	);

extern kern_return_t _kernelrpc_mach_port_destruct_trap(
	mach_port_name_t target,
	mach_port_name_t name,
	mach_port_delta_t srdelta,
	uint64_t guard
	);

extern kern_return_t _kernelrpc_mach_port_guard_trap(
	mach_port_name_t target,
	mach_port_name_t name,
	uint64_t guard,
	boolean_t strict
	);

extern kern_return_t _kernelrpc_mach_port_unguard_trap(
	mach_port_name_t target,
	mach_port_name_t name,
	uint64_t guard
	);

extern kern_return_t mach_vm_allocate(
	mach_port_name_t target,
	mach_vm_address_t *address,
	mach_vm_size_t size,
	int flags);

extern kern_return_t mach_vm_protect(
	mach_port_name_t task,
	mach_vm_address_t address,
	mach_vm_size_t size,
	boolean_t set_maximum,
	vm_prot_t new_protection);

extern kern_return_t mach_vm_deallocate(
	mach_port_name_t target,
	mach_vm_address_t address,
	mach_vm_size_t size);

extern kern_return_t mach_generate_activity_id(
	mach_port_name_t target,
	int count,
	uint64_t *activity_id
	);

extern kern_return_t macx_swapon(
	uint64_t filename,
	int flags,
	int size,
	int priority);

extern kern_return_t macx_swapoff(
	uint64_t filename,
	int flags);

extern kern_return_t macx_triggers(
	int hi_water,
	int low_water,
	int flags,
	mach_port_t alert_port);

extern kern_return_t macx_backing_store_suspend(
	boolean_t suspend);

extern kern_return_t macx_backing_store_recovery(
	int pid);

extern boolean_t swtch_pri(int pri);

extern boolean_t swtch(void);

extern kern_return_t thread_switch(
	mach_port_name_t thread_name,
	int option,
	mach_msg_timeout_t option_time);

extern mach_port_name_t task_self_trap(void);

extern kern_return_t host_create_mach_voucher_trap(
	mach_port_name_t host,
	mach_voucher_attr_raw_recipe_array_t recipes,
	int recipes_size,
	mach_port_name_t *voucher);

extern kern_return_t mach_voucher_extract_attr_recipe_trap(
	mach_port_name_t voucher_name,
	mach_voucher_attr_key_t key,
	mach_voucher_attr_raw_recipe_t recipe,
	mach_msg_type_number_t *recipe_size);

extern kern_return_t _kernelrpc_mach_port_type_trap(
	ipc_space_t task,
	mach_port_name_t name,
	mach_port_type_t *ptype);

extern kern_return_t _kernelrpc_mach_port_request_notification_trap(
	ipc_space_t task,
	mach_port_name_t name,
	mach_msg_id_t msgid,
	mach_port_mscount_t sync,
	mach_port_name_t notify,
	mach_msg_type_name_t notifyPoly,
	mach_port_name_t *previous);

kern_return_t
mach_vm_allocate(
	mach_port_name_t target,
	mach_vm_address_t *address,
	mach_vm_size_t size,
	int flags)
{
	kern_return_t rv;

	rv = _kernelrpc_mach_vm_allocate_trap(target, address, size, flags);

	if (rv == MACH_SEND_INVALID_DEST) {
		rv = _kernelrpc_mach_vm_allocate(target, address, size, flags);
	}

	//int userTagFlags = flags & VM_FLAGS_ALIAS_MASK;
	/*if (__syscall_logger && rv == KERN_SUCCESS && (userTagFlags != VM_MAKE_TAG(VM_MEMORY_STACK))) {
		__syscall_logger(stack_logging_type_vm_allocate | userTagFlags, (uintptr_t)target, (uintptr_t)size, 0, (uintptr_t)*address, 0);
	}*/

	return rv;
}

kern_return_t
mach_vm_deallocate(
	mach_port_name_t target,
	mach_vm_address_t address,
	mach_vm_size_t size)
{
	kern_return_t rv;

	/*if (__syscall_logger) {
		__syscall_logger(stack_logging_type_vm_deallocate, (uintptr_t)target, (uintptr_t)address, (uintptr_t)size, 0, 0);
	}*/

	rv = _kernelrpc_mach_vm_deallocate_trap(target, address, size);

	if (rv == MACH_SEND_INVALID_DEST) {
		rv = _kernelrpc_mach_vm_deallocate(target, address, size);
	}

	return rv;
}

kern_return_t
mach_vm_protect(
	mach_port_name_t task,
	mach_vm_address_t address,
	mach_vm_size_t size,
	boolean_t set_maximum,
	vm_prot_t new_protection)
{
	kern_return_t rv;

	rv = _kernelrpc_mach_vm_protect_trap(task, address, size, set_maximum,
	    new_protection);

	if (rv == MACH_SEND_INVALID_DEST) {
		rv = _kernelrpc_mach_vm_protect(task, address, size,
		    set_maximum, new_protection);
	}

	return rv;
}

kern_return_t
vm_allocate(
	mach_port_name_t task,
	vm_address_t *address,
	vm_size_t size,
	int flags)
{
	kern_return_t rv;
	mach_vm_address_t mach_addr;

	mach_addr = (mach_vm_address_t)*address;
	rv = mach_vm_allocate(task, &mach_addr, size, flags);
#if defined(__LP64__)
	*address = mach_addr;
#else
	*address = (vm_address_t)(mach_addr & ((vm_address_t)-1));
#endif

	return rv;
}

kern_return_t
vm_deallocate(
	mach_port_name_t task,
	vm_address_t address,
	vm_size_t size)
{
	kern_return_t rv;

	rv = mach_vm_deallocate(task, address, size);

	return rv;
}

kern_return_t
vm_protect(
	mach_port_name_t task,
	vm_address_t address,
	vm_size_t size,
	boolean_t set_maximum,
	vm_prot_t new_protection)
{
	kern_return_t rv;

	rv = mach_vm_protect(task, address, size, set_maximum, new_protection);

	return rv;
}

kern_return_t
mach_vm_map(
	mach_port_name_t target,
	mach_vm_address_t *address,
	mach_vm_size_t size,
	mach_vm_offset_t mask,
	int flags,
	mem_entry_name_port_t object,
	memory_object_offset_t offset,
	boolean_t copy,
	vm_prot_t cur_protection,
	vm_prot_t max_protection,
	vm_inherit_t inheritance)
{
	kern_return_t rv = MACH_SEND_INVALID_DEST;

	if (object == MEMORY_OBJECT_NULL && max_protection == VM_PROT_ALL &&
	    inheritance == VM_INHERIT_DEFAULT) {
		rv = _kernelrpc_mach_vm_map_trap(target, address, size, mask, flags,
		    cur_protection);
	}

	if (rv == MACH_SEND_INVALID_DEST) {
		rv = _kernelrpc_mach_vm_map(target, address, size, mask, flags, object,
		    offset, copy, cur_protection, max_protection, inheritance);
	}

	//int userTagFlags = flags & VM_FLAGS_ALIAS_MASK;
	/*if (__syscall_logger && rv == KERN_SUCCESS && (userTagFlags != VM_MAKE_TAG(VM_MEMORY_STACK))) {
		int eventTypeFlags = stack_logging_type_vm_allocate | stack_logging_type_mapped_file_or_shared_mem;
		__syscall_logger(eventTypeFlags | userTagFlags, (uintptr_t)target, (uintptr_t)size, 0, (uintptr_t)*address, 0);
	}*/

	return rv;
}

kern_return_t
mach_vm_remap(
	mach_port_name_t target,
	mach_vm_address_t *address,
	mach_vm_size_t size,
	mach_vm_offset_t mask,
	int flags,
	mach_port_name_t src_task,
	mach_vm_address_t src_address,
	boolean_t copy,
	vm_prot_t *cur_protection,
	vm_prot_t *max_protection,
	vm_inherit_t inheritance)
{
	kern_return_t rv;

	rv = _kernelrpc_mach_vm_remap(target, address, size, mask, flags,
	    src_task, src_address, copy, cur_protection, max_protection,
	    inheritance);

	/*if (__syscall_logger && rv == KERN_SUCCESS) {
		int eventTypeFlags = stack_logging_type_vm_allocate | stack_logging_type_mapped_file_or_shared_mem;
		int userTagFlags = flags & VM_FLAGS_ALIAS_MASK;
		__syscall_logger(eventTypeFlags | userTagFlags, (uintptr_t)target, (uintptr_t)size, 0, (uintptr_t)*address, 0);
	}*/

	return rv;
}

kern_return_t
mach_vm_read(
	mach_port_name_t target,
	mach_vm_address_t address,
	mach_vm_size_t size,
	vm_offset_t *data,
	mach_msg_type_number_t *dataCnt)
{
	kern_return_t rv;

	rv = _kernelrpc_mach_vm_read(target, address, size, data, dataCnt);

	/*if (__syscall_logger && rv == KERN_SUCCESS) {
		int eventTypeFlags = stack_logging_type_vm_allocate | stack_logging_type_mapped_file_or_shared_mem;
		// The target argument is the remote task from which data is being read,
		// so pass mach_task_self() as the destination task receiving the allocation.
		__syscall_logger(eventTypeFlags, (uintptr_t)mach_task_self(), (uintptr_t)*dataCnt, 0, *data, 0);
	}*/

	return rv;
}

kern_return_t
vm_map(
	mach_port_name_t target,
	vm_address_t *address,
	vm_size_t size,
	vm_offset_t mask,
	int flags,
	mem_entry_name_port_t object,
	vm_offset_t offset,
	boolean_t copy,
	vm_prot_t cur_protection,
	vm_prot_t max_protection,
	vm_inherit_t inheritance)
{
	kern_return_t rv;

	rv = _kernelrpc_vm_map(target, address, size, mask, flags, object,
	    offset, copy, cur_protection, max_protection, inheritance);

	/*if (__syscall_logger && rv == KERN_SUCCESS) {
		int eventTypeFlags = stack_logging_type_vm_allocate | stack_logging_type_mapped_file_or_shared_mem;
		int userTagFlags = flags & VM_FLAGS_ALIAS_MASK;
		__syscall_logger(eventTypeFlags | userTagFlags, (uintptr_t)target, (uintptr_t)size, 0, (uintptr_t)*address, 0);
	}*/

	return rv;
}

kern_return_t
vm_remap(
	mach_port_name_t target,
	vm_address_t *address,
	vm_size_t size,
	vm_offset_t mask,
	int flags,
	mach_port_name_t src_task,
	vm_address_t src_address,
	boolean_t copy,
	vm_prot_t *cur_protection,
	vm_prot_t *max_protection,
	vm_inherit_t inheritance)
{
	kern_return_t rv;

	rv = _kernelrpc_vm_remap(target, address, size, mask, flags,
	    src_task, src_address, copy, cur_protection, max_protection,
	    inheritance);

	/*if (__syscall_logger) {
		int eventTypeFlags = stack_logging_type_vm_allocate | stack_logging_type_mapped_file_or_shared_mem;
		int userTagFlags = flags & VM_FLAGS_ALIAS_MASK;
		__syscall_logger(eventTypeFlags | userTagFlags, (uintptr_t)target, (uintptr_t)size, 0, (uintptr_t)*address, 0);
	}*/

	return rv;
}

kern_return_t
vm_read(
	mach_port_name_t target,
	vm_address_t address,
	vm_size_t size,
	vm_offset_t *data,
	mach_msg_type_number_t *dataCnt)
{
	kern_return_t rv;

	rv = _kernelrpc_vm_read(target, address, size, data, dataCnt);

	/*if (__syscall_logger && rv == KERN_SUCCESS) {
		int eventTypeFlags = stack_logging_type_vm_allocate | stack_logging_type_mapped_file_or_shared_mem;
		// The target argument is the remote task from which data is being read,
		// so pass mach_task_self() as the destination task receiving the allocation.
		__syscall_logger(eventTypeFlags, (uintptr_t)mach_task_self(), (uintptr_t)*dataCnt, 0, *data, 0);
	}*/

	return rv;
}

kern_return_t
mach_vm_purgable_control(
	mach_port_name_t        target,
	mach_vm_offset_t        address,
	vm_purgable_t           control,
	int                     *state)
{
	kern_return_t rv;

	rv = _kernelrpc_mach_vm_purgable_control_trap(target, address, control, state);

	if (rv == MACH_SEND_INVALID_DEST) {
		rv = _kernelrpc_mach_vm_purgable_control(target, address, control, state);
	}

	return rv;
}

kern_return_t
vm_purgable_control(
	mach_port_name_t        task,
	vm_offset_t             address,
	vm_purgable_t           control,
	int                     *state)
{
	return mach_vm_purgable_control(task,
	           (mach_vm_offset_t) address,
	           control,
	           state);
}


kern_return_t
mach_port_allocate(
	ipc_space_t task,
	mach_port_right_t right,
	mach_port_name_t *name)
{
	kern_return_t rv;

	rv = _kernelrpc_mach_port_allocate_trap(task, right, name);

	if (rv == MACH_SEND_INVALID_DEST) {
		rv = _kernelrpc_mach_port_allocate(task, right, name);
	}

	return rv;
}

kern_return_t
mach_port_destroy(
	ipc_space_t task,
	mach_port_name_t name)
{
	kern_return_t rv;

	rv = _kernelrpc_mach_port_destroy(task, name);

	return rv;
}

kern_return_t
mach_port_deallocate(
	ipc_space_t task,
	mach_port_name_t name)
{
	kern_return_t rv;

	rv = _kernelrpc_mach_port_deallocate_trap(task, name);

	if (rv == MACH_SEND_INVALID_DEST) {
		rv = _kernelrpc_mach_port_deallocate(task, name);
	}

	return rv;
}

kern_return_t
mach_port_get_refs(
	ipc_space_t task,
	mach_port_name_t name,
	mach_port_right_t right,
	mach_port_urefs_t *refs)
{
	kern_return_t rv;

	rv = _kernelrpc_mach_port_get_refs(task, name, right, refs);

	return rv;
}

kern_return_t
mach_port_mod_refs(
	ipc_space_t task,
	mach_port_name_t name,
	mach_port_right_t right,
	mach_port_delta_t delta)
{
	kern_return_t rv;

	rv = _kernelrpc_mach_port_mod_refs_trap(task, name, right, delta);

	if (rv == MACH_SEND_INVALID_DEST) {
		rv = _kernelrpc_mach_port_mod_refs(task, name, right, delta);
	}

	return rv;
}


kern_return_t
mach_port_insert_right(
	ipc_space_t task,
	mach_port_name_t name,
	mach_port_t poly,
	mach_msg_type_name_t polyPoly)
{
	kern_return_t rv;

	rv = _kernelrpc_mach_port_insert_right_trap(task, name, poly, polyPoly);

	if (rv == MACH_SEND_INVALID_DEST) {
		rv = _kernelrpc_mach_port_insert_right(task, name, poly,
		    polyPoly);
	}

	return rv;
}

kern_return_t
mach_port_extract_right(
	ipc_space_t task,
	mach_port_name_t name,
	mach_msg_type_name_t msgt_name,
	mach_port_t *poly,
	mach_msg_type_name_t *polyPoly)
{
	kern_return_t rv;

	rv = _kernelrpc_mach_port_extract_right(task, name, msgt_name,
	    poly, polyPoly);

	return rv;
}


kern_return_t
mach_port_guard(
	ipc_space_t             task,
	mach_port_name_t        name,
	mach_port_context_t     guard,
	boolean_t               strict)
{
	kern_return_t rv;

	rv = _kernelrpc_mach_port_guard_trap(task, name, (uint64_t) guard, strict);

	if (rv == MACH_SEND_INVALID_DEST) {
		rv = _kernelrpc_mach_port_guard(task, name, (uint64_t) guard, strict);
	}

	return rv;
}

kern_return_t
mach_port_unguard(
	ipc_space_t             task,
	mach_port_name_t        name,
	mach_port_context_t     guard)
{
	kern_return_t rv;

	rv = _kernelrpc_mach_port_unguard_trap(task, name, (uint64_t) guard);

	if (rv == MACH_SEND_INVALID_DEST) {
		rv = _kernelrpc_mach_port_unguard(task, name, (uint64_t) guard);
	}

	return rv;
}

#define MACH_MSG_TRAP(msg, opt, ssize, rsize, rname, to, not) \
	 mach_msg_trap((msg), (opt), (ssize), (rsize), (rname), (to), (not))

#define LIBMACH_OPTIONS (MACH_SEND_INTERRUPT|MACH_RCV_INTERRUPT)

extern mach_msg_return_t mach_msg_trap(
	mach_msg_header_t *msg,
	mach_msg_option_t option,
	mach_msg_size_t send_size,
	mach_msg_size_t rcv_size,
	mach_port_name_t rcv_name,
	mach_msg_timeout_t timeout,
	mach_port_name_t notify);

/*
 *	Routine:	mach_msg
 *	Purpose:
 *		Send and/or receive a message.  If the message operation
 *		is interrupted, and the user did not request an indication
 *		of that fact, then restart the appropriate parts of the
 *              operation.
 */
mach_msg_return_t
mach_msg(msg, option, send_size, rcv_size, rcv_name, timeout, notify)
mach_msg_header_t *msg;
mach_msg_option_t option;
mach_msg_size_t send_size;
mach_msg_size_t rcv_size;
mach_port_t rcv_name;
mach_msg_timeout_t timeout;
mach_port_t notify;
{
	mach_msg_return_t mr;

	/*
	 * Consider the following cases:
	 *	1) Errors in pseudo-receive (eg, MACH_SEND_INTERRUPTED
	 *	plus special bits).
	 *	2) Use of MACH_SEND_INTERRUPT/MACH_RCV_INTERRUPT options.
	 *	3) RPC calls with interruptions in one/both halves.
	 *
	 * We refrain from passing the option bits that we implement
	 * to the kernel.  This prevents their presence from inhibiting
	 * the kernel's fast paths (when it checks the option value).
	 */

	mr = MACH_MSG_TRAP(msg, option & ~LIBMACH_OPTIONS,
	    send_size, rcv_size, rcv_name,
	    timeout, notify);
	if (mr == MACH_MSG_SUCCESS) {
		return MACH_MSG_SUCCESS;
	}

	if ((option & MACH_SEND_INTERRUPT) == 0) {
		while (mr == MACH_SEND_INTERRUPTED) {
			mr = MACH_MSG_TRAP(msg,
			    option & ~LIBMACH_OPTIONS,
			    send_size, rcv_size, rcv_name,
			    timeout, notify);
		}
	}

	if ((option & MACH_RCV_INTERRUPT) == 0) {
		while (mr == MACH_RCV_INTERRUPTED) {
			mr = MACH_MSG_TRAP(msg,
			    option & ~(LIBMACH_OPTIONS | MACH_SEND_MSG),
			    0, rcv_size, rcv_name,
			    timeout, notify);
		}
	}

	return mr;
}

static void
mach_msg_destroy_port(mach_port_t port, mach_msg_type_name_t type)
{
	if (MACH_PORT_VALID(port)) {
		switch (type) {
		case MACH_MSG_TYPE_MOVE_SEND:
		case MACH_MSG_TYPE_MOVE_SEND_ONCE:
			/* destroy the send/send-once right */
			(void) mach_port_deallocate(mach_task_self_, port);
			break;

		case MACH_MSG_TYPE_MOVE_RECEIVE:
			/* destroy the receive right */
			(void) mach_port_mod_refs(mach_task_self_, port,
			    MACH_PORT_RIGHT_RECEIVE, -1);
			break;

		case MACH_MSG_TYPE_MAKE_SEND:
			/* create a send right and then destroy it */
			(void) mach_port_insert_right(mach_task_self_, port,
			    port, MACH_MSG_TYPE_MAKE_SEND);
			(void) mach_port_deallocate(mach_task_self_, port);
			break;

		case MACH_MSG_TYPE_MAKE_SEND_ONCE:
			/* create a send-once right and then destroy it */
			(void) mach_port_extract_right(mach_task_self_, port,
			    MACH_MSG_TYPE_MAKE_SEND_ONCE,
			    &port, &type);
			(void) mach_port_deallocate(mach_task_self_, port);
			break;
		}
	}
}

static void
mach_msg_destroy_memory(vm_offset_t addr, vm_size_t size)
{
	if (size != 0) {
		(void) vm_deallocate(mach_task_self_, addr, size);
	}
}


/*
 *	Routine:	mach_msg_destroy
 *	Purpose:
 *		mach_msg_destroy is useful in two contexts.
 *
 *		First, it can deallocate all port rights and
 *		out-of-line memory in a received message.
 *		When a server receives a request it doesn't want,
 *		it needs this functionality.
 *
 *		Second, it can mimic the side-effects of a msg-send
 *		operation.  The effect is as if the message were sent
 *		and then destroyed inside the kernel.  When a server
 *		can't send a reply (because the client died),
 *		it needs this functionality.
 */
void
mach_msg_destroy(mach_msg_header_t *msg)
{
	mach_msg_bits_t mbits = msg->msgh_bits;

	/*
	 *	The msgh_local_port field doesn't hold a port right.
	 *	The receive operation consumes the destination port right.
	 */

	mach_msg_destroy_port(msg->msgh_remote_port, MACH_MSGH_BITS_REMOTE(mbits));
	mach_msg_destroy_port(msg->msgh_voucher_port, MACH_MSGH_BITS_VOUCHER(mbits));

	if (mbits & MACH_MSGH_BITS_COMPLEX) {
		mach_msg_base_t         *base;
		mach_msg_type_number_t  count, i;
		mach_msg_descriptor_t   *daddr;

		base = (mach_msg_base_t *) msg;
		count = base->body.msgh_descriptor_count;

		daddr = (mach_msg_descriptor_t *) (base + 1);
		for (i = 0; i < count; i++) {
			switch (daddr->type.type) {
			case MACH_MSG_PORT_DESCRIPTOR: {
				mach_msg_port_descriptor_t *dsc;

				/*
				 * Destroy port rights carried in the message
				 */
				dsc = &daddr->port;
				mach_msg_destroy_port(dsc->name, dsc->disposition);
				daddr = (mach_msg_descriptor_t *)(dsc + 1);
				break;
			}

			case MACH_MSG_OOL_DESCRIPTOR: {
				mach_msg_ool_descriptor_t *dsc;

				/*
				 * Destroy memory carried in the message
				 */
				dsc = &daddr->out_of_line;
				if (dsc->deallocate) {
					mach_msg_destroy_memory((vm_offset_t)dsc->address,
					    dsc->size);
				}
				daddr = (mach_msg_descriptor_t *)(dsc + 1);
				break;
			}

			case MACH_MSG_OOL_VOLATILE_DESCRIPTOR: {
				mach_msg_ool_descriptor_t *dsc;

				/*
				 * Just skip it.
				 */
				dsc = &daddr->out_of_line;
				daddr = (mach_msg_descriptor_t *)(dsc + 1);
				break;
			}

			case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
				mach_port_t                         *ports;
				mach_msg_ool_ports_descriptor_t     *dsc;
				mach_msg_type_number_t              j;

				/*
				 * Destroy port rights carried in the message
				 */
				dsc = &daddr->ool_ports;
				ports = (mach_port_t *) dsc->address;
				for (j = 0; j < dsc->count; j++, ports++) {
					mach_msg_destroy_port(*ports, dsc->disposition);
				}

				/*
				 * Destroy memory carried in the message
				 */
				if (dsc->deallocate) {
					mach_msg_destroy_memory((vm_offset_t)dsc->address,
					    dsc->count * sizeof(mach_port_t));
				}
				daddr = (mach_msg_descriptor_t *)(dsc + 1);
				break;
			}

			case MACH_MSG_GUARDED_PORT_DESCRIPTOR: {
				mach_msg_guarded_port_descriptor_t *dsc;
				mach_msg_guard_flags_t flags;
				/*
				 * Destroy port right carried in the message
				 */
				dsc = &daddr->guarded_port;
				flags = dsc->flags;
				if ((flags & MACH_MSG_GUARD_FLAGS_UNGUARDED_ON_SEND) == 0) {
					/* Need to unguard before destroying the port */
					mach_port_unguard(mach_task_self_, dsc->name, (uint64_t)dsc->context);
				}
				mach_msg_destroy_port(dsc->name, dsc->disposition);
				daddr = (mach_msg_descriptor_t *)(dsc + 1);
				break;
			}
			}
		}
	}
}

kern_return_t
host_page_size(__unused host_t host, vm_size_t *out_page_size) {
	*out_page_size = vm_kernel_page_size;
	return KERN_SUCCESS;
}

extern mach_port_name_t host_self_trap(void);

mach_port_t
mach_host_self(void) {
	return host_self_trap();
}

int
mig_strncpy(
	char *dest,
	const char *src,
	int len)
{
	int i;

	if (len <= 0) {
		return 0;
	}

	for (i = 1; i < len; i++) {
		if (!(*dest++ = *src++)) {
			return i;
		}
	}

	*dest = '\0';
	return i;
}

int
mig_strncpy_zerofill(
	char *dest,
	const char *src,
	int len)
{
	int i;
	boolean_t terminated = FALSE;
	int retval = 0;

	if (len <= 0 || dest == 0) {
		return 0;
	}

	if (src == 0) {
		terminated = TRUE;
	}

	for (i = 1; i < len; i++) {
		if (!terminated) {
			if (!(*dest++ = *src++)) {
				retval = i;
				terminated = TRUE;
			}
		} else {
			*dest++ = '\0';
		}
	}

	*dest = '\0';
	if (!terminated) {
		retval = i;
	}

	return retval;
}

#define __TSD_MIG_REPLY 2

extern mach_port_name_t mach_reply_port(void);

static void**
_os_tsd_get_base(void);
//#define _os_tsd_get_base()  _os_tsd_get_base()

__attribute__((always_inline))
static __inline__ void*
_os_tsd_get_direct(unsigned long slot) {
	return _os_tsd_get_base()[slot];
}

__attribute__((always_inline))
static __inline__ int
_os_tsd_set_direct(unsigned long slot, void *val) {
	_os_tsd_get_base()[slot] = val;
	return 0;
}


__XNU_PRIVATE_EXTERN mach_port_t _task_reply_port = MACH_PORT_NULL;

static inline mach_port_t
_mig_get_reply_port()
{
	return (mach_port_t)(uintptr_t)_os_tsd_get_direct(__TSD_MIG_REPLY);
}

static inline void
_mig_set_reply_port(mach_port_t port)
{
	_os_tsd_set_direct(__TSD_MIG_REPLY, (void *)(uintptr_t)port);
}

/*
 * Called by mig interface code whenever a reply port is needed.
 * Tracing is masked during this call; otherwise, a call to printf()
 * can result in a call to malloc() which eventually reenters
 * mig_get_reply_port() and deadlocks.
 */
mach_port_t
mig_get_reply_port(void)
{
	mach_port_t port = _mig_get_reply_port();
	if (port == MACH_PORT_NULL) {
		port = mach_reply_port();
		_mig_set_reply_port(port);
	}
	return port;
}

/*
 * Called by mig interface code after a timeout on the reply port.
 * May also be called by user. The new mig calls with port passed in.
 */
void
mig_dealloc_reply_port(mach_port_t migport)
{
	mach_port_t port = _mig_get_reply_port();
	if (port != MACH_PORT_NULL && port != _task_reply_port) {
		_mig_set_reply_port(_task_reply_port);
		(void) mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
		if (migport != port) {
			(void) mach_port_deallocate(mach_task_self(), migport);
		}
		_mig_set_reply_port(MACH_PORT_NULL);
	}
}

/*************************************************************
 *  Called by mig interfaces after each RPC.
 *  Could be called by user.
 ***********************************************************/

void
mig_put_reply_port(mach_port_t reply_port __unused)
{
}


static kern_return_t
mach_msg_server_mig_return_code(mig_reply_error_t *reply)
{
	/*
	 * If the message is complex, it is assumed that the reply was successful,
	 * as the RetCode is where the count of out of line descriptors is.
	 *
	 * If not, we read RetCode.
	 */
	if (reply->Head.msgh_bits & MACH_MSGH_BITS_COMPLEX) {
		return KERN_SUCCESS;
	}
	return reply->RetCode;
}

static inline boolean_t
mach_msg_server_is_recoverable_send_error(kern_return_t kr)
{
	switch (kr) {
	case MACH_SEND_INVALID_DEST:
	case MACH_SEND_TIMED_OUT:
	case MACH_SEND_INTERRUPTED:
		return TRUE;
	default:
		/*
		 * Other errors mean that the message may have been partially destroyed
		 * by the kernel, and these can't be recovered and may leak resources.
		 */
		return FALSE;
	}
}

static void
mach_msg_server_consume_unsent_message(mach_msg_header_t *hdr)
{
	/* mach_msg_destroy doesn't handle the local port */
	mach_port_t port = hdr->msgh_local_port;
	if (MACH_PORT_VALID(port)) {
		switch (MACH_MSGH_BITS_LOCAL(hdr->msgh_bits)) {
		case MACH_MSG_TYPE_MOVE_SEND:
		case MACH_MSG_TYPE_MOVE_SEND_ONCE:
			/* destroy the send/send-once right */
			(void) mach_port_deallocate(mach_task_self_, port);
			hdr->msgh_local_port = MACH_PORT_NULL;
			break;
		}
	}
	mach_msg_destroy(hdr);
}

/*
 *	Routine:	mach_msg_overwrite
 *	Purpose:
 *		Send and/or receive a message.  If the message operation
 *		is interrupted, and the user did not request an indication
 *		of that fact, then restart the appropriate parts of the
 *              operation.
 *
 *		Distinct send and receive buffers may be specified.  If
 *		no separate receive buffer is specified, the msg parameter
 *		will be used for both send and receive operations.
 *
 *		In addition to a distinct receive buffer, that buffer may
 *		already contain scatter control information to direct the
 *		receiving of the message.
 */

extern mach_msg_return_t mach_msg_overwrite_trap(
	mach_msg_header_t *msg,
	mach_msg_option_t option,
	mach_msg_size_t send_size,
	mach_msg_size_t rcv_size,
	mach_port_name_t rcv_name,
	mach_msg_timeout_t timeout,
	mach_msg_priority_t priority,
	mach_msg_header_t *rcv_msg,
	mach_msg_size_t rcv_limit);

mach_msg_return_t
mach_msg_overwrite(msg, option, send_size, rcv_limit, rcv_name, timeout,
    notify, rcv_msg, rcv_scatter_size)
mach_msg_header_t *msg;
mach_msg_option_t option;
mach_msg_size_t send_size;
mach_msg_size_t rcv_limit;
mach_port_t rcv_name;
mach_msg_timeout_t timeout;
mach_port_t notify;
mach_msg_header_t *rcv_msg;
mach_msg_size_t rcv_scatter_size;
{
	mach_msg_return_t mr;

	/*
	 * Consider the following cases:
	 *	1) Errors in pseudo-receive (eg, MACH_SEND_INTERRUPTED
	 *	plus special bits).
	 *	2) Use of MACH_SEND_INTERRUPT/MACH_RCV_INTERRUPT options.
	 *	3) RPC calls with interruptions in one/both halves.
	 *
	 * We refrain from passing the option bits that we implement
	 * to the kernel.  This prevents their presence from inhibiting
	 * the kernel's fast paths (when it checks the option value).
	 */

	mr = mach_msg_overwrite_trap(msg, option & ~LIBMACH_OPTIONS,
	    send_size, rcv_limit, rcv_name,
	    timeout, notify, rcv_msg, rcv_scatter_size);
	if (mr == MACH_MSG_SUCCESS) {
		return MACH_MSG_SUCCESS;
	}

	if ((option & MACH_SEND_INTERRUPT) == 0) {
		while (mr == MACH_SEND_INTERRUPTED) {
			mr = mach_msg_overwrite_trap(msg,
			    option & ~LIBMACH_OPTIONS,
			    send_size, rcv_limit, rcv_name,
			    timeout, notify, rcv_msg, rcv_scatter_size);
		}
	}

	if ((option & MACH_RCV_INTERRUPT) == 0) {
		while (mr == MACH_RCV_INTERRUPTED) {
			mr = mach_msg_overwrite_trap(msg,
			    option & ~(LIBMACH_OPTIONS | MACH_SEND_MSG),
			    0, rcv_limit, rcv_name,
			    timeout, notify, rcv_msg, rcv_scatter_size);
		}
	}

	return mr;
}

/*
 *	Routine:	mach_msg_server
 *	Purpose:
 *		A simple generic server function.  Note that changes here
 *              should be considered for duplication above.
 */
mach_msg_return_t
mach_msg_server(
	boolean_t (*demux)(mach_msg_header_t *, mach_msg_header_t *),
	mach_msg_size_t max_size,
	mach_port_t rcv_name,
	mach_msg_options_t options)
{
	mig_reply_error_t *bufRequest, *bufReply;
	mach_msg_size_t request_size;
	mach_msg_size_t new_request_alloc;
	mach_msg_size_t request_alloc;
	mach_msg_size_t trailer_alloc;
	mach_msg_size_t reply_alloc;
	mach_msg_return_t mr;
	kern_return_t kr;
	mach_port_t self = mach_task_self_;
	voucher_mach_msg_state_t old_state = VOUCHER_MACH_MSG_STATE_UNCHANGED;
	boolean_t buffers_swapped = FALSE;

	options &= ~(MACH_SEND_MSG | MACH_RCV_MSG | MACH_RCV_VOUCHER);

	reply_alloc = (mach_msg_size_t)round_page((options & MACH_SEND_TRAILER) ?
	    (max_size + MAX_TRAILER_SIZE) : max_size);

	kr = vm_allocate(self,
	    (vm_address_t *)&bufReply,
	    reply_alloc,
	    VM_MAKE_TAG(VM_MEMORY_MACH_MSG) | TRUE);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	request_alloc = 0;
	trailer_alloc = REQUESTED_TRAILER_SIZE(options);
	new_request_alloc = (mach_msg_size_t)round_page(max_size + trailer_alloc);

	request_size = (options & MACH_RCV_LARGE) ?
	    new_request_alloc : max_size + trailer_alloc;

	for (;;) {
		if (request_alloc < new_request_alloc) {
			request_alloc = new_request_alloc;
			kr = vm_allocate(self,
			    (vm_address_t *)&bufRequest,
			    request_alloc,
			    VM_MAKE_TAG(VM_MEMORY_MACH_MSG) | TRUE);
			if (kr != KERN_SUCCESS) {
				vm_deallocate(self,
				    (vm_address_t)bufReply,
				    reply_alloc);
				return kr;
			}
		}

		mr = mach_msg(&bufRequest->Head, MACH_RCV_MSG | MACH_RCV_VOUCHER | options,
		    0, request_size, rcv_name,
		    MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);

		while (mr == MACH_MSG_SUCCESS) {
			/* we have another request message */

			buffers_swapped = FALSE;
			old_state = voucher_mach_msg_adopt(&bufRequest->Head);
			bufReply->Head = (mach_msg_header_t){};

			(void) (*demux)(&bufRequest->Head, &bufReply->Head);

			switch (mach_msg_server_mig_return_code(bufReply)) {
			case KERN_SUCCESS:
				break;
			case MIG_NO_REPLY:
				bufReply->Head.msgh_remote_port = MACH_PORT_NULL;
				break;
			default:
				/*
				 * destroy the request - but not the reply port
				 * (MIG moved it into the bufReply).
				 */
				bufRequest->Head.msgh_remote_port = MACH_PORT_NULL;
				mach_msg_destroy(&bufRequest->Head);
			}

			/*
			 * We don't want to block indefinitely because the client
			 * isn't receiving messages from the reply port.
			 * If we have a send-once right for the reply port, then
			 * this isn't a concern because the send won't block.
			 * If we have a send right, we need to use MACH_SEND_TIMEOUT.
			 * To avoid falling off the kernel's fast RPC path,
			 * we only supply MACH_SEND_TIMEOUT when absolutely necessary.
			 */
			if (bufReply->Head.msgh_remote_port != MACH_PORT_NULL) {
				if (request_alloc == reply_alloc) {
					mig_reply_error_t *bufTemp;

					mr = mach_msg(
						&bufReply->Head,
						(MACH_MSGH_BITS_REMOTE(bufReply->Head.msgh_bits) ==
						MACH_MSG_TYPE_MOVE_SEND_ONCE) ?
						MACH_SEND_MSG | MACH_RCV_MSG | MACH_RCV_TIMEOUT | MACH_RCV_VOUCHER | options :
						MACH_SEND_MSG | MACH_RCV_MSG | MACH_SEND_TIMEOUT | MACH_RCV_TIMEOUT | MACH_RCV_VOUCHER | options,
						bufReply->Head.msgh_size, request_size, rcv_name,
						MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);

					/* swap request and reply */
					bufTemp = bufRequest;
					bufRequest = bufReply;
					bufReply = bufTemp;
					buffers_swapped = TRUE;
				} else {
					mr = mach_msg_overwrite(
						&bufReply->Head,
						(MACH_MSGH_BITS_REMOTE(bufReply->Head.msgh_bits) ==
						MACH_MSG_TYPE_MOVE_SEND_ONCE) ?
						MACH_SEND_MSG | MACH_RCV_MSG | MACH_RCV_TIMEOUT | MACH_RCV_VOUCHER | options :
						MACH_SEND_MSG | MACH_RCV_MSG | MACH_SEND_TIMEOUT | MACH_RCV_TIMEOUT | MACH_RCV_VOUCHER | options,
						bufReply->Head.msgh_size, request_size, rcv_name,
						MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL,
						&bufRequest->Head, 0);
				}

				/*
				 * Need to destroy the reply msg in case if there was a send timeout or
				 * invalid destination. The reply msg would be swapped with request msg
				 * if buffers_swapped is true, thus destroy request msg instead of
				 * reply msg in such cases.
				 */
				if (mach_msg_server_is_recoverable_send_error(mr)) {
					if (buffers_swapped) {
						mach_msg_server_consume_unsent_message(&bufRequest->Head);
					} else {
						mach_msg_server_consume_unsent_message(&bufReply->Head);
					}
				} else if (mr != MACH_RCV_TIMED_OUT) {
					voucher_mach_msg_revert(old_state);
					old_state = VOUCHER_MACH_MSG_STATE_UNCHANGED;

					continue;
				}
			}
			voucher_mach_msg_revert(old_state);
			old_state = VOUCHER_MACH_MSG_STATE_UNCHANGED;

			mr = mach_msg(&bufRequest->Head, MACH_RCV_MSG | MACH_RCV_VOUCHER | options,
			    0, request_size, rcv_name,
			    MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
		} /* while (mr == MACH_MSG_SUCCESS) */

		if ((mr == MACH_RCV_TOO_LARGE) && (options & MACH_RCV_LARGE)) {
			new_request_alloc = (mach_msg_size_t)round_page(bufRequest->Head.msgh_size +
			    trailer_alloc);
			request_size = new_request_alloc;
			vm_deallocate(self,
			    (vm_address_t) bufRequest,
			    request_alloc);
			continue;
		}

		break;
	} /* for(;;) */

	(void)vm_deallocate(self,
	    (vm_address_t) bufRequest,
	    request_alloc);
	(void)vm_deallocate(self,
	    (vm_address_t) bufReply,
	    reply_alloc);
	return mr;
}

typedef const struct _libkernel_voucher_functions {
	/* The following functions are included in version 1 of this structure */
	unsigned long version;
	boolean_t (*voucher_mach_msg_set)(mach_msg_header_t*);
	void (*voucher_mach_msg_clear)(mach_msg_header_t*);
	voucher_mach_msg_state_t (*voucher_mach_msg_adopt)(mach_msg_header_t*);
	void (*voucher_mach_msg_revert)(voucher_mach_msg_state_t);

	/* Subsequent versions must only add pointers! */
} *_libkernel_voucher_functions_t;

static const struct _libkernel_voucher_functions
    _libkernel_voucher_functions_empty;
static _libkernel_voucher_functions_t _libkernel_voucher_functions =
    &_libkernel_voucher_functions_empty;

kern_return_t
__libkernel_voucher_init(_libkernel_voucher_functions_t fns)
{
	_libkernel_voucher_functions = fns;
	return KERN_SUCCESS;
}

boolean_t
voucher_mach_msg_set(mach_msg_header_t *msg)
{
	if (_libkernel_voucher_functions->voucher_mach_msg_set) {
		return _libkernel_voucher_functions->voucher_mach_msg_set(msg);
	}
	return 0;
}

void
voucher_mach_msg_clear(mach_msg_header_t *msg)
{
	if (_libkernel_voucher_functions->voucher_mach_msg_clear) {
		return _libkernel_voucher_functions->voucher_mach_msg_clear(msg);
	}
}

voucher_mach_msg_state_t
voucher_mach_msg_adopt(mach_msg_header_t *msg)
{
	if (_libkernel_voucher_functions->voucher_mach_msg_adopt) {
		return _libkernel_voucher_functions->voucher_mach_msg_adopt(msg);
	}
	return VOUCHER_MACH_MSG_STATE_UNCHANGED;
}

void
voucher_mach_msg_revert(voucher_mach_msg_state_t state)
{
	if (_libkernel_voucher_functions->voucher_mach_msg_revert) {
		return _libkernel_voucher_functions->voucher_mach_msg_revert(state);
	}
}

__attribute__((always_inline, pure))
static __inline__ void**
_os_tsd_get_base(void)
{
#if defined(__arm__)
	uintptr_t tsd;
	__asm__("mrc p15, 0, %0, c13, c0, 3\n"
                "bic %0, %0, #0x3\n" : "=r" (tsd));
#elif defined(__arm64__)
	uint64_t tsd;
	__asm__("mrs %0, TPIDRRO_EL0\n"
                "bic %0, %0, #0x7\n" : "=r" (tsd));
#endif

	return (void**)(uintptr_t)tsd;
}


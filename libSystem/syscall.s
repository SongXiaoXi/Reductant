
#define SWI_SYSCALL     0x80

#define kernel_trap(trap_name, trap_number, num_args) \
.globl _##trap_name                                           %% \
.text                                                         %% \
.align  2                                                     %% \
_##trap_name:                                                 %% \
    mov x16, #(trap_number)                                   %% \
    svc #SWI_SYSCALL                                          %% \
    ret

kernel_trap(__proc_info, 0x150, 6)
kernel_trap(getpid, 0x14, 0)

kernel_trap(_kernelrpc_mach_vm_allocate_trap,-10,5) /* 4 args, +1 for mach_vm_size_t */
kernel_trap(_kernelrpc_mach_vm_purgable_control_trap,-11,5) /* 4 args, +1 for mach_vm_offset_t */
kernel_trap(_kernelrpc_mach_vm_deallocate_trap,-12,5) /* 3 args, +2 for mach_vm_size_t and mach_vm_address_t */
kernel_trap(_kernelrpc_mach_vm_protect_trap,-14,7) /* 5 args, +2 for mach_vm_address_t and mach_vm_size_t */
kernel_trap(_kernelrpc_mach_vm_map_trap,-15,9)
kernel_trap(_kernelrpc_mach_port_allocate_trap,-16,3)
/* mach_port_destroy */
kernel_trap(_kernelrpc_mach_port_deallocate_trap,-18,2)
kernel_trap(_kernelrpc_mach_port_mod_refs_trap,-19,4)
kernel_trap(_kernelrpc_mach_port_move_member_trap,-20,3)
kernel_trap(_kernelrpc_mach_port_insert_right_trap,-21,4)
kernel_trap(_kernelrpc_mach_port_insert_member_trap,-22,3)
kernel_trap(_kernelrpc_mach_port_extract_member_trap,-23,3)
kernel_trap(_kernelrpc_mach_port_construct_trap,-24,5)
kernel_trap(_kernelrpc_mach_port_destruct_trap,-25,5)

kernel_trap(mach_reply_port,-26,0)
kernel_trap(thread_self_trap,-27,0)
kernel_trap(task_self_trap,-28,0)
kernel_trap(host_self_trap,-29,0)

kernel_trap(mach_msg_trap,-31,7)
kernel_trap(mach_msg_overwrite_trap,-32,9)
kernel_trap(semaphore_signal_trap, -33, 1)
kernel_trap(semaphore_signal_all_trap, -34, 1)
kernel_trap(semaphore_signal_thread_trap, -35, 2)
kernel_trap(semaphore_wait_trap,-36,1)
kernel_trap(semaphore_wait_signal_trap,-37,2)
kernel_trap(semaphore_timedwait_trap,-38,3)
kernel_trap(semaphore_timedwait_signal_trap,-39,4)

kernel_trap(_kernelrpc_mach_port_get_attributes_trap,-40,5)
kernel_trap(_kernelrpc_mach_port_guard_trap,-41,5)
kernel_trap(_kernelrpc_mach_port_unguard_trap,-42,4)
kernel_trap(mach_generate_activity_id, -43, 3)

kernel_trap(task_name_for_pid,-44,3)
kernel_trap(task_for_pid,-45,3)
kernel_trap(pid_for_task,-46,2)

#if defined(__LP64__)
kernel_trap(macx_swapon,-48, 4)
kernel_trap(macx_swapoff,-49, 2)
#else	/* __LP64__ */
kernel_trap(macx_swapon,-48, 5)
kernel_trap(macx_swapoff,-49, 3)
#endif	/* __LP64__ */
kernel_trap(thread_get_special_reply_port,-50,0)
kernel_trap(macx_triggers,-51, 4)
kernel_trap(macx_backing_store_suspend,-52, 1)
kernel_trap(macx_backing_store_recovery,-53, 1)

/* These are currently used by pthreads even on LP64 */
/* But as soon as that is fixed - they will go away there */
kernel_trap(swtch_pri,-59,1)
kernel_trap(swtch,-60,0)

kernel_trap(syscall_thread_switch,-61,3)
kernel_trap(clock_sleep_trap,-62,5)

/* voucher traps */
kernel_trap(host_create_mach_voucher_trap,-70,4)
/* mach_voucher_extract_attr_content */
kernel_trap(mach_voucher_extract_attr_recipe_trap,-72,4)
/* mach_voucher_extract_all_attr_recipes */
/* mach_voucher_attr_command */
/* mach_voucher_debug_info */

/* more mach_port traps */
kernel_trap(_kernelrpc_mach_port_type_trap,-76,3)
kernel_trap(_kernelrpc_mach_port_request_notification_trap,-77,7)

kernel_trap(mach_timebase_info_trap,-89,1)

#if		defined(__LP64__)
/* unit64_t arguments passed in one register in LP64 */
kernel_trap(mach_wait_until,-90,1)
#else	/* __LP64__ */
kernel_trap(mach_wait_until,-90,2)
#endif	/* __LP64__ */

kernel_trap(mk_timer_create,-91,0)
kernel_trap(mk_timer_destroy,-92,1)

#if		defined(__LP64__)
/* unit64_t arguments passed in one register in LP64 */
kernel_trap(mk_timer_arm,-93,2)
#else	/* __LP64__ */
kernel_trap(mk_timer_arm,-93,3)
#endif	/* __LP64__ */

kernel_trap(mk_timer_cancel,-94,2)
#if		defined(__LP64__)
kernel_trap(mk_timer_arm_leeway,-95,4)
#else
kernel_trap(mk_timer_arm_leeway,-95,7)
#endif
kernel_trap(debug_control_port_for_pid,-96,3)

#define _COMM_PAGE64_BASE_ADDRESS               (0x0000000FFFFFC000ULL) /* In TTBR0 */
#define _COMM_PAGE_START_ADDRESS                (_COMM_PAGE64_BASE_ADDRESS)
#define _COMM_PAGE_CONT_HW_TIMEBASE             (_COMM_PAGE_START_ADDRESS+0x0A8)        // uint64_t base for mach_continuous_time() relative to CNT[PV]CT
#define _COMM_PAGE_CONT_TIMEBASE                (_COMM_PAGE_START_ADDRESS+0x098)        // uint64_t base for mach_continuous_time() relative to mach_absolute_time()
#define _COMM_PAGE_CONT_HWCLOCK                 (_COMM_PAGE_START_ADDRESS+0x091)        // uint8_t is always-on hardware clock present for mach_continuous_time()
#define _COMM_PAGE_USER_TIMEBASE                (_COMM_PAGE_START_ADDRESS+0x090)        // uint8_t is userspace mach_absolute_time supported (can read the timebase)
#define _COMM_PAGE_TIMEBASE_OFFSET              (_COMM_PAGE_START_ADDRESS+0x088)        // uint64_t timebase offset for constructing mach_absolute_time()

#define USER_TIMEBASE_NONE   0
#define USER_TIMEBASE_SPEC   1
	.text
	.align 2
	.globl _mach_absolute_time
_mach_absolute_time:
	movk	x3, #(((_COMM_PAGE_TIMEBASE_OFFSET) >> 48) & 0x000000000000FFFF), lsl #48
	movk	x3, #(((_COMM_PAGE_TIMEBASE_OFFSET) >> 32) & 0x000000000000FFFF), lsl #32
	movk	x3, #(((_COMM_PAGE_TIMEBASE_OFFSET) >> 16) & 0x000000000000FFFF), lsl #16
	movk	x3, #((_COMM_PAGE_TIMEBASE_OFFSET) & 0x000000000000FFFF)
	ldrb	w2, [x3, #((_COMM_PAGE_USER_TIMEBASE) - (_COMM_PAGE_TIMEBASE_OFFSET))]
	cmp	x2, #USER_TIMEBASE_NONE		// Are userspace reads supported?
	b.eq	_mach_absolute_time_kernel	// If not, go to the kernel
	isb					// Prevent speculation on CNTPCT across calls
						// (see ARMV7C.b section B8.1.2, ARMv8 section D6.1.2)
L_mach_absolute_time_user:
	ldr	x1, [x3]			// Load the offset
	mrs	x0, CNTPCT_EL0			// Read the timebase
	ldr	x2, [x3]			// Load the offset
	cmp	x1, x2				// Compare our offset values...
	b.ne	L_mach_absolute_time_user	// If they changed, try again
	add	x0, x0, x1			// Construct mach_absolute_time
	ret



	.text
	.align 2
	.globl _mach_absolute_time_kernel
_mach_absolute_time_kernel:
	mov	w16, #-3			// Load the magic MAT number
	svc	#SWI_SYSCALL
	ret

	.text
	.align 2
	.globl _mach_continuous_time_kernel
_mach_continuous_time_kernel:
	mov	w16, #-4			// Load the magic MCT number
	svc	#SWI_SYSCALL
	ret
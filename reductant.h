#ifndef __REDUCTANT_H__
#define __REDUCTANT_H__

#include <stddef.h>
#include <mach/mach.h>
#include <mach/vm_map.h>

#define FD_VALID(fd) ((fd) >= 0)
#define FD_INVALID(fd) (fd < 0)

__BEGIN_DECLS

int map_dyld_and_main_executable(int target_pid, const char *dyld_path, const char *argv0, int fd, void *exe_map, size_t map_size);

kern_return_t mach_vm_read_overwrite(
	vm_map_t target_task,
	mach_vm_address_t address,
	mach_vm_size_t size,
	mach_vm_address_t data,
	mach_vm_size_t *outsize
);

kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);

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
	vm_inherit_t inheritance);

kern_return_t
mach_vm_region(vm_map_t, mach_vm_address_t *, mach_vm_size_t *, vm_region_flavor_t, vm_region_info_t, mach_msg_type_number_t *, mach_port_t *);

__END_DECLS

#endif // __REDUCTANT_H__
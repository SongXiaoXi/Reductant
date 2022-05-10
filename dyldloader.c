#include <errno.h>
#include <fcntl.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>
#include <mach-o/getsect.h>
#include <mach-o/ldsyms.h>
#include "reductant.h"

static void 
set_all_images_offset_maybe(struct segment_command_64* seg_cmd,
                                                        size_t* all_images_offset) {
    struct section_64* sections = (void*)seg_cmd + sizeof(*seg_cmd);
    for (unsigned int index = 0; index < seg_cmd->nsects; index++) {
        struct section_64* section = &sections[index];
        if (!strncmp(section->sectname, "__all_image_info",
                                 sizeof(section->sectname))) {
            if (all_images_offset != NULL) {
                *all_images_offset = section->addr;
            }
        }
    }
}

static size_t 
get_execute_address_space_size(void* executable_region,
                               size_t* all_images_offset, 
                       size_t* sigcmd_dataoff,
                       size_t* sigcmd_datasize) {
    struct mach_header_64* mh = executable_region;
    struct load_command* cmd = executable_region + sizeof(struct mach_header_64);
    if (all_images_offset != NULL) {
        *all_images_offset = 0;
    }

    uint64_t min_addr = ~0;
    uint64_t max_addr = 0;
    for (unsigned int index = 0; index < mh->ncmds; index++) {
        switch (cmd->cmd) {
            case LC_SEGMENT_64: {
                struct segment_command_64* seg_cmd = (struct segment_command_64*)cmd;
                if (!strncmp(seg_cmd->segname, "__PAGEZERO", sizeof(seg_cmd->segname))) {
                    break;
                }
                min_addr = MIN(min_addr, seg_cmd->vmaddr);
                max_addr = MAX(max_addr, seg_cmd->vmaddr + seg_cmd->vmsize);
                if (all_images_offset != NULL && !strncmp(seg_cmd->segname, "__DATA", sizeof(seg_cmd->segname))) {
                    set_all_images_offset_maybe(seg_cmd, all_images_offset);
                }
                break;
            }
            case LC_CODE_SIGNATURE: {
                struct linkedit_data_command* signature_cmd =
                        (struct linkedit_data_command*)cmd;
                *sigcmd_dataoff = signature_cmd->dataoff;
                *sigcmd_datasize = signature_cmd->datasize;
            }
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    return max_addr - min_addr;
}

#ifdef __arm64__
static const cpu_type_t kPreferredCpuType = CPU_TYPE_ARM64;
#else
static const cpu_type_t kPreferredCpuType = CPU_TYPE_X86_64;
#endif

static off_t 
get_fat_offset(void* fat_region) {
    struct fat_header* fat_header = fat_region;
    if (fat_header->magic != FAT_CIGAM) {
        //fprintf(stderr, "Not a FAT executable. Assume raw.\n");
        return 0;
    }
    struct fat_arch* fat_arches = fat_region + sizeof(struct fat_header);
    for (unsigned int index = 0; index < ntohl(fat_header->nfat_arch); index++) {
        struct fat_arch* fat_arch = &fat_arches[index];
        if (ntohl(fat_arch->cputype) == kPreferredCpuType) {
            return ntohl(fat_arch->offset);
        }
    }
    fprintf(stderr, "No preferred slice\n");
    return -1;
}

static int 
remap_into_process(task_t target_task, void* executable_region,
                                     vm_address_t target_base, int executable_fd,
                                     off_t fat_offset) {
    struct mach_header_64* mh = executable_region;
    struct load_command* cmd = executable_region + sizeof(struct mach_header_64);
    kern_return_t err;

    for (unsigned int index = 0; index < mh->ncmds; index++) {
        switch (cmd->cmd) {
            case LC_SEGMENT_64: {
                struct segment_command_64* seg_cmd = (struct segment_command_64*)cmd;
                vm_address_t source_address =
                        (vm_address_t)(executable_region + seg_cmd->fileoff);

                if (!strncmp(seg_cmd->segname, "__PAGEZERO", sizeof(seg_cmd->segname))) {
                    target_base -= seg_cmd->vmsize;
                    goto next_loop;
                }
                if (seg_cmd->filesize == 0) {
                    goto next_loop;
                }
                if (executable_fd >= 0) {
                    void* remap = mmap(NULL, seg_cmd->filesize, seg_cmd->initprot, MAP_PRIVATE, executable_fd, fat_offset + seg_cmd->fileoff);
                    if (remap == MAP_FAILED) {
                        fprintf(stderr, "remap failed: %s\n", strerror(errno));
                        return 1;
                    }
                    source_address = (vm_address_t)remap;
                    if (seg_cmd->fileoff == 0) {
                        struct mach_header_64 *header = remap;
                        err = vm_protect(mach_task_self(), source_address, seg_cmd->filesize, true, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
                        if (err != KERN_SUCCESS) {
                            fprintf(stderr, "%dCan't protect into process: %s addr: %lx initprot %d size %llx\n",
                                    __LINE__, mach_error_string(err), 
                                    source_address, seg_cmd->initprot, seg_cmd->vmsize);
                            return 1;
                        }
                        err = vm_protect(mach_task_self(), source_address, seg_cmd->filesize, false, VM_PROT_READ | VM_PROT_WRITE);
                        if (err != KERN_SUCCESS) {
                            fprintf(stderr, "%dCan't protect into process: %s addr: %lx initprot %d size %llx\n",
                                    __LINE__, mach_error_string(err), 
                                    source_address, seg_cmd->initprot, seg_cmd->vmsize);
                            return 1;
                        }
                        if (header->magic == MH_MAGIC_64 && header->cputype == CPU_TYPE_ARM64 && (header->cpusubtype & CPU_SUBTYPE_ARM64E) == CPU_SUBTYPE_ARM64E && header->filetype == MH_EXECUTE) {
                            header->cpusubtype = 0;
                        }
                    }
                } else {
                    vm_address_t addr = 0;
                    kern_return_t kr = vm_allocate(mach_task_self(), &addr, seg_cmd->filesize, VM_FLAGS_ANYWHERE);
                    if (kr != KERN_SUCCESS) {
                        fprintf(stderr, "remap_into_process: vm_allocate %s\n", mach_error_string(kr));
                        return 1;
                    }
                    memcpy((void*)addr, executable_region + seg_cmd->fileoff, seg_cmd->filesize);
                    source_address = addr;
                }
                vm_address_t target_address = target_base + seg_cmd->vmaddr;
                vm_prot_t cur_protection;
                vm_prot_t max_protection;
                if (seg_cmd->filesize) {
                    err = vm_remap(target_task, &target_address, seg_cmd->filesize,
                                                 /*mask=*/0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                                                 mach_task_self(), source_address,
                                                 /*copy=*/false, &cur_protection, &max_protection,
                                                 VM_INHERIT_COPY);
                    if (err) {
                        fprintf(stderr, "Can't map into process: %s\n", mach_error_string(err));
                        return 1;
                    }
                }
                err = vm_protect(target_task, target_address, seg_cmd->vmsize, false, seg_cmd->initprot);
                if (err) {
                    fprintf(stderr, "Can't protect into process: %s addr: %lx initprot %d size %llx\n",
                                    mach_error_string(err), 
                                    target_address, seg_cmd->initprot, seg_cmd->vmsize);
                    return 1;
                }
                if (executable_fd >= 0) {
                    munmap((void*)source_address, seg_cmd->filesize);
                } else {
                    vm_deallocate(mach_task_self(), source_address, seg_cmd->filesize);
                }
                break;
            }
                // TODO(zhuowei): handle unixthread (we currently assume dylds have the
                // same unixthread)
        }
next_loop:
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    return 0;
}

static thread_t 
task_first_thread(task_t target_task) {
    kern_return_t err;
    thread_act_t* thread_array;
    mach_msg_type_number_t num_threads;
    err = task_threads(target_task, &thread_array, &num_threads);
    if (err) {
        fprintf(stderr, "Failed to get threads: %s\n", mach_error_string(err));
        return MACH_PORT_NULL;
    }
    return thread_array[0];
}

static vm_address_t 
set_entry_point(task_t target_task, vm_address_t entry_point) {
    kern_return_t err;
    vm_address_t ret = 0;
    thread_t main_thread = task_first_thread(target_task);
    if (main_thread == MACH_PORT_NULL) {
        return ret;
    }
#ifdef __x86_64__
    x86_thread_state64_t thread_state;
    mach_msg_type_number_t thread_state_count = x86_THREAD_STATE64_COUNT;
    err = thread_get_state(main_thread, x86_THREAD_STATE64,
                                                 (thread_state_t)&thread_state, &thread_state_count);
    if (err) {
        fprintf(stderr, "Failed to get thread state: %s\n", mach_error_string(err));
        goto end;
    }
    thread_state.__rip = entry_point;
    err = thread_set_state(main_thread, x86_THREAD_STATE64,
                                                 (thread_state_t)&thread_state, thread_state_count);
    if (err) {
        fprintf(stderr, "Failed to set thread state: %s\n", mach_error_string(err));
        goto end;
    }
    ret = thread_state.__rsp;
#elif __arm64__
    arm_thread_state64_t thread_state;
    mach_msg_type_number_t thread_state_count = ARM_THREAD_STATE64_COUNT;
    err = thread_get_state(main_thread, ARM_THREAD_STATE64,
                                                 (thread_state_t)&thread_state, &thread_state_count);
    if (err) {
        fprintf(stderr, "Failed to get thread state: %s\n", mach_error_string(err));
        goto end;
    }
    thread_state.__pc = entry_point;
    err = thread_set_state(main_thread, ARM_THREAD_STATE64,
                                                 (thread_state_t)&thread_state, thread_state_count);
    if (err) {
        fprintf(stderr, "Failed to set thread state: %s\n", mach_error_string(err));
        goto end;
    }
    ret = thread_state.__sp;
#endif
end:
    if (main_thread != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), main_thread);
    }
    return ret;
}

static vm_address_t 
dyld_all_images_address_ptr(task_t target_task) {
    kern_return_t err;
    // https://opensource.apple.com/source/dyld/dyld-195.6/unit-tests/test-cases/all_image_infos-cache-slide/main.c
    task_dyld_info_data_t task_dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    err = task_info(target_task, TASK_DYLD_INFO, (task_info_t)&task_dyld_info, &count);
    if (err) {
        fprintf(stderr, "Failed to get task info: %s\n", mach_error_string(err));
        return 0;
    }
    return task_dyld_info.all_image_info_addr;
}

static int 
prepare_dyld_map(const char *dyld_path, void **map, int *fd, off_t *dyld_fat_offset, size_t *dyld_map_size) {
    void *dyld_map = NULL;
    struct stat dyld_stat;
    int dyld_fd = -1;
    kern_return_t err = 0;
    if (dyld_path != NULL) {
        dyld_fd = open(dyld_path, O_RDONLY);
        if (FD_INVALID(dyld_fd)) {
            fprintf(stderr, "Can't open %s: %s", dyld_path, strerror(errno));
            err = 1;
            goto err;
        }
        if (fstat(dyld_fd, &dyld_stat)) {
            fprintf(stderr, "Can't stat %s: %s", dyld_path, strerror(errno));
            err = 1;
            goto err;
        }
        dyld_map = mmap(NULL, dyld_stat.st_size, PROT_READ, MAP_PRIVATE, dyld_fd, 0);
        if (dyld_map == MAP_FAILED) {
            fprintf(stderr, "Can't map %s: %s", dyld_path, strerror(errno));
            err = 1;
            goto err;
        }
    } else {
        size_t size;
        dyld_map = getsectiondata(&_mh_execute_header, "__DATA", "builtin_dyld", &size);
    }
    off_t fat_offset = get_fat_offset(dyld_map);
    if (fat_offset == -1) {
        err = 1;
        goto err;
    }
    *map = dyld_map;
    *fd = dyld_fd;
    *dyld_fat_offset = fat_offset;
    *dyld_map_size = dyld_stat.st_size;
    return 0;
err:
    if (FD_VALID(dyld_fd)) {
        if (dyld_map != MAP_FAILED) {
            munmap(dyld_map, dyld_stat.st_size);
        }
        close(dyld_fd);
    }
    return err;
}

#define EXECUTABLE_KEY "executable_path"
#define EXECUTABLE_KEY_LEN (sizeof(EXECUTABLE_KEY) - 1)

static int 
set_executable_path(task_t target_task, vm_address_t stack_ptr, const char *argv0) {
    int target_argc;
    vm_address_t target_argc_ptr = stack_ptr + 8;
    mach_vm_size_t sz;
    mach_vm_read_overwrite(target_task, target_argc_ptr, sizeof(target_argc), (vm_address_t)&target_argc, &sz);
    vm_address_t argv = stack_ptr + 16;
    vm_address_t envp = argv + (target_argc + 1) * sizeof(uintptr_t);
    vm_address_t apple_ptr = envp;

    uintptr_t apple = 0;
    mach_vm_read_overwrite(target_task, apple_ptr, sizeof(apple), (vm_address_t)&apple, &sz);
    while (apple != 0) {
        apple_ptr += 8;
        mach_vm_read_overwrite(target_task, apple_ptr, sizeof(apple), (vm_address_t)&apple, &sz);
    }
    apple_ptr += 8;

    mach_vm_read_overwrite(target_task, apple_ptr, sizeof(apple), (vm_address_t)&apple, &sz);

    for (vm_address_t p = apple_ptr; p != 0 && apple != 0; ) {
        const char buffer[MAXPATHLEN + EXECUTABLE_KEY_LEN];
        mach_vm_read_overwrite(target_task, apple, sizeof(buffer), (vm_address_t)buffer, &sz);
        
        size_t p_len = strlen(buffer);
        if (p_len >= EXECUTABLE_KEY_LEN && (memcmp(buffer, EXECUTABLE_KEY, EXECUTABLE_KEY_LEN) == 0) && buffer[EXECUTABLE_KEY_LEN] == '=') {
            kern_return_t kr = mach_vm_write(target_task, apple + EXECUTABLE_KEY_LEN + 1, (vm_offset_t)argv0, strlen(argv0) + 1);
            if (kr != KERN_SUCCESS) {
                fprintf(stderr, "overwriting ececutable_path failed: %s\n", mach_error_string(kr));
            }
            return 0;
        }
        p += 8;
        mach_vm_read_overwrite(target_task, p, sizeof(apple), (vm_address_t)&apple, &sz);
    }

    return 0;
}

int map_dyld_and_main_executable(int target_pid, const char *dyld_path, const char *argv0, int fd, void *exe_map, size_t map_size) {
    task_t target_task = MACH_PORT_NULL;
    kern_return_t err = 0;
    int dyld_fd = -1;
    err = task_for_pid(mach_task_self(), target_pid, &target_task);
    if (err) {
        fprintf(stderr, "Failed to get task port: %s\n", mach_error_string(err));
        err = 1;
        goto err;
    }
    void *dyld_map = MAP_FAILED;
    size_t dyld_size = 0;
    off_t fat_offset = 0;
    if (prepare_dyld_map(dyld_path, &dyld_map, &dyld_fd, &fat_offset, &dyld_size) != 0) {
        err = 0;
        goto err;
    }
    void* dyld_executable_map = dyld_map + fat_offset;

    size_t new_dyld_all_images_offset = 0;
    size_t sigcmd_dataoff = 0;
    size_t sigcmd_datasize = 0;
    size_t address_space_size = get_execute_address_space_size(dyld_executable_map, &new_dyld_all_images_offset, &sigcmd_dataoff, &sigcmd_datasize);
    if (!new_dyld_all_images_offset) {
        fprintf(stderr, "can't find all images\n");
        err = 1;
        goto err;
    }

    if (dyld_fd >= 0) {
        fsignatures_t siginfo;
        siginfo.fs_file_start = fat_offset;  // start of mach-o slice in fat file
        siginfo.fs_blob_start =
                (void*)(sigcmd_dataoff);             // start of CD in mach-o file
        siginfo.fs_blob_size = sigcmd_datasize;  // size of CD
        if (fcntl(dyld_fd, F_ADDFILESIGS_RETURN, &siginfo) == -1) {
            fprintf(stderr, "can't add signatures: %s\n", strerror(errno));
            err = 1;
            goto err;
        }
    }

    vm_address_t dyld_target_address = dyld_all_images_address_ptr(target_task) - new_dyld_all_images_offset;
    if (!dyld_target_address) {
        err = 1;
        goto err;
    }
    //fprintf(stderr, "mapping dyld at %p\n", (void*)dyld_target_address);
    err = vm_allocate(target_task, &dyld_target_address, address_space_size, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE);
    if (err) {
        fprintf(stderr, "Can't allocate into process: %s\n",
                        mach_error_string(err));
        err = 1;
        goto err;
    }
    if (remap_into_process(target_task, dyld_map + fat_offset, dyld_target_address, dyld_fd, fat_offset)) {
        err = 1;
        goto err;
    }
    vm_address_t stack_ptr = set_entry_point(target_task, dyld_target_address + 0x1000);
    if (stack_ptr == 0) {
        fprintf(stderr, "failed to get main execute address\n");
        err = 1;
        goto err;
    }
    vm_address_t target_main_execute;
    
    size_t exe_sigcmd_dataoff = 0;
    size_t exe_sigcmd_datasize = 0;
    off_t main_offset = get_fat_offset(exe_map);
    if (main_offset == -1) {
        err = 1;
        goto err;
    }
    size_t exe_space_size = get_execute_address_space_size(exe_map + main_offset, NULL, &exe_sigcmd_dataoff, &exe_sigcmd_datasize);

    err = vm_allocate(target_task, &target_main_execute, exe_space_size, VM_FLAGS_ANYWHERE);
    if (err) {
        fprintf(stderr, "Can't allocate main execute into process: %s\n",
                        mach_error_string(err));
        err = 1;
        goto err;
    }
    //fprintf(stderr, "main execute address: %lx size: %lx\n", target_main_execute, exe_space_size);
    uintptr_t tmp = (uintptr_t)target_main_execute;
    set_executable_path(target_task, stack_ptr, argv0);
    mach_vm_write(target_task, stack_ptr, (vm_offset_t)&tmp, sizeof(tmp));
    if (remap_into_process(target_task, exe_map + main_offset, target_main_execute, fd, main_offset)) {
        err = 1;
        goto err;
    }
err:
    if (target_task != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), target_task);
    }
    if (dyld_fd >= 0) {
        if (dyld_map != NULL) {
            munmap(dyld_map, dyld_size);
        }
        close(dyld_fd);
    }
    return err;
}

int map_dyld(int target_pid, const char* dyld_path) {
    task_t target_task = MACH_PORT_NULL;
    kern_return_t err = 0;
    int dyld_fd = -1;

    err = task_for_pid(mach_task_self(), target_pid, &target_task);
    if (err || target_task == MACH_PORT_NULL) {
        fprintf(stderr, "Failed to get task port: %s\n", mach_error_string(err));
        err = 1;
        goto err;
    }
    void *dyld_map = MAP_FAILED;
    size_t dyld_size = 0;
    off_t fat_offset = 0;
    if (prepare_dyld_map(dyld_path, &dyld_map, &dyld_fd, &fat_offset, &dyld_size) != 0) {
        err = 0;
        goto err;
    }

    void* executable_map = dyld_map + fat_offset;
    size_t new_dyld_all_images_offset = 0;
    size_t sigcmd_dataoff = 0;
    size_t sigcmd_datasize = 0;
    size_t address_space_size = get_execute_address_space_size(executable_map, &new_dyld_all_images_offset, &sigcmd_dataoff, &sigcmd_datasize);
    if (!new_dyld_all_images_offset) {
        fprintf(stderr, "can't find all images\n");
        err = 1;
        goto err;
    }
    // ImageLoaderMachO::loadCodeSignature, Loader::mapImage
    if (dyld_fd >= 0) {
        fsignatures_t siginfo;
        siginfo.fs_file_start = fat_offset;  // start of mach-o slice in fat file
        siginfo.fs_blob_start =
                (void*)(sigcmd_dataoff);             // start of CD in mach-o file
        siginfo.fs_blob_size = sigcmd_datasize;  // size of CD
        if (fcntl(dyld_fd, F_ADDFILESIGS_RETURN, &siginfo) == -1) {
            fprintf(stderr, "can't add signatures: %s\n", strerror(errno));
            err = 1;
            goto err;
        }
    }
    // TODO(zhuowei): this _only_ works if ASLR is enabled
    // (since we try to align the image infos of the new dyld on top of the old,
    // and that would overwrite the executable if ASLR is off and dyld is right
    // behind the executable) at least detect if we would overwrite an existing
    // mapping...
    vm_address_t target_address = dyld_all_images_address_ptr(target_task) - new_dyld_all_images_offset;
    if (!target_address) {
        err = 1;
        goto err;
    }
    //fprintf(stderr, "mapping dyld at %p\n", (void*)target_address);
    err = vm_allocate(target_task, &target_address, address_space_size, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE);
    if (err) {
        fprintf(stderr, "Can't allocate into process: %s\n",
                        mach_error_string(err));
        err = 1;
        goto err;
    }
    if (remap_into_process(target_task, executable_map + fat_offset, target_address, dyld_fd, fat_offset)) {
        err = 1;
        goto err;
    }
    // TODO(zhuowei): grab entry point from unixthread
    if (!set_entry_point(target_task, target_address + 0x1000)) {
        err = 1;
        goto err;
    }
err:
    if (target_task != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), target_task);
    }
    if (dyld_fd >= 0) {
        if (dyld_map != NULL) {
            munmap(dyld_map, dyld_size);
        }
        close(dyld_fd);
    }
    return err;
}
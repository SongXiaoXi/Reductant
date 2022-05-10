#include <errno.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <mach-o/loader.h>
#include <sys/stat.h>
#include <mach-o/fat.h>
#include <sys/mman.h>
#include "reductant.h"

extern char** environ;

extern int map_dyld(int target_pid, const char* dyld_path);

pid_t 
littlespawn(char *const argv[], short posix_spawn_flag) {
    // https://github.com/coolstar/electra/issues/53#issuecomment-359287851
    posix_spawnattr_t attr;
    if (getenv("RT_DYLD_SHARED_CACHE_DIR")) {
        setenv("DYLD_SHARED_CACHE_DIR", getenv("RT_DYLD_SHARED_CACHE_DIR"), 1);
    } else {
        if (access("/System/macOSSupport/dyld/dyld_shared_cache_arm64e", F_OK) == 0) {
            setenv("DYLD_SHARED_REGION", "private", 1);
            setenv("DYLD_SHARED_CACHE_DIR", "/System/macOSSupport/dyld", 1);
        }
        if (access("/System/macOSSupport/", F_OK) == 0) {
            setenv("DYLD_ROOT_PATH", "/System/macOSSupport/", 1);
        }
    }
    if (getenv("RT_DYLD_INSERT_LIBRARIES")) {
        setenv("DYLD_INSERT_LIBRARIES", getenv("RT_DYLD_INSERT_LIBRARIES"), 1);
    } else {
        if (access("/System/macOSSupport/usr/lib/rt_hooker.dylib", F_OK) == 0) {
            setenv("DYLD_INSERT_LIBRARIES", "/System/macOSSupport/usr/lib/rt_hooker.dylib", 1);
        }
    }
    if (getenv("RT_DYLD_ROOT_PATH")) {
        setenv("DYLD_ROOT_PATH", getenv("RT_DYLD_ROOT_PATH"), 1);
    }
    char *buffer;
    const char *path = argv[0];
    int fd = open(path, O_RDONLY);
    struct stat exec_stat;

    if (fd >= 0) {
        if (fstat(fd, &exec_stat)) {
            goto exec;
        }
        buffer = mmap(NULL, exec_stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (buffer == MAP_FAILED) {
            goto exec;
        }

        struct mach_header_64 *header = (struct mach_header_64 *)buffer;
        if ((exec_stat.st_size >= sizeof(*header) && header->magic == MH_MAGIC_64 && header->cputype == CPU_TYPE_ARM64 && (header->cpusubtype & CPU_SUBTYPE_ARM64E) == CPU_SUBTYPE_ARM64E && header->filetype == MH_EXECUTE) || getenv("RT_FORCE_ARM64_RUNNER")) {
arm64e:
            path = getenv("RT_ARM64_RUNNER_PATH");
            if (path == NULL) {
                path = "/System/macOSSupport/usr/libexec/arm64_runner";
            }
        } else {
            struct fat_header *fat_header = (struct fat_header *)buffer;
            if (fat_header->magic == FAT_CIGAM) {
                struct fat_arch* fat_arches = (void*)buffer + sizeof(struct fat_header);
                bool has_arm64e = false;
                for (unsigned int index = 0; index < ntohl(fat_header->nfat_arch); index++) {
                    struct fat_arch* fat_arch = &fat_arches[index];
                    if (ntohl(fat_arch->cputype) == CPU_TYPE_ARM64) {
                        if ((ntohl(fat_arch->cpusubtype) & CPU_SUBTYPE_ARM64E) == CPU_SUBTYPE_ARM64E) {
                            has_arm64e = true;
                        } else {
                            goto has_arm64;
                        }
                    }
                }
                if (has_arm64e) {
                    goto arm64e;
                }
            }
has_arm64:
            close(fd);
            fd = -1;
        }
    }
exec:
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, posix_spawn_flag);
    pid_t child;
    int ret = posix_spawnp(&child, path, NULL, &attr, &argv[0], environ);
    posix_spawnattr_destroy(&attr);
    if (ret) {
        fprintf(stderr, "failed to exec %s: %s\n", argv[0], strerror(ret));
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }
    if (fd >= 0) {
        map_dyld_and_main_executable(child, getenv("RT_DYLD_PATH"), argv[0], fd, buffer, exec_stat.st_size);
        munmap(buffer, exec_stat.st_size);
        close(fd);
    } else {
        map_dyld(child, getenv("RT_DYLD_PATH"));
    }
    return child;
}

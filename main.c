#include <unistd.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <mach/mach.h>
#include <mach-o/arch.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>

#if __arm64e__
#define __RT_arm64e__ true
#elif __arm64__
#define __RT_arm64e__ ({const NXArchInfo *info = NXGetLocalArchInfo(); info->cputype == CPU_TYPE_ARM64 && (info->cpusubtype & CPU_SUBTYPE_ARM64E) == CPU_SUBTYPE_ARM64E;})
#endif

extern int map_dyld(int target_pid, const char* dyld_path);
extern int map_dyld_and_main_executable(int target_pid, const char *dyld_path, int fd);
extern pid_t littlespawn(char *const argv[], short posix_spawn_flag);
extern int translator(task_t p);
extern void translator_loop(mach_port_t port);

static void *
translator_subthread(void *arg) {
    pid_t p = *(pid_t*)arg;
    task_t child;
    kern_return_t err;
    err = task_for_pid(mach_task_self(), p, &child);
    if (err != KERN_SUCCESS) {
        fprintf(stderr, "translator: task_for_pid: %s\n", mach_error_string(err));
        return MACH_PORT_NULL;
    }
    mach_port_t port = translator(child);
    kill(*(pid_t*)arg, SIGCONT);
    if (port != MACH_PORT_NULL) {
        translator_loop(port);
    }
    return NULL;
}

static pid_t pid;

static void 
signal_handle(int signo) {
    kill(pid, signo);
}

int inject(pid_t pid, const char *lib);

int main(int argc, char *const argv[]) {
    if (argc == 1) {
        fprintf(stderr, "bad arguments\n");
        return -1;
    }
    pid = littlespawn(&argv[1], POSIX_SPAWN_START_SUSPENDED);
    if (pid < 0) {
        return -1;
    }

    signal(SIGINT, signal_handle);
    signal(SIGTERM, signal_handle);
    signal(SIGHUP, signal_handle);
    signal(SIGQUIT, signal_handle);
    signal(SIGSTOP, signal_handle);
    signal(SIGCONT, signal_handle);
    signal(SIGTSTP, signal_handle);
    signal(SIGTTIN, signal_handle);
#if __arm64__
    if (!__RT_arm64e__) {
        pthread_t pth;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, 1);
        pthread_create(&pth, &attr, translator_subthread, (void*)&pid);
    } else {
        kill(pid, SIGCONT);
    }
#endif
    int status;
    if (waitpid(pid, &status, 0) != -1) {
        return status;
    } else {
        fprintf(stderr, "waitpid: %s\n", strerror(errno));
    }
    return 0;
}
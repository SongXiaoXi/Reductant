#include <string.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <mach/mach_port.h>
#include <mach/mach.h>
#include <mach/mach_time.h>

typedef const void *MSImageRef;

MSImageRef MSGetImageByName(const char *file);
void *MSFindSymbol(MSImageRef image, const char *name);

void MSHookFunction(void *symbol, void *replace, void **result);

int sysctlbyname(const char *, void *, size_t *, void *, size_t);

static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);

int translator(task_t t);
extern void translator_loop(mach_port_t port);

extern void *translator_subthread(void *arg);

static int 
new_sysctlbyname(const char *name, void *oldp, size_t *oldenp, void *newp, size_t newlen) {
    if (name != NULL && oldp != NULL && (strcmp(name, "kern.osvariant_status") == 0)) {
        *(unsigned long long *)oldp = 0x70010000f388828a;
        return 0;
    }
    return orig_sysctlbyname(name, oldp, oldenp, newp, newlen);
}

void *IOServiceMatching(const char *name);
static void *(*orig_IOServiceMatching)(const char *name);
static void *new_IOServiceMatching(const char *name) {
    if (strcmp("IOSurfaceRoot", name) == 0) {
        static const char tmp[] = "IOCoreSurfaceRoot";
        return orig_IOServiceMatching(tmp);
    } else if (strcmp("IOAccelerator", name) == 0) {
        static const char tmp[] = "IOAcceleratorES";
        return orig_IOServiceMatching(tmp);
    }
    return orig_IOServiceMatching(name);
}

void *IOServiceNameMatching(const char *name);
static void *(*orig_IOServiceNameMatching)(const char *name);
static void *new_IOServiceNameMatching(const char *name) {
    if (strcmp("IOSurfaceRoot", name) == 0) {
        static const char tmp[] = "IOCoreSurfaceRoot";
        return orig_IOServiceNameMatching(tmp);
    } else if (strcmp("IOAccelerator", name) == 0) {
        static const char tmp[] = "IOAcceleratorES";
        return orig_IOServiceNameMatching(tmp);
    }
    return orig_IOServiceNameMatching(name);
}

extern mach_port_t mach_thread_self(void);

static void __attribute__((constructor))
$ctor(void) {
    MSHookFunction(sysctlbyname, new_sysctlbyname, (void**)&orig_sysctlbyname);
    MSHookFunction(IOServiceMatching, new_IOServiceMatching, (void**)&orig_IOServiceMatching);
    MSHookFunction(IOServiceNameMatching, new_IOServiceNameMatching, (void**)&orig_IOServiceNameMatching);
    // iOS 14 and above use modern mach_continuous_time.
    // If this binary is linked with macOS dynamic libraries, the version checked here is macOS 14.
    if (__builtin_available(macOS 14, iOS 14, *)) {
    } else {
        if (!getenv("RT_EMULATE_TIME")) {
            uint64_t mach_continuous_time_iOS13(void);
            MSHookFunction(mach_continuous_time, mach_continuous_time_iOS13, NULL);
        }
    }
    if (!getenv("RT_OUT_OF_PROCESS")) {
        pthread_t pth;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, 1);
        pthread_create(&pth, &attr, (void*)translator_subthread, NULL);
    }
}
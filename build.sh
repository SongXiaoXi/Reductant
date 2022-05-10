#!/bin/bash

set -e

rm -rf mach
mkdir mach
pushd mach 
mig -arch arm64 -DXNU_KERNEL_PRIVATE $(xcrun -sdk macosx --show-sdk-path)/usr/include/mach/mach_exc.defs
mig -arch arm64 -DXNU_KERNEL_PRIVATE $(xcrun -sdk macosx --show-sdk-path)/usr/include/mach/task.defs
mig -arch arm64 -DXNU_KERNEL_PRIVATE $(xcrun -sdk macosx --show-sdk-path)/usr/include/mach/mach_port.defs
mig -arch arm64 -DXNU_KERNEL_PRIVATE $(xcrun -sdk macosx --show-sdk-path)/usr/include/mach/mach_vm.defs
mig -arch arm64 -DXNU_KERNEL_PRIVATE $(xcrun -sdk macosx --show-sdk-path)/usr/include/mach/thread_act.defs
mig -arch arm64 -DXNU_KERNEL_PRIVATE $(xcrun -sdk macosx --show-sdk-path)/usr/include/mach/vm_map.defs
popd

clang -O3 -std=gnu11 -flto -target arm64-apple-ios7.0 -Wall \
	-isysroot "$(xcrun -sdk iphoneos --show-sdk-path)" \
	-o rt_spawn \
	littlespawn.c main.c dyldloader.c translator.c mach/mach_excServer.c -mcpu=apple-a7 -Wl,-sectcreate,__DATA,builtin_dyld,dyld
strip rt_spawn
ldid -Sent.xml rt_spawn
echo build hooker
hooker_sdk=iphoneos 
if [ x$hooker_sdk == xiphoneos ]
then
	libinject=CydiaSubstrate.tbd
else
	libinject=libsubstitute.dylib
fi

enable_dobby_hook=true 
if [ x$enable_dobby_hook == xtrue ]
then 
	CFLAGS="libmimalloc.a DobbyX -lc++ -DENABLE_DOBBY_HOOK=1"
else
	CFLAGS=""
fi

clang -O3 -std=gnu11 -flto -march=armv8-a -target arm64-apple-ios9.0 -Wall \
	-isysroot "$(xcrun -sdk $hooker_sdk --show-sdk-path)" \
	-o rt_hooker.dylib \
	hooker.c translator.c mach/mach_excServer.c libSystem/syscall.s libSystem/syscall.c mach/mach_vmUser.c mach/mach_portUser.c libSystem/libc.c mach/vm_mapUser.c mach/taskUser.c mach/thread_actUser.c libSystem/mach_time_legacy.c -DIN_PROCESS=1 -shared $libinject -fno-stack-check -fno-stack-protector -D_FORTIFY_SOURCE=0 -mcpu=apple-a7 -framework IOKit $CFLAGS
ldid -S rt_hooker.dylib

as arm64_runner.s -o arm64_runner.o -target arm64-apple-ios7.0 -isysroot "$(xcrun -sdk $hooker_sdk --show-sdk-path)"
ld -o arm64_runner arm64_runner.o -syslibroot "$(xcrun -sdk $hooker_sdk --show-sdk-path)" -e __mh_execute_header -lSystem -arch arm64 -platform_version ios 7.0.0 7.0.0 -dead_strip_dylibs
rm arm64_runner.o
strip arm64_runner
ldid -S arm64_runner
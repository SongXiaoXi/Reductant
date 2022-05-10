# Reductant Translator
**Translate and patch arm64e binaries or macOS arm64 binaries to run on an arm64 iPhones at runtime.**

As Macs move to ARM, there are many official command-line tools from Apple, Homebrew or others. But the instructions in these binaries are at least ARMv8.3+ since the first arm Mac was based on A12z.
You can run these utilities directly on arm64e iDevices, if there are dependent libraries on iOS. If not, it's this tool's turn:

- If your iDevice is arm64, you can run them with this tool.
- If your binaries are linked with macOS frameworks, you can run them with this tool and a dyld_shared_caches_arm64e from macOS.

You can replace **these binaries provided by me**:
- A patched dyld from macOS 11.4.
- A customized [Dobby](https://github.com/jmpews/Dobby) Framework.
- [mimalloc.a](https://github.com/microsoft/mimalloc) built for arm64 iOS.

## Build options in `build.sh`

- enable_dobby_hook Use a custom [Dobby Framework](https://github.com/jmpews/Dobby) to optimize a (CAS + B) sequence. This obviously improve performance. 

Requirements: Xcode 12 or later.

## Environment variables

- `RT_OUT_OF_PROCESS=[whatever]` Do not inject threads in target process.
- `RT_EMULATE_TIME=[whatever]` Do not hook mach_continuous_time.
- `RT_DYLD_SHARED_CACHE_DIR=[path to dyld_share_cache]` Specify the dyld_share_cache path. It defaults to "/System/macOSSupport/dyld" if exists. Otherwise use the system one.
- `RT_DYLD_INSERT_LIBRARIES=[libraries to insert]` Pass this env to dyld as `DYLD_INSERT_LIBRARIES`. Default is `/System/macOSSupport/usr/lib/rt_hooker.dylib` to support in-process translating and hooking, and other necessary patches.
- `RT_DYLD_ROOT_PATH=[libraries to insert]` Pass this env to dyld as `DYLD_ROOT_PATH`.
- `RT_ARM64_RUNNER_PATH=[path to a binary]` Creating a process with a arm64 binary. Then map the real binary arm64e default) into this process.
- `RT_FORCE_ARM64_RUNNER=[whatever]` Creating a process with a arm64 binary. Then force map the real binary into this process. (arm64e only runs in this mode.)
- `RT_DYLD_PATH=[dyld path]` Dyld path, default use a builtin dyld.
- `RT_DISABLE_DOBBY_HOOK=[whatever]` Disable dobby hook if the build option `enable_dobby_hook` is enabled.

The detail behaviors can be easly gotten in codes.

## Known issues

- NSURLSession will get a `kCFURLErrorCannotFindHost` error with macOS 11 dyld_shared_cache on iOS 13. (iOS 14 is OK.)
- Metal is not available except A12z or M1 iPad due to missing binary for `/System/Library/Extensions/AGXMetalxxx` in dyld_shared_cache. (I have not tested these iPad, maybe Metal parallel computing works.)
- `fork()` and `spawn()` is not work properly which means you can not use bash/zsh or other utilities depended on them from macOS. (This can be fixed by hooking.)
- Some libproc-based (such as `proc_pidinfo(PROC_PIDPATHINFO)`) processes viewer will only treat `arm64_runner` as the process executable. This cannot be fixed because XNU uses the vnode of the executable when `spawn()`.
- Code signing issues are dependent on your jailbreak tools.
- A bad mach-o may crash this tool.

## Example 

``` sh
mobile@iPhone-7-Plus ~ % ./rt_spawn ./geekbench_aarch64
Geekbench 5.4.2 Corporate : https://www.geekbench.com/

System Information
  Operating System              macOS 14.8 (Build 18H17)
  Model                         D11AP
  Model ID                      D11AP
  Motherboard                   D11AP

Processor Information
  Name                          Apple processor
  Topology                      1 Processor, 2 Cores
  Identifier                    Apple processor
  Base Frequency                2.33 GHz
  L1 Instruction Cache          64.0 KB
  L1 Data Cache                 64.0 KB
  L2 Cache                      3.00 MB

Memory Information
  Size                          2.93 GB


Single-Core
  AES-XTS                        1121              1.91 GB/sec
  Text Compression                682              3.45 MB/sec
  Image Compression               744         35.2 Mpixels/sec
  Navigation                      727             2.05 MTE/sec
  HTML5                           724      849.8 KElements/sec
  SQLite                          806          252.6 Krows/sec
  PDF Rendering                   112         6.07 Mpixels/sec
  Text Rendering                  824             262.7 KB/sec
  Clang                           673          5.24 Klines/sec
  Camera                          760          8.82 images/sec
  N-Body Physics                  413         517.1 Kpairs/sec
  Rigid Body Physics              836               5181.6 FPS
  Gaussian Blur                   598         32.9 Mpixels/sec
  Face Detection                  896          6.90 images/sec
  Horizon Detection               990         24.4 Mpixels/sec
  Image Inpainting               1159         56.8 Mpixels/sec
  HDR                            1276         17.4 Mpixels/sec
  Ray Tracing                     934        750.1 Kpixels/sec
  Structure from Motion           608         5.45 Kpixels/sec
  Speech Recognition              545           17.4 Words/sec
  Machine Learning                 66          2.54 images/sec

Multi-Core
  AES-XTS                        1963              3.35 GB/sec
  Text Compression               1097              5.55 MB/sec
  Image Compression              1371         64.8 Mpixels/sec
  Navigation                     1222             3.44 MTE/sec
  HTML5                          1299       1.53 MElements/sec
  SQLite                         1438          450.7 Krows/sec
  PDF Rendering                   177         9.60 Mpixels/sec
  Text Rendering                 1455             463.5 KB/sec
  Clang                          1103          8.59 Klines/sec
  Camera                         1340          15.5 images/sec
  N-Body Physics                  723         904.0 Kpairs/sec
  Rigid Body Physics             1496               9268.8 FPS
  Gaussian Blur                  1058         58.2 Mpixels/sec
  Face Detection                 1623          12.5 images/sec
  Horizon Detection              1771         43.6 Mpixels/sec
  Image Inpainting               1852         90.9 Mpixels/sec
  HDR                            2336         31.8 Mpixels/sec
  Ray Tracing                    1721         1.38 Mpixels/sec
  Structure from Motion          1082         9.69 Kpixels/sec
  Speech Recognition              832           26.6 Words/sec
  Machine Learning                118          4.55 images/sec

Benchmark Summary
  Single-Core Score              634
    Crypto Score                  1121
    Integer Score                  601
    Floating Point Score           623
  Multi-Core Score              1095
    Crypto Score                  1963
    Integer Score                 1030
    Floating Point Score          1091

Upload results to the Geekbench Browser? [Y/n]
```

## Credits
- [iOS-run-macOS-executables-tools](https://github.com/zhuowei/iOS-run-macOS-executables-tools) for the idea and some implementation details.
- [Dobby](https://github.com/jmpews/Dobby) for the idea of single instruction hook.

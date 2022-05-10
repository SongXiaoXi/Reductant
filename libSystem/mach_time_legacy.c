#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>
#include <mach/mach_time.h>

#define USER_TIMEBASE_NONE   0
#define USER_TIMEBASE_SPEC   1
#define USER_TIMEBASE_NOSPEC 2

#define _COMM_PAGE64_BASE_ADDRESS               (0x0000000FFFFFC000ULL) /* In TTBR0 */
#define _COMM_PAGE_START_ADDRESS                (_COMM_PAGE64_BASE_ADDRESS)
#define _COMM_PAGE_CONT_HW_TIMEBASE             (_COMM_PAGE_START_ADDRESS+0x0A8)        // uint64_t base for mach_continuous_time() relative to CNT[PV]CT
#define _COMM_PAGE_CONT_TIMEBASE                (_COMM_PAGE_START_ADDRESS+0x098)        // uint64_t base for mach_continuous_time() relative to mach_absolute_time()
#define _COMM_PAGE_CONT_HWCLOCK                 (_COMM_PAGE_START_ADDRESS+0x091)        // uint8_t is always-on hardware clock present for mach_continuous_time()
#define _COMM_PAGE_USER_TIMEBASE                (_COMM_PAGE_START_ADDRESS+0x090)        // uint8_t is userspace mach_absolute_time supported (can read the timebase)

uint64_t
_mach_continuous_time_base(void)
{
#if !defined(__x86_64__) && !defined(__arm64__)
	// Deal with the lack of 64-bit loads on arm32 (see mach_approximate_time.s)
	while (1) {
		volatile uint64_t *base_ptr = (volatile uint64_t*)_COMM_PAGE_CONT_TIMEBASE;
		uint64_t read1, read2;
		read1 = *base_ptr;
#if defined(__arm__)
		__asm__ volatile ("dsb sy" ::: "memory");
#elif defined(__i386__)
		__asm__ volatile ("lfence" ::: "memory");
#else
#error "unsupported arch"
#endif
		read2 = *base_ptr;

		if (__builtin_expect((read1 == read2), 1)) {
			return read1;
		}
	}
#else // 64-bit
	return *(volatile uint64_t*)_COMM_PAGE_CONT_TIMEBASE;
#endif // 64-bit
}

#if 0
// CNTVCT_EL0 is enabled in iOS 14 above and macOS 11 above.
#define CNTVCTSS_EL0 "S3_3_c14_c0_6"

__attribute__((visibility("hidden")))
kern_return_t
_mach_continuous_hwclock(uint64_t *cont_time __unused)
{
#if defined(__arm64__)
#define ISB_SY          0xf
	uint8_t cont_hwclock = *((uint8_t*)_COMM_PAGE_CONT_HWCLOCK);
	if (cont_hwclock) {
		volatile uint64_t *base_ptr = (volatile uint64_t*)_COMM_PAGE_CONT_HW_TIMEBASE;

		boolean_t has_cntvctss_el0 = *((uint8_t*)_COMM_PAGE_USER_TIMEBASE) == USER_TIMEBASE_NOSPEC;
		if (has_cntvctss_el0) {
			*cont_time = __builtin_arm_rsr64(CNTVCTSS_EL0) + *base_ptr;
			return KERN_SUCCESS;
		}


		__builtin_arm_isb(ISB_SY);
		*cont_time = __builtin_arm_rsr64("CNTVCT_EL0") + *base_ptr;
		return KERN_SUCCESS;
	}
#endif
	return KERN_NOT_SUPPORTED;
}
#else
__attribute__((visibility("hidden")))
kern_return_t
_mach_continuous_hwclock(uint64_t *cont_time __unused)
{
#if defined(__arm64__)
#define ISB_SY          0xf
	uint8_t cont_hwclock = *((uint8_t*)_COMM_PAGE_CONT_HWCLOCK);
	if (cont_hwclock) {
		__builtin_arm_isb(ISB_SY);
		*cont_time = __builtin_arm_rsr64("CNTPCT_EL0");
		return KERN_SUCCESS;
	}
#endif
	return KERN_NOT_SUPPORTED;
}
#endif

__attribute__((visibility("hidden")))
kern_return_t
_mach_continuous_time(uint64_t* absolute_time, uint64_t* cont_time)
{
	volatile uint64_t *base_ptr = (volatile uint64_t*)_COMM_PAGE_CONT_TIMEBASE;
	volatile uint64_t read1, read2;
	volatile uint64_t absolute;

	do {
		read1 = *base_ptr;
		absolute = mach_absolute_time();
#if     defined(__arm__) || defined(__arm64__)
		/*
		 * mach_absolute_time() contains an instruction barrier which will
		 * prevent the speculation of read2 above this point, so we don't
		 * need another barrier here.
		 */
#endif
		read2 = *base_ptr;
	} while (__builtin_expect((read1 != read2), 0));

	if (absolute_time) {
		*absolute_time = absolute;
	}
	if (cont_time) {
		*cont_time = absolute + read1;
	}

	return KERN_SUCCESS;
}

uint64_t
mach_continuous_time_iOS13(void)
{
	uint64_t cont_time;
	if (_mach_continuous_hwclock(&cont_time) != KERN_SUCCESS) {
		_mach_continuous_time(NULL, &cont_time);
	}
	return cont_time;
}
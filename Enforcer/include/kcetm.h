/*
 * kcetm
 * Kernel code execution time measurement
 * May 12, 2018
 * root@davejingtian.org
 * http://davejingtian.org
 */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/timekeeping.h>
#include <linux/time64.h>
#include <linux/string.h>
#include <linux/timex.h>
#include <linux/irqflags.h>
#include <linux/preempt.h>
#include <linux/time.h>


#define KCETM_MS				0
#define KCETM_NS				1
#define KCETM_TSC				2
#define KCETM_SUB_TV(s,e)			\
	((e.tv_sec*USEC_PER_SEC+e.tv_usec) - 	\
	(s.tv_sec*USEC_PER_SEC+s.tv_usec))
#define KCETM_SUB_TS(s,e)			\
	((e.tv_sec*NSEC_PER_SEC+e.tv_nsec) -	\
	(s.tv_sec*NSEC_PER_SEC+s.tv_nsec))

struct kcetm_perf_time {
	//struct timeval start_tv;
	//struct timeval end_tv;
	struct timespec64 start_ts;
	struct timespec64 end_ts;
	u64 start_tsc;
	u64 end_tsc;
	unsigned long flags;
	u64 start_tsc_high;
	u64 start_tsc_low;
	u64 end_tsc_high;
	u64 end_tsc_low;
};

/* Change the perf option here */
static int kcetm_perf_option = 2;

/* Perf helpers */
static inline void perf_start(struct kcetm_perf_time *t)
{
	switch (kcetm_perf_option) {
	case KCETM_MS:
	//	do_gettimeofday(&t->start_tv);
		break;
	case KCETM_NS:
	//	getnstimeofday64(&t->start_ts);
		break;
	case KCETM_TSC:
		preempt_disable();
		raw_local_irq_save(t->flags);
		asm volatile ("cpuid\n\t"
			"rdtsc\n\t"
			"mov %%rdx, %0\n\t"
			"mov %%rax, %1\n\t"
			: "=r" (t->start_tsc_high), "=r" (t->start_tsc_low)
			:: "%rax", "%rbx", "%rcx", "%rdx");
		break;
	default:
		pr_err("kcetm: not supported perf option\n");
		break;
	}
}

static inline unsigned long long perf_end(struct kcetm_perf_time *t)
{
	switch (kcetm_perf_option) {
	case KCETM_MS:
		//do_gettimeofday(&t->end_tv);
		//return KCETM_SUB_TV((t->start_tv), (t->end_tv));
		return 0;
	case KCETM_NS:
		//getnstimeofday64(&t->end_ts);
		
		//return KCETM_SUB_TS((t->start_ts), (t->end_ts));
		return 0;
	case KCETM_TSC:
		asm volatile ("rdtscp\n\t"
			"mov %%rdx, %0\n\t"
			"mov %%rax, %1\n\t"
			"cpuid\n\t"
			: "=r" (t->end_tsc_high), "=r" (t->end_tsc_low)
			:: "%rax", "%rbx", "%rcx", "%rdx");
		raw_local_irq_restore(t->flags);
		preempt_enable();
		/* Merge the high and low */
		t->start_tsc = ((u64)t->start_tsc_high << 32 | t->start_tsc_low);
		t->end_tsc = ((u64)t->end_tsc_high << 32 | t->end_tsc_low);
		return ((t->end_tsc)-(t->start_tsc));
	default:
		pr_err("kcetm: not supported perf option\n");
		return 0;
	}
}

static inline unsigned long long tsc_to_ns(unsigned long long cycles)
{
	return cycles*1000000/tsc_khz;
}

static inline void perf_print(unsigned long long diff)
{
	switch (kcetm_perf_option) {
	case KCETM_MS:
		pr_info("kcetm: %s took [%llu] us\n", __func__, diff);
		break;
	case KCETM_NS:
		pr_info("kcetm: %s took [%llu] ns\n", __func__, diff);
		break;
	case KCETM_TSC:
		pr_info("kcetm: %s took [%llu] cycles ([%llu] ns),tsc_khz is %llu\n",
			__func__, diff, tsc_to_ns(diff),tsc_khz);
		break;
	default:
		pr_err("kcetm: not supported perf option\n");
		break;
	}
}

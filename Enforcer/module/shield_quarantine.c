// SPDX-License-Identifier: GPL-2.0
/*
 * KASAN quarantine.
 *
 * Author: Alexander Potapenko <glider@google.com>
 * Copyright (C) 2016 Google, Inc.
 *
 * Based on code by Dmitry Chernenkov.
 */

#include <linux/gfp.h>
#include <linux/hash.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/percpu.h>
#include <linux/printk.h>
#include <linux/shrinker.h>
#include <linux/slab.h>
#include <linux/srcu.h>
#include <linux/string.h>
#include <linux/types.h>
// #include <linux/cpuhotplug.h>
#include <linux/kmemleak.h>
// #include <mm/slab.h>
#include <net/sock.h>
#include <linux/page-flags.h>
#include <linux/hashtable.h>
#include <linux/mmzone.h>
#include <linux/kthread.h>

// #include "../slab.h"
// #include "kasan.h"
#include "../include/protocol.h"
#include "../include/kcetm.h"
#define SHIELD_FREE_TAG 0x00
/* Data structure and operations for quarantine queues. */

struct shield_qlist_node {
	void* object;
	unsigned long epoch;
	struct hlist_node node;
	struct shield_qlist_node *next;
};
static DEFINE_HASHTABLE(shield_table, 20);
static inline void perf_start(struct kcetm_perf_time*);
static inline unsigned long long perf_end(struct kcetm_perf_time*);
static inline void perf_print(unsigned long long );
static unsigned long shield_quarantine_epoch;
static struct task_struct *shield_quarantine_sweeper_task;
/*
 * Each queue is a single-linked list, which also stores the total size of
 * objects inside of it.
 */
struct qlist_head {
	struct shield_qlist_node *head;
	struct shield_qlist_node *tail;
	size_t bytes;
};

#define QLIST_INIT { NULL, NULL, 0 }

static bool qlist_empty(struct qlist_head *q)
{
	return !q->head;
}

static void qlist_init(struct qlist_head *q)
{
	q->head = q->tail = NULL;
	q->bytes = 0;
}

static void qlist_put(struct qlist_head *q, struct shield_qlist_node *qlink,
		size_t size)
{
	if (unlikely(qlist_empty(q)))
		q->head = qlink;
	else
		q->tail->next = qlink;
	q->tail = qlink;
	qlink->next = NULL;
	q->bytes += size;
}

static void qlist_move_all(struct qlist_head *from, struct qlist_head *to)
{
	if (unlikely(qlist_empty(from)))
		return;


	if (qlist_empty(to)) {
		*to = *from;
		qlist_init(from);
		return;
	}

	to->tail->next = from->head;
	to->tail = from->tail;
	to->bytes += from->bytes;

	qlist_init(from);
}

#define QUARANTINE_PERCPU_SIZE (1 << 20)
#define QUARANTINE_BATCHES \
	(1024 > 4 * CONFIG_NR_CPUS ? 1024 : 4 * CONFIG_NR_CPUS)
#define QUARANTINE_EPOCH_THRESHOLD 2

/*
 * The object quarantine consists of per-cpu queues and a global queue,
 * guarded by quarantine_lock.
 */
// static DEFINE_PER_CPU(struct qlist_head, cpu_quarantine);

/* Round-robin FIFO array of batches. */
static struct qlist_head shield_global_quarantine[QUARANTINE_BATCHES];
static int shield_quarantine_head;
static int shield_quarantine_tail;
/* Total size of all objects in global_quarantine across all batches. */
static unsigned long shield_quarantine_size=0;
/* Semaphore to wake up idle sweep thread */
static DEFINE_SEMAPHORE(shield_quarantine_sem);

static DEFINE_RAW_SPINLOCK(shield_quarantine_lock);
// DEFINE_STATIC_SRCU(shield_remove_cache_srcu);

/* Maximum size of the global queue. */
static unsigned long shield_quarantine_max_size=QUARANTINE_PERCPU_SIZE * QUARANTINE_BATCHES / 2;
/* Watermark size of all objects in global_quarantine to activate sweep thread */
static unsigned long shield_quarantine_size_watermark=QUARANTINE_PERCPU_SIZE * QUARANTINE_BATCHES / 8;

/*
 * Target size of a batch in global_quarantine.
 * Usually equal to QUARANTINE_PERCPU_SIZE unless we have too much RAM.
 */
static unsigned long shield_quarantine_batch_size;

/*
 * The fraction of physical memory the quarantine is allowed to occupy.
 * Quarantine doesn't support memory shrinker with SLAB allocator, so we keep
 * the ratio low to avoid OOM.
 */
#define QUARANTINE_FRACTION 32

// static struct kmem_cache *qlink_to_cache(struct shield_qlist_node *qlink)
// {
//         return virt_to_head_page(qlink)->slab_cache;
// }

static void *qlink_to_object(struct shield_qlist_node *qlink)
{
	// struct kasan_free_meta *free_info =
	//         container_of(qlink, struct kasan_free_meta,
	//                      quarantine_link);

	// return ((void *)free_info) - cache->kasan_info.free_meta_offset;
	return qlink->object;
}

static void qlink_free(struct shield_qlist_node *qlink)
{
	void *object = qlink_to_object(qlink);
	unsigned long flags;

	// if (IS_ENABLED(CONFIG_SLAB))
	local_irq_save(flags);

	/*
	 * As the object now gets freed from the quarantine, assume that its
	 * free track is no longer valid.
	 */
	// *(u8 *)kasan_mem_to_shadow(object) = KASAN_KMALLOC_FREE;

	// ___cache_free(cache, object, _THIS_IP_);
	kfree(object);
	hash_del(&qlink->node);
	kfree(qlink);

	// if (IS_ENABLED(CONFIG_SLAB))
	local_irq_restore(flags);
}

static void qlist_free_all(struct qlist_head *q)
{
	struct shield_qlist_node *qlink;

	if (unlikely(qlist_empty(q)))
		return;


	qlink = q->head;
	while (qlink) {
		// struct kmem_cache *obj_cache =
		//         cache ? cache : qlink_to_cache(qlink);
		struct shield_qlist_node *next = qlink->next;
		qlink_free(qlink);
		qlink = next;
	}
	qlist_init(q);
}

/*
COMMENT(Chenyang): Put new object into our quarantine space
*/
bool shield_quarantine_put(void *object)
{
	unsigned long flags;
	struct qlist_head *q;
	struct shield_qlist_node* cur;
	// struct qlist_head temp = QLIST_INIT;
	// struct kasan_free_meta *meta = kasan_get_free_meta(cache, object);

	// /*
	//  * If there's no metadata for this object, don't put it into
	//  * quarantine.
	//  */
	// if (!meta)
	//     return false;

	/*
	 * Note: irq must be disabled until after we move the batch to the
	 * global quarantine. Otherwise kasan_quarantine_remove_cache() can
	 * miss some objects belonging to the cache if they are in our local
	 * temp list. kasan_quarantine_remove_cache() executes on_each_cpu()
	 * at the beginning which ensures that it either sees the objects in
	 * per-cpu lists or in the global quarantine.
	 */
	local_irq_save(flags);
	u8* mem_tag_ptr = (u8*)(object);
	u8  mem_tag = *mem_tag_ptr;
	// if(unlikely(mem_tag==SHIELD_FREE_TAG)){
		hash_for_each_possible(shield_table,cur,node,object){
			if(cur->object==object){
				pr_info("double free detected");
				return false;
			}
		}
	// }
	// q = this_cpu_ptr(&cpu_quarantine);
	// if (q->offline) {
	//         local_irq_restore(flags);
	//         return false;
	// }
	q = &shield_global_quarantine[shield_quarantine_tail];
	// qlist_put(q, &meta->quarantine_link, cache->size);
	size_t object_size = ksize(object);

	raw_spin_lock(&shield_quarantine_lock);
	// memset(object, SHIELD_FREE_TAG, object_size);

	struct shield_qlist_node* qlink = kmalloc(sizeof(struct shield_qlist_node), GFP_ATOMIC);
	qlink->object = object;
	qlink->epoch = READ_ONCE(shield_quarantine_epoch);
	hash_add(shield_table, &qlink->node, qlink->object);
	qlist_put(q, qlink, object_size);
	WRITE_ONCE(shield_quarantine_size, shield_quarantine_size + object_size);
	if (READ_ONCE(shield_quarantine_size) >= READ_ONCE(shield_quarantine_size_watermark)) {
		if (down_trylock(&shield_quarantine_sem)) // If semaphore is not available
			up(&shield_quarantine_sem);       // release the semaphore so that sweeper can run
	}
	if (q->bytes >= READ_ONCE(shield_quarantine_batch_size)){
		int new_tail;
		new_tail = shield_quarantine_tail + 1;
		if (new_tail == QUARANTINE_BATCHES)
			new_tail = 0;
		if (new_tail != shield_quarantine_head)
			shield_quarantine_tail = new_tail;
	}
	raw_spin_unlock(&shield_quarantine_lock);

	// if (unlikely(q->bytes > QUARANTINE_PERCPU_SIZE)) {
	//         qlist_move_all(q, &temp);

	//         raw_spin_lock(&quarantine_lock);
	//         WRITE_ONCE(shield_quarantine_size, shield_quarantine_size + temp.bytes);
	//         qlist_move_all(&temp, &global_quarantine[quarantine_tail]);
	//         if (global_quarantine[quarantine_tail].bytes >=
	//                         READ_ONCE(shield_quarantine_batch_size)) {
	//                 int new_tail;

	//                 new_tail = quarantine_tail + 1;
	//                 if (new_tail == QUARANTINE_BATCHES)
	//                         new_tail = 0;
	//                 if (new_tail != quarantine_head)
	//                         quarantine_tail = new_tail;
	//         }
	//         raw_spin_unlock(&quarantine_lock);
	// }

	local_irq_restore(flags);

	return true;
}


/*
COMMENT(Chenyang):
  Make room for newly quarantined object when quarantine area is nearly full,
  normally we will free quarantined objects in sweeper kthread
*/
void shield_quarantine_reduce(void *object)
{
	size_t total_size, new_quarantine_size;
	unsigned long flags;
	int srcu_idx;
	struct qlist_head to_free = QLIST_INIT;

	if (likely(READ_ONCE(shield_quarantine_size) <=
		   READ_ONCE(shield_quarantine_max_size)&&shield_quarantine_max_size!=0))
		return;

	/*
	 * srcu critical section ensures that kasan_quarantine_remove_cache()
	 * will not miss objects belonging to the cache while they are in our
	 * local to_free list. srcu is chosen because (1) it gives us private
	 * grace period domain that does not interfere with anything else,
	 * and (2) it allows synchronize_srcu() to return without waiting
	 * if there are no pending read critical sections (which is the
	 * expected case).
	 */
	// srcu_idx = srcu_read_lock(&shield_remove_cache_srcu);
	raw_spin_lock_irqsave(&shield_quarantine_lock, flags);

	/*
	 * Update quarantine size in case of hotplug. Allocate a fraction of
	 * the installed memory to quarantine minus per-cpu queue limits.
	 */
	//total_size = (totalram_pages() << PAGE_SHIFT) /
	//        QUARANTINE_FRACTION;
	//total_size = (READ_ONCE(totalram_pages) << PAGE_SHIFT) /
	//        QUARANTINE_FRACTION;
	total_size = QUARANTINE_PERCPU_SIZE * QUARANTINE_BATCHES / 2;
	// percpu_quarantines = QUARANTINE_PERCPU_SIZE * num_online_cpus();
	// new_quarantine_size = (total_size < percpu_quarantines) ?
	//         0 : total_size - percpu_quarantines;
	new_quarantine_size = total_size;
	WRITE_ONCE(shield_quarantine_max_size, new_quarantine_size);
	WRITE_ONCE(shield_quarantine_size_watermark, new_quarantine_size / 4);
	/* Aim at consuming at most 1/2 of slots in quarantine. */
	WRITE_ONCE(shield_quarantine_batch_size, max((size_t)QUARANTINE_PERCPU_SIZE,
		2 * total_size / QUARANTINE_BATCHES));

	if (unlikely(shield_quarantine_size > shield_quarantine_max_size)) {
		int rnd=get_random_int()%QUARANTINE_BATCHES;
		qlist_move_all(&shield_global_quarantine[rnd], &to_free);
		WRITE_ONCE(shield_quarantine_size, shield_quarantine_size - to_free.bytes);
		qlist_free_all(&to_free);
		qlist_init(&shield_global_quarantine[rnd]);
		// shield_quarantine_head++;
		// if (shield_quarantine_head == QUARANTINE_BATCHES)
		//         shield_quarantine_head = 0;
	}

	raw_spin_unlock_irqrestore(&shield_quarantine_lock, flags);

	// srcu_read_unlock(&shield_remove_cache_srcu, srcu_idx);
}

/*
COMMENT(Chenyang): Free all quarantined objects
*/
void shield_quarantine_all_reduce(void)
{
	struct qlist_head to_free = QLIST_INIT;
	int i =0;
	for(i=0;i<QUARANTINE_BATCHES;i++){
		qlist_move_all(&shield_global_quarantine[i], &to_free);
		qlist_free_all(&to_free);
		qlist_init(&shield_global_quarantine[i]);
	}
}

/*
COMMENT(Chenyang): helper functions
*/
#define first_online_pgdat() first_online_pgdat_monkeypatch()
#define next_online_pgdat(x) next_online_pgdat_monkeypatch(x)
#define next_zone(x) next_zone_monkeypatch(x)

static struct pglist_data *first_online_pgdat_monkeypatch(void)
{
	return NODE_DATA(first_online_node);
}

static struct pglist_data *next_online_pgdat_monkeypatch(struct pglist_data *pgdat)
{
	int nid = next_online_node(pgdat->node_id);

	if (nid == MAX_NUMNODES)
		return NULL;
	return NODE_DATA(nid);
}

/*
 * next_zone - helper magic for for_each_zone()
 */
static struct zone *next_zone_monkeypatch(struct zone *zone)
{
	pg_data_t *pgdat = zone->zone_pgdat;

	if (zone < pgdat->node_zones + MAX_NR_ZONES - 1)
		zone++;
	else {
		pgdat = next_online_pgdat(pgdat);
		if (pgdat)
			zone = pgdat->node_zones;
		else
			zone = NULL;
	}
	return zone;
}

static bool page_mapping_exist(unsigned long addr) {
	pgd_t *pgd;
	p4d_t *p4d;
	pmd_t *pmd;
	pud_t *pud;
	pte_t *pte;
	struct mm_struct *mm = current->active_mm;
	unsigned long end_addr;
	pgd = pgd_offset(mm, addr);
	if (unlikely(!pgd) || unlikely(pgd_none(*pgd)) || unlikely(!pgd_present(*pgd)))
		return false;
	p4d = p4d_offset(pgd, addr);
	if (unlikely(!p4d) || unlikely(p4d_none(*p4d)) || unlikely(!p4d_present(*p4d)))
		return false;
	pud = pud_offset(p4d, addr);
	if (unlikely(!pud) || unlikely(pud_none(*pud)) || unlikely(!pud_present(*pud)))
		return false;
	if (pud_large(*pud)) {
		// goto end;
		return true;
	}
	pmd = pmd_offset(pud, addr);
	if (unlikely(!pmd) || unlikely(pmd_none(*pmd)) || unlikely(!pmd_present(*pmd)))
		return false;
	if (pmd_large(*pmd)) {
		return true;
	}
	pte = pte_offset_map(pmd, addr);
	if (unlikely(!pte) || unlikely(!pte_present(*pte)))
		return false;
end:
	return true;
}

#ifdef CONFIG_KASAN
static inline void *kasan_mem_to_shadow_vul(const void *addr)
{
        return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
                + KASAN_SHADOW_OFFSET;
}
#endif

/*
COMMENT(Chenyang): sweeper kthread
*/
static void __no_sanitize_address shield_quarantine_sweep(void) {
	struct page *page;
	struct zone *zone;
	struct shield_qlist_node* cur;
	unsigned long start_addr, end_addr, content, current_epoch, i;
	unsigned long end_all_addr = __PAGE_OFFSET + get_num_physpages() * 4096;

	raw_spin_lock(&shield_quarantine_lock);
	current_epoch = READ_ONCE(shield_quarantine_epoch) + 1;
	raw_spin_unlock(&shield_quarantine_lock);
	for_each_populated_zone(zone) {
		for (i = zone->zone_start_pfn; i < zone->zone_start_pfn + zone->present_pages; i++) {
			if (kthread_should_stop()) 
				return;                           // Comment(Chenyang): Assume NO LOCK here!!!

			if (!pfn_valid(i))
				continue;
			page = pfn_to_page(i);
			start_addr = (unsigned long)page_to_virt(page);
			end_addr = start_addr + 4096;
			if (start_addr < __PAGE_OFFSET || start_addr >= end_all_addr) {
				continue;
			}

			if (!page_mapping_exist(start_addr)) {
				continue;
			}
			#ifdef CONFIG_KASAN
			if(start_addr>=KASAN_SHADOW_START&&start_addr<KASAN_SHADOW_END){
				continue;
			}
			#endif
			raw_spin_lock(&shield_quarantine_lock);  // Comment(Chenyang): Lock hashtable here
			while (start_addr < end_addr && start_addr < end_all_addr) {
				content = *(unsigned long *) start_addr;
				if (start_addr < __PAGE_OFFSET || content >= end_all_addr) {
					start_addr = start_addr + 8;
					continue;
				}
				#ifdef CONFIG_KASAN	
				s8 shadow_byte=*(s8 *)kasan_mem_to_shadow_vul(start_addr);
				if (shadow_byte!=0) {
					start_addr = start_addr + 8;
					continue;
				}
				#endif

				void *object = (void *) content;
				hash_for_each_possible(shield_table, cur, node, object){
					if(cur->object == object) {
						cur->epoch = current_epoch;
					}
				}

				start_addr = start_addr + 8;
			}
			raw_spin_unlock(&shield_quarantine_lock);
			
		}
	}
 //       pr_info("count is %llu\n",count);
	raw_spin_lock(&shield_quarantine_lock);
	WRITE_ONCE(shield_quarantine_epoch, current_epoch);
	raw_spin_unlock(&shield_quarantine_lock);
}

static int shield_quarantine_collect(void) {
	struct qlist_head *from;
	struct shield_qlist_node* cur;
	struct shield_qlist_node** last;
	unsigned long current_epoch;
	int collected = 0;

	raw_spin_lock(&shield_quarantine_lock);
	current_epoch = READ_ONCE(shield_quarantine_epoch);

	unsigned long batch = current_epoch % QUARANTINE_BATCHES;
	from = &shield_global_quarantine[batch];

	if (unlikely(qlist_empty(from)))
		goto _done;

	cur = from->head;
	last = &from->head;
	while (cur) {
		if ((current_epoch - cur->epoch) >= QUARANTINE_EPOCH_THRESHOLD) {
			*last = cur->next;
			qlink_free(cur);
			cur = *last;
			collected++;
		} else {
			last = &cur->next;
			cur = cur->next;
		}
	}

_done:
	raw_spin_unlock(&shield_quarantine_lock);

	return collected;
}

static int shield_quarantine_sweeper(void* data)
{
	while (!kthread_should_stop()) {
		if (READ_ONCE(shield_quarantine_size) <= READ_ONCE(shield_quarantine_size_watermark)) {
			//pr_info("shield quarantine sweeper sleeping\n");
			down_timeout(&shield_quarantine_sem, msecs_to_jiffies(10000));
		} else if(READ_ONCE(shield_quarantine_size) <= READ_ONCE(shield_quarantine_max_size)/2){
			msleep(10000);
		}else{
			msleep(5000);
		}
                
		if(READ_ONCE(shield_quarantine_size)<= READ_ONCE(shield_quarantine_max_size)/4) continue;
		//pr_info("shield quarantine sweeper activated\n");
		shield_quarantine_sweep();
		int collected = shield_quarantine_collect();
		//pr_info("shield quarantine sweeper collected %d objects\n", collected);
	}
	return 0;
}

/*
COMMENT(Chenyang): Initialize sweeper kthread
*/
void init_shield_quarantine(void) {
	shield_quarantine_sweeper_task = kthread_run(&shield_quarantine_sweeper, NULL, "shield_quarantine_sweeper");
}

void exit_shield_quarantine(void) {
	kthread_stop(shield_quarantine_sweeper_task);
}

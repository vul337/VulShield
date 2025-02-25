#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uprobes.h>
#include <linux/kprobes.h>
#include <linux/namei.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/hw_breakpoint.h>
#include <linux/version.h>
#include <net/genetlink.h>
#include <linux/list.h>
#include <linux/linkage.h>
#include <linux/ptrace.h>
#include <linux/hashtable.h>
#include "../include/protocol.h"
#include "../include/kcetm.h"
#include <linux/vmalloc.h>
#include <linux/resource.h>
#include <linux/fs.h>
// #include <sys/time.h>
#include <linux/syscalls.h>
#include <linux/delay.h> /* usleep_range */
#include <linux/posix-timers.h>
unsigned int vulshield_sysctl_nr_open __read_mostly = 1024*1024;
// --------------------- MACRO

# define likely(x)      __builtin_expect(!!(x), 1)
# define unlikely(x)    __builtin_expect(!!(x), 0)

#define OK(x) x == 0

#define PATCH_AND(a,b) a&b
#define PATCH_OR(a,b) a|b=
#define PATCH_XOR(a,b) a^b
#define PATCH_WITHIN(x,a,b) x>=a&&x<b?1:0 
#define PATCH_EQUAL(a,b) a==b?1:0
#define PATCH_LARGER(a,b) a>b?1:0
#define PATCH_LESS(a,b) a<b?1:0
#define PATCH_LOAD(base,offset)  *(unsigned long*)(base+offset) 

// --------------------- ASM

asmlinkage void just_retfunc(void);

asm(
	".text\n"
	".type just_retfunc, @function\n"
	".globl just_retfunc\n"
	"just_retfunc:\n"
	"ret; \n\t"
	".size just_retfunc, .-just_retfunc\n"
);


//------------Verify
int verify(struct genl_info *);


// --------------------- Helpers

static int get_length(void* src, int length) {
	
	void* dst = (void*)kzalloc(length, GFP_KERNEL);
	copy_from_user(dst, src, length);
	int res = strnlen(dst, length);
	kfree(dst);
	return res;
}

struct vulshield_completion {
        unsigned int done;
		long int current_pid;
};

struct vulshield_completion completion_array[1000]={ 0 };


static inline long vulshield_do_wait_for_common(unsigned int x, long timeout)
{
        if (!completion_array[x].done) {
			long delay_time=0;
                do {
					udelay(1);
					delay_time++;
					if(delay_time==timeout) break;
                } while (!completion_array[x].done && timeout);

                if (!completion_array[x].done){
					pr_err("Find the data race and timeout now\n");
                    return -1;
				}
				else{
					// pr_err("find the data race and delay success now\n");
					return completion_array[x].done;
				}
        }else{
			return completion_array[x].done;
		}
}

// --------------------- Unions

typedef union arg {
	uint64_t i;
	bool b;
} arg_t;

// --------------------- Structs

/**
 * Data structure - linked list:
 * 
 * |node| -> |node| -> |node| -> ...
 *    |         |         |
 *     -- pi  --          pi
 * 
 * Takeaway: 
 * - Each node corresponds to a k/uprobe registeration point
 * - Each pi (patch_info) corresponds to a patch. It's shared between all the nodes within one patch
 * - TODO: Need a lock when accessing pi? Performance?
 */

typedef struct patch_info {
	uint64_t arg[8];
	uint64_t arg_type[8];
	uint64_t arg_offset[8];
	uint64_t op[8];
	uint64_t policy;
	uint64_t rip;
	uint64_t rip_type;
	uint64_t rax;
	uint64_t state_val;
	uint64_t state_val_type;
	uint64_t state_val_offset;
	uint64_t state_code;
	uint64_t write_addr_offset;
	uint64_t write_op;
	// Reserve for inter-handler communication
	uint64_t cache[17];
}patch_info;

typedef struct patch_node {
	// id = ptr
	uint64_t id;
	// shared pi among hanlders in one patch
	struct patch_info* pi;
	// uprobe handler info
	uint64_t bin_offset;
    struct uprobe_consumer* uc;
	struct inode *debuggee_inode;
	// linked list
	struct hlist_node node;
    struct patch_node *next;
}patch_node;

typedef struct k_patch_node {
	// id = ptr
	uint64_t id;
	// shared pi among hanlders in one patch
	struct patch_info* pi;
	// kprobe handler info
        struct kprobe* kp;
	// char symbol[256];
	// linked list
	struct hlist_node node;
    struct k_patch_node *next;
}k_patch_node;

DEFINE_HASHTABLE(k_patches, 8);
DEFINE_HASHTABLE(u_patches, 8);

static void add_k_patch_node(struct patch_info* pi, struct kprobe* kp){
    struct k_patch_node* kpn=kmalloc(sizeof(struct k_patch_node),GFP_KERNEL);
    kpn->id = (uint64_t)kp;
	kpn->pi = pi;
	kpn->kp = kp;
	// kpn->symbol = memcpy(kpi->symbol,symbol_name,sizeof(kpi->symbol));
    hash_add(k_patches,&kpn->node,kpn->id);
}

static struct patch_info* get_k_patch_node(uint64_t id){
	struct k_patch_node* kpn;
	hash_for_each_possible(k_patches, kpn, node, id) {
		if(kpn->id == id) {
			return kpn->pi;
		}
	}
	return NULL;
}

static struct patch_info* del_all_k_patch_node(void){
        struct k_patch_node* kpn;
	unsigned int hash_bkt;
	struct hlist_node *tmp;
        hash_for_each_safe(k_patches,hash_bkt,tmp,kpn, node) {
                kfree(kpn->pi);
		unregister_kprobe(kpn->kp);
		kfree(kpn->kp);
		hash_del(&kpn->node);
		kfree(kpn);
        }
        return NULL;
}

static struct patch_info* del_all_u_patch_node(void){
        struct patch_node* pn;
	unsigned int hash_bkt;
	struct hlist_node *tmp;
    hash_for_each_safe(u_patches,hash_bkt,tmp,pn, node){
        kfree(pn->pi);
		uprobe_unregister(pn->debuggee_inode,pn->bin_offset, pn->uc);
		kfree(pn->uc);
		hash_del(&pn->node);
		kfree(pn);
    }
    return NULL;
}


static void add_u_patch_node(struct patch_info* pi, struct uprobe_consumer* uc, struct inode *debuggee_inode,uint64_t bin_offset){
    struct patch_node* pn=kmalloc(sizeof(struct patch_node),GFP_KERNEL);
    pn->id = (uint64_t)uc;
	pn->pi = pi;
	pn->uc = uc;
	pn->debuggee_inode = debuggee_inode;
	pn->bin_offset=bin_offset;
	// kpn->symbol = memcpy(kpi->symbol,symbol_name,sizeof(kpi->symbol));
    hash_add(u_patches,&pn->node,pn->id);
}

static struct patch_info* get_u_patch_node(uint64_t id){
	struct patch_node* pn;
	hash_for_each_possible(u_patches, pn, node, id) {
		if(pn->id == id) {
			return pn->pi;
		}
	}
	return NULL;
}

// --------------------- Arch related

static inline void vul_shield_override_function_with_return(struct pt_regs *regs);
static inline void vul_shield_regs_set_return_value(struct pt_regs *regs, unsigned long rc);
static inline unsigned long vul_shield_regs_get_argument(struct pt_regs *regs,unsigned int n, struct patch_info *pi);


static inline void vul_shield_override_function_with_return(struct pt_regs *regs) {
  regs->ip = (unsigned long)&just_retfunc;
}
static inline void vul_shield_regs_set_return_value(struct pt_regs *regs, unsigned long rc)
{
        regs->ax = rc;
}
static inline unsigned long vul_shield_regs_get_argument(struct pt_regs *regs, unsigned int n, struct patch_info *pi)
{
	switch(n) {
		case AX: return regs->ax;
		case BX: return regs->bx;
		case CX: return regs->cx;
		case DX: return regs->dx;
		case SI: return regs->si;
		case DI: return regs->di;
		case BP: return regs->bp;
		case SP: return regs->sp;
		case R8: return regs->r8;
		case R9: return regs->r9;
		case R10: return regs->r10;
		case R11: return regs->r11;
		case R12: return regs->r12;
		case R13: return regs->r13;
		case R14: return regs->r14;
		case R15: return regs->r15;
		case VR1: return pi->cache[0];
		default: 
			pr_info("[VUL_PATCH] invalid regs idx.\n");
			return 0;
	}
}

static inline unsigned long vul_shield_regs_set_argument(struct pt_regs *regs, unsigned int n, struct patch_info *pi,uint64_t value)
{
	switch(n) {
		case AX: regs->ax=value;break;
		case BX: regs->bx=value;break;
		case CX: regs->cx=value;break;
		case DX: regs->dx=value;break;
		case SI: regs->si=value;break;
		case DI: regs->di=value;break;
		case BP: regs->bp=value;break;
		case SP: regs->sp=value;break;
		case R8: regs->r8=value;break;
		case R9: regs->r9=value;break;
		case R10: regs->r10=value;break;
		case R11: regs->r11=value;break;
		case R12: regs->r12=value;break;
		case R13: regs->r13=value;break;
		case R14: regs->r14=value;break;
		case R15: regs->r15=value;break;
		case VR1: pi->cache[0]=value;break;
		default: 
			pr_info("[VUL_PATCH] invalid regs idx.\n");
			return 0;
	}
	return 0;
}

// --------------------- Hashing
// Deprecated because of bad performance

typedef struct pre_handler_node {
	uint64_t id;
	kprobe_pre_handler_t pre;
	struct hlist_node node;
    struct pre_handler_node *next;
}pre_handler_node;

typedef struct post_handler_node {
	uint64_t id;
	kprobe_post_handler_t post;
	struct hlist_node node;
    struct post_handler_node *next;
}post_handler_node;

typedef struct state_node {
	uint64_t id;
	int count;
	struct hlist_node node;
    struct state_node *next;
}state_node;

void* isolation_obj=NULL;
void* current_obj=NULL;
void* current_tail=NULL;



/*
typedef struct fault_handler_node {
	uint64_t id;
	kprobe_fault_handler_t fault;
	struct hlist_node node;
    struct fault_handler_node *next;
}fault_handler_node;
*/
static DEFINE_HASHTABLE(hm_pre, 8);
static DEFINE_HASHTABLE(hm_post, 8);
static DEFINE_HASHTABLE(hm_state, 20);
// static DEFINE_HASHTABLE(hm_fault, 8);

static int AddPreHandler(uint64_t id, kprobe_pre_handler_t pre){
    struct pre_handler_node* qlink=kmalloc(sizeof(struct pre_handler_node),GFP_KERNEL);
    qlink->pre=pre;
    qlink->id=id;
    hash_add(hm_pre,&qlink->node,qlink->id);
    return 0;
}

static int AddPostHandler(uint64_t id, kprobe_post_handler_t post){
    struct post_handler_node* qlink=kmalloc(sizeof(struct post_handler_node),GFP_KERNEL);
    qlink->post=post;
    qlink->id=id;
    hash_add(hm_post,&qlink->node,qlink->id);
    return 0;
}

static int AddState(uint64_t id){
	if((void*)id==NULL) return 0;
	struct state_node* sn;
	hash_for_each_possible(hm_state, sn, node, id) {
		if(sn->id == id) {
			sn->count++;
			//pr_info("id %lx is alloc,count is:%d\n",id,sn->count);
			return 1;
		}
	}
    struct state_node* qlink=kmalloc(sizeof(struct state_node),GFP_KERNEL);
    qlink->count=1;
    qlink->id=id;
	//pr_info("id %lx is alloc,count is:%d\n",id,qlink->count);
    hash_add(hm_state,&qlink->node,qlink->id);
    return 0;
}

static int DelState(uint64_t id){
	struct state_node* sn;
	hash_for_each_possible(hm_state, sn, node, id) {
		if(sn->id == id) {
			sn->count--;
	//		pr_info("id %lx is free,count is:%d\n",id,sn->count);
			return 1;
		}
	}
	return 0;
}

/*
static int AddFaultHandler(uint64_t id, kprobe_fault_handler_t fault){
    struct fault_handler_node* qlink=kmalloc(sizeof(struct fault_handler_node),GFP_KERNEL);
    qlink->fault=fault;
    qlink->id=id;
    hash_add(hm_fault,&qlink->node,qlink->id);
}
*/
static kprobe_pre_handler_t GetPreHandler(uint64_t id){
	struct pre_handler_node* phn;
	hash_for_each_possible(hm_pre, phn, node, id) {
		if(phn->id == id) {
			return phn->pre;
		}
	}
	return NULL;
}

static kprobe_post_handler_t GetPostHandler(uint64_t id){
	struct post_handler_node* phn;
	hash_for_each_possible(hm_post, phn, node, id) {
		if(phn->id == id) {
			return phn->post;
		}
	}
	return NULL;
}

static int GetState(uint64_t id){
	struct state_node* sn;
	hash_for_each_possible(hm_state, sn, node, id) {
		if(sn->id == id) {
			return sn->count;
		}
	}
	return 0xdeadbeef;
}

static int GetStateRange(uint64_t addr,uint64_t offset){
	//pr_info("find %lx\n",addr);
	struct state_node* sn;
	hash_for_each_possible(hm_state, sn, node, addr) {
		if((sn->id<=addr)&&(sn->id+offset>=addr)) {
			//pr_info("find %p,count is:%d\n",(void *)sn->id,sn->count);
			return sn->count;
		}
	}
	return 0;
}

/*
static kprobe_fault_handler_t GetFaultHandler(uint64_t id){
	struct fault_handler_node* pfn;
	hash_for_each_possible(hm_fault, pfn, node, id) {
		if(pfn->id == id) {
			return pfn->fault;
		}
	}
	return NULL;
}
*/

// --------------------- 

static arg_t load_arg(struct patch_info* pi,struct pt_regs *regs, uint64_t arg, uint64_t arg_type, uint64_t arg_offset){
	// pr_info("load_arg: arg: %lld, arg_type: %lld, arg_offset: %lld\n");
	arg_t data;
	switch (arg_type) {
		case ARG_NUM:
			data.i = arg;
			return data;
		case ARG_REG:
			data.i = vul_shield_regs_get_argument(regs, arg, pi) + arg_offset;
			return data;
		case ARG_STATE_NUM:{
			data.i = GetState(arg);
			return data;
		}
		case ARG_STATE_REG_COUNT:{
			uint64_t id = vul_shield_regs_get_argument(regs, arg, pi);
			data.i = GetState(id);
			return data;
		}
		case ARG_STATE_REG_RANGE:{
			uint64_t addr=vul_shield_regs_get_argument(regs, arg, pi)+arg_offset;
			arg_t args =load_arg(pi,regs,pi->state_val, pi->state_val_type,pi->state_val_offset);
			uint64_t offset = args.i;
			data.i = GetStateRange(addr,offset);
			return data;
		}			
		case ARG_ADDR:{
			uint64_t* addr = vul_shield_regs_get_argument(regs, arg, pi) + arg_offset;
			//pr_info("load_arg: arg: %lld, arg_type: %lld, arg_offset: %lld, val: %lld\n", arg, arg_type, arg_offset, * addr);
			data.i = * addr;
			return data;
		}
		case ARG_VALID:{
			uint64_t dst = vul_shield_regs_get_argument(regs, arg, pi)+arg_offset;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
            if (access_ok(VERIFY_WRITE, (void *)dst, 1)){
				data.i = 2;
			}else if(access_ok(VERIFY_READ, (void *)dst, 1)){
				data.i = 1;
			}else data.i = 0;

			if(data.i == 0) pr_err("find the invalid address %p\n",(void *)dst);
			
			return data;
#else
	    	if(user_access_begin((void *)dst,1)){
				data.i = 2;
				user_access_end();
			}else data.i = 0;

			if(data.i == 0) pr_err("find the invalid address %p\n",(void *)dst);

			return data;
#endif
		}
		case ARG_STRLEN_U: {
			void* dst = vul_shield_regs_get_argument(regs, arg, pi) + arg_offset;
			// Magic Number 8192
			data.i = get_length(dst, 8192);
			// pr_err("the lengh of user string is %d",data.i);
			return data;
		}
		case ARG_STRLEN_K: {
			// Magic Number 8192
			void* dst = vul_shield_regs_get_argument(regs, arg, pi) + arg_offset;
			data.i = strlen(dst);
			// pr_err("the lengh of kernel string is %d",data.i);
			return data;
		}
		case ARG_VR_1: {
			data.i = pi->cache[0];
			return data;
		}
		default:
			data.i = 0;
			return data;
	}
}

static arg_t set_arg(struct patch_info* pi,struct pt_regs *regs, uint64_t arg, uint64_t arg_type, uint64_t arg_offset,uint64_t value){
	// pr_info("load_arg: arg: %lld, arg_type: %lld, arg_offset: %lld\n");
	arg_t data;
	switch (arg_type) {
		case ARG_REG:
			vul_shield_regs_set_argument(regs, arg, pi,value);break;		
		case ARG_ADDR:{
			uint64_t* addr = vul_shield_regs_get_argument(regs, arg, pi) + arg_offset;
			//pr_info("load_arg: arg: %lld, arg_type: %lld, arg_offset: %lld, val: %lld\n", arg, arg_type, arg_offset, * addr);
			* addr=value;
			break;
		}
		default:
			data.i = 0;
			return data;
	}
	return data;
}

static arg_t exec_exp(uint64_t op, arg_t arg1, arg_t arg2){
	arg_t data;
	switch (op){
		case OP_RVAL:
			return arg2;
		case OP_AND:
			data.i = arg1.i & arg2.i;
			return data;
		case OP_XOR:
			data.i = arg1.i ^ arg2.i;
			return data;
		case OP_OR:
			data.i = arg1.i | arg2.i;
			return data;
		case OP_ADD:
			data.i = arg1.i + arg2.i;
			return data;
		case OP_MUL:
			data.i = arg1.i * arg2.i;
			return data;
		case OP_DIV:
			data.i = arg1.i / arg2.i;
			return data;
		case OP_REM:
			data.i = arg1.i % arg2.i;
			return data;
		case OP_SHR:
			data.i = arg1.i >> arg2.i;
			return data;
		case OP_SHL:
			data.i = arg1.i << arg2.i;
			return data;
		case OP_GT:
			data.b = arg1.i > arg2.i;
			return data;
		case OP_GE:
			data.b = arg1.i >= arg2.i;
			return data;
		case OP_LT:
			data.b = arg1.i < arg2.i;
			return data;
		case OP_LE:
			data.b = arg1.i <= arg2.i;
			return data;
		case OP_EQ:
			data.b = arg1.i == arg2.i;
			// pr_info("[VUL_PATCH]: %d %d\n", arg1.i, arg2.i);
			return data;
		case OP_NE:
			data.b = arg1.i != arg2.i;
			// pr_info("[VUL_PATCH]: %d %d\n", arg1.i, arg2.i);
			return data;
		case OP_AND_BOOL:
			data.b = arg1.b && arg2.b;
			return data;
		case OP_OR_BOOL:
			data.b = arg1.b || arg2.b;
			return data;
		default: 
			data.b = false;
			return data;
	}
}

// A faster exp execution impl
// Assumption: 
// We don't need all args for most of cases
// 
static arg_t fast_eval_exp(struct pt_regs *regs, struct patch_info* pi, int i){
	//pr_info("[VUL_PATCH] eval_exp_r: idx: %d", i);
	if(i == 0){
		arg_t arg1 = load_arg(pi,regs, pi->arg[0], pi->arg_type[0], pi->arg_offset[0]);
		arg_t arg2 = load_arg(pi,regs, pi->arg[1], pi->arg_type[1], pi->arg_offset[1]);
		return exec_exp(pi->op[0], arg1, arg2);
	}
	uint64_t op = pi->op[2*i];
	int l = 2*i;
	int r = 2*i + 1;
	arg_t argl = load_arg(pi,regs, pi->arg[l], pi->arg_type[l], pi->arg_offset[l]);
	arg_t argr = load_arg(pi,regs, pi->arg[r], pi->arg_type[r], pi->arg_offset[r]);
	arg_t childr = exec_exp(pi->op[2*i - 1], argl, argr);
	//pr_info("[VUL_PATCH] eval_exp_r: childr: op: %d, l: %d, r:%d", 2*i - 1, l, r);
	switch (op){
		case OP_RVAL: {
			pr_info("[VUL_PATCH] eval_exp_r: fast pass childr");
			return childr;
		}
		default: {
			arg_t childl = fast_eval_exp(regs, pi, i - 1);
			pr_info("[VUL_PATCH] eval_exp_r: childl: op: %d", op);
			return exec_exp(op, childl, childr);
		}
	}
}

static arg_t eval_exp(struct pt_regs *regs, struct patch_info* pi){
	arg_t arg1 = load_arg(pi,regs, pi->arg[0], pi->arg_type[0], pi->arg_offset[0]);
	arg_t arg2 = load_arg(pi,regs, pi->arg[1], pi->arg_type[1], pi->arg_offset[1]);
	arg_t arg3 = load_arg(pi,regs, pi->arg[2], pi->arg_type[2], pi->arg_offset[2]);
	arg_t arg4 = load_arg(pi,regs, pi->arg[3], pi->arg_type[3], pi->arg_offset[3]);
	arg_t arg5 = load_arg(pi,regs, pi->arg[4], pi->arg_type[4], pi->arg_offset[4]);
	arg_t arg6 = load_arg(pi,regs, pi->arg[5], pi->arg_type[5], pi->arg_offset[5]);
	arg_t arg7 = load_arg(pi,regs, pi->arg[6], pi->arg_type[6], pi->arg_offset[6]);
	arg_t arg8 = load_arg(pi,regs, pi->arg[7], pi->arg_type[7], pi->arg_offset[7]);

	arg_t res_12 = exec_exp(pi->op[0], arg1, arg2);
	arg_t res_34 = exec_exp(pi->op[1], arg3, arg4);
	arg_t res_56 = exec_exp(pi->op[3], arg5, arg6);
	arg_t res_78 = exec_exp(pi->op[5], arg7, arg8);

	arg_t res_14 = exec_exp(pi->op[2], res_12, res_34);
	arg_t res_16 = exec_exp(pi->op[4], res_14, res_56);
	arg_t res_18 = exec_exp(pi->op[6], res_16, res_78);

	return res_18;
}

static bool detect_violation(struct pt_regs *regs, struct patch_info* pi){
	arg_t arg1 = load_arg(pi,regs, pi->arg[0], pi->arg_type[0], pi->arg_offset[0]);
	arg_t arg2 = load_arg(pi,regs, pi->arg[1], pi->arg_type[1], pi->arg_offset[1]);
	arg_t arg3 = load_arg(pi,regs, pi->arg[2], pi->arg_type[2], pi->arg_offset[2]);
	arg_t arg4 = load_arg(pi,regs, pi->arg[3], pi->arg_type[3], pi->arg_offset[3]);
	arg_t arg5 = load_arg(pi,regs, pi->arg[4], pi->arg_type[4], pi->arg_offset[4]);
	arg_t arg6 = load_arg(pi,regs, pi->arg[5], pi->arg_type[5], pi->arg_offset[5]);
	arg_t arg7 = load_arg(pi,regs, pi->arg[6], pi->arg_type[6], pi->arg_offset[6]);
	arg_t arg8 = load_arg(pi,regs, pi->arg[7], pi->arg_type[7], pi->arg_offset[7]);

	arg_t res_12 = exec_exp(pi->op[0], arg1, arg2);
	// pr_err("res_12 is %ld\n",res_12.i);
	arg_t res_34 = exec_exp(pi->op[1], arg3, arg4);
	// pr_err("res_34 is %ld\n",res_34.i);
	arg_t res_56 = exec_exp(pi->op[3], arg5, arg6);
	// pr_err("res_56 is %ld\n",res_56.i);
	arg_t res_78 = exec_exp(pi->op[5], arg7, arg8);
	// pr_err("res_78 is %ld\n",res_78.i);

	arg_t res_14 = exec_exp(pi->op[2], res_12, res_34);
	// pr_err("res_14 is %ld\n",res_14.i);
	arg_t res_16 = exec_exp(pi->op[4], res_14, res_56);
	// pr_err("res_16 is %ld\n",res_16.i);
	arg_t res_18 = exec_exp(pi->op[6], res_16, res_78);
	// pr_err("res_18 is %ld\n",res_18.b);

	return res_18.b;
}

static int set_ip(struct pt_regs *regs, uint64_t arg, uint64_t ip_type){
//	pr_err("arg is %ld\n",arg);
	switch(ip_type){
		case IP_ABS: {
			regs->ip = arg;
//			pr_err(" IP_ABS: ip is %llx\n",regs->ip);
			return 1;
		}
		case IP_REL:{
	                //pr_err(" IP_REL: before ip is %llx\n",regs->ip);
			//pr_err(" IP_REL: offset is %llx\n",arg);
			regs->ip = regs->ip + arg;
			//pr_err(" IP_REL: after ip is %llx\n",regs->ip);
			return 1;
		}
		case IP_NO:{
//		        pr_err(" IP_NO: ip is %llx\n");
			return 0;
		}
		default: return 0;
	}
}

// --------------------- shield free
void shield_quarantine_all_reduce(void);
void shield_quarantine_reduce(void *object);
void shield_quarantine_put(void *object);
void init_shield_quarantine(void);
void exit_shield_quarantine(void);
void shieldfree(const void *objp)
{
        unsigned long flags;
        if (unlikely(ZERO_OR_NULL_PTR(objp)))
                return;
        local_irq_save(flags);
       shield_quarantine_reduce((void *)objp);
      shield_quarantine_put((void *)objp);
     local_irq_restore(flags);
		
}


// --------------------- handler

static int detect_kernel_policy(struct patch_info* pi,struct pt_regs *regs){
	// pr_err("[VUL_PATCH] detect_kernel_policy\n ");
	if(likely(pi != NULL)){
		// pr_err("[VUL_PATCH] handler:\n ");
		// Expression parsing...
		switch(pi->policy){
			case ACT_RET:{
				if(detect_violation(regs, pi)){
			//		pr_err("ACT_RET\n");
					vul_shield_regs_set_return_value(regs, pi->rax);
					return set_ip(regs, pi->rip, pi->rip_type);
				}
				break;
		    }
			case ACT_RIP:{
				if(detect_violation(regs, pi)){
			//		pr_err("ACT_IP\n");
					return set_ip(regs, pi->rip, pi->rip_type);
                }
				break;
            }
			case ACT_QRT:{
			//	pr_err("ACT_QRT\n");
				//pr_err("v2 is %p\n",regs->bp);
				void *objp=(void*)regs->di;
				shieldfree(objp);
				regs->di=0;
				return 0;
            }
			case ACT_INC:{
			//	pr_err("ACT_INC\n");
				arg_t arg = load_arg(pi,regs,pi->state_val, pi->state_val_type,pi->state_val_offset);
				AddState(arg.i);
				return 0;
			}
			case ACT_DEC:{
			//	pr_err("ACT_DEC\n");
				arg_t arg = load_arg(pi,regs,pi->state_val, pi->state_val_type,pi->state_val_offset);
				DelState(arg.i);
				return 0;
            }
			case ACT_NOP: return 0;
			case ACT_INIT_COMPLETION:{
			//	pr_err("ACT_INIT_COMPLETION\n");
				unsigned int x=current->pid%100;
				if(completion_array[x].current_pid!=0&&completion_array[x].current_pid!=current->pid){
						pr_err("completion array is not enough\n");
				}else{
					completion_array[x].current_pid=current->pid;
					completion_array[x].done=0;
				}
				break;
			}
			case ACT_SET_COMPLETION:{
			//	pr_err("ACT_SET_COMPLETION\n");
				unsigned int x=current->pid%1000;
				if(completion_array[x].current_pid!=0&&completion_array[x].current_pid!=current->pid){
						pr_err("completion array is not enough\n");
						pr_err("completion_array[x].current_pid is %ld\n",completion_array[x].current_pid);
						pr_err("current->pid is %ld\n",current->pid);
				}else{
					completion_array[x].current_pid=current->pid;
					completion_array[x].done=1;
				}
				break;
			}
			case ACT_SLEEP:{
				if(detect_violation(regs, pi)){
					// pr_err("ACT_SLEEP\n");
					arg_t arg = load_arg(pi,regs,pi->state_val, pi->state_val_type,pi->state_val_offset);
					unsigned int x=current->pid%1000;
					if(completion_array[x].current_pid!=0&&completion_array[x].current_pid!=current->pid){
						pr_err("completion array is not enough\n");
						pr_err("completion_array[x].current_pid is %ld\n",completion_array[x].current_pid);
						pr_err("current->pid is %ld\n",current->pid);
					}else vulshield_do_wait_for_common(x,arg.i);
				}
				break;
			}
			case ACT_RECORD_RAX: {
				pi->cache[0] = regs->ax;
				break;
			}
			case ACT_RECORD_RBX: {
				pi->cache[1] = regs->bx;
				break;
			}
			case ACT_RECORD_RCX: {
				pi->cache[2] = regs->cx;
				break;
			}
			case ACT_RECORD_RDX: {
				pi->cache[3] = regs->dx;
				break;
			}
			case ACT_RECORD_RSI: {
				pi->cache[4] = regs->si;
				break;
			}
			case ACT_RECORD_RDI: {
				pi->cache[5] = regs->di;
				break;
			}
			case ACT_RECORD_R8: {
				pi->cache[6] = regs->r8;
				break;
			}
			case ACT_RECORD_R9: {
				pi->cache[7] = regs->r9;
				break;
			}
			case ACT_RECORD_R10: {
				pi->cache[8] = regs->r10;
				break;
			}
			case ACT_TEST: {/*micro performance tes*/
                struct kcetm_perf_time t;
                unsigned long long res;
                perf_start(&t);
				detect_violation(regs, pi);
				res = perf_end(&t);
                perf_print(res);
				// if(detect_violation(regs, pi)){
				// 	return 0;
				// }
				return 0;
			}
		    default: return 0;
		}
	}
	return 0;
}


static int detect_user_policy(struct patch_info* pi,struct pt_regs *regs){
	// pr_err("[VUL_PATCH] detect_user_policy\n ");
	if(likely(pi != NULL)){
		// pr_err("[VUL_PATCH] handler:\n ");
		// Expression parsing...
		switch(pi->policy){
			case ACT_INC:{
			//	pr_err("ACT_INC\n");
				arg_t arg = load_arg(pi,regs,pi->state_val, pi->state_val_type,pi->state_val_offset);
				AddState(arg.i);
				return 0;
			}
			case ACT_DEC:{
			//	pr_err("ACT_DEC\n");
				arg_t arg = load_arg(pi,regs,pi->state_val, pi->state_val_type,pi->state_val_offset);
				DelState(arg.i);
				return 0;
            }
			case ACT_KILL:{
				// pr_err("ACT_KILL\n");
				// usleep_range(300, 301);
				if(detect_violation(regs, pi)){
					pr_err("[VUL_PATCH] kill the progress!\n");
					kill_pid(find_vpid(current->pid), SIGKILL, 1);
				}
				break;
			}
			case ACT_WARMING:{
				if(detect_violation(regs, pi)){
					pr_err("[VUL_PATCH] detect the violation of the progress %d !\n",current->pid);
				}
				break;
			}
			case ACT_HANG:{
				if(detect_violation(regs, pi)){
					pr_err("[VUL_PATCH] hang on the progress!\n");
					struct pid *pid_struct = find_get_pid(current->pid);
					if (pid_struct) {
						struct task_struct *task = pid_task(pid_struct, PIDTYPE_PID);
						if (task) {
							if (send_sig(SIGSTOP, task, 0) < 0)
								pr_err("send_sig SIGSTOP fail\n");
						}
						put_pid(pid_struct);
					}
				}
				break;
			}
			/*if do not use the ACT_INC/ACT_DEC to record the heap malloc/free, 
			  use the ACT_RECORD_MALLOC to record the allocation of the heap object*/
			case ACT_RECORD_MALLOC: {
			//	pr_err("ACT_RECORD_MALLOC\n");
				pi->cache[0] = regs->ax;
				break;
			}
			case ACT_INIT_COMPLETION:{
			//	pr_err("ACT_INIT_COMPLETION\n");
				unsigned int x=current->pid%100;
				if(completion_array[x].current_pid!=0&&completion_array[x].current_pid!=current->pid){
						pr_err("completion array is not enough\n");
				}else{
					completion_array[x].current_pid=current->pid;
					completion_array[x].done=0;
				}
				break;
			}
			case ACT_SET_COMPLETION:{
			//	pr_err("ACT_SET_COMPLETION\n");
				unsigned int x=current->pid%1000;
				if(completion_array[x].current_pid!=0&&completion_array[x].current_pid!=current->pid){
						pr_err("completion array is not enough\n");
						pr_err("completion_array[x].current_pid is %ld\n",completion_array[x].current_pid);
						pr_err("current->pid is %ld\n",current->pid);
				}else{
					completion_array[x].current_pid=current->pid;
					completion_array[x].done=1;
				}
				break;
			}
			/*if do wanna use the SIGSTOP,can use the sleep with timeout*/
			case ACT_SLEEP:{
				if(detect_violation(regs, pi)){
					// pr_err("ACT_SLEEP\n");
					arg_t arg = load_arg(pi,regs,pi->state_val, pi->state_val_type,pi->state_val_offset);
					unsigned int x=current->pid%1000;
					if(completion_array[x].current_pid!=0&&completion_array[x].current_pid!=current->pid){
						pr_err("completion array is not enough\n");
						pr_err("completion_array[x].current_pid is %ld\n",completion_array[x].current_pid);
						pr_err("current->pid is %ld\n",current->pid);
					}else vulshield_do_wait_for_common(x,arg.i);
				}
				break;
			}
			case ACT_RECORD_RAX: {
				pi->cache[0] = regs->ax;
				break;
			}
			case ACT_RECORD_RBX: {
				pi->cache[1] = regs->bx;
				break;
			}
			case ACT_RECORD_RCX: {
				pi->cache[2] = regs->cx;
				break;
			}
			case ACT_RECORD_RDX: {
				pi->cache[3] = regs->dx;
				break;
			}
			case ACT_RECORD_RSI: {
				pi->cache[4] = regs->si;
				break;
			}
			case ACT_RECORD_RDI: {
				pi->cache[5] = regs->di;
				break;
			}
			case ACT_RECORD_R8: {
				pi->cache[6] = regs->r8;
				break;
			}
			case ACT_RECORD_R9: {
				pi->cache[7] = regs->r9;
				break;
			}
			case ACT_RECORD_R10: {
				pi->cache[8] = regs->r10;
				break;
			}
			case ACT_TEST: {/*micro performance tes*/
                struct kcetm_perf_time t;
                unsigned long long res;
                perf_start(&t);
				detect_violation(regs, pi);
				res = perf_end(&t);
                perf_print(res);
				// if(detect_violation(regs, pi)){
				// 	return 0;
				// }
				return 0;
			}
		    default: return 0;
		}
	}
	return 0;
}


static int pre_handler(struct kprobe *p, struct pt_regs *regs) {
	// Searching for pn
	struct patch_info* pi = get_k_patch_node((uint64_t)p);
	return detect_kernel_policy(pi,regs);
}

static void post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags) {
    // pr_err("[VUL_PATCH] post_handler: \n");
	// Searching for pn
	struct patch_info* pi = get_k_patch_node((uint64_t)p);
	detect_kernel_policy(pi,regs);
	return;
}

static int u_handler(struct uprobe_consumer *con,struct pt_regs *regs) {
	// Searching for pn
	// pr_err("[VUL_PATCH] u_handler detected !\n");
	struct patch_info* pi = get_u_patch_node((uint64_t)con);
	return detect_user_policy(pi,regs);
}

static int u_ret_handler(struct uprobe_consumer *con, unsigned long func, struct pt_regs *regs) {
	// Searching for pn
	struct patch_info* pi = get_u_patch_node((uint64_t)con);
	return detect_user_policy(pi,regs);
}


static int fault_handler(struct kprobe *p, struct pt_regs *regs, int trapnr) {
	pr_info("[VUL_PATCH] fault_handler: ");
	return 0;
}

const static struct {
	kprobe_pre_handler_t pre;
} pre_handler_map [] = {
	{pre_handler},
	{pre_handler},
};

const static struct {
	kprobe_post_handler_t post;
} post_handler_map [] = {
	{post_handler},
	{post_handler},
};

typedef int (*uprobe_handler_t) (struct uprobe_consumer *, struct pt_regs *);

typedef int (*uprobe_ret_handler_t) (struct uprobe_consumer *, unsigned long,struct pt_regs *);

typedef int (*uprobe_filter) (struct uprobe_consumer *, enum uprobe_filter_ctx,struct mm_struct *);

const static struct {
        uprobe_handler_t handler;
} u_handler_map [] = {
        {u_handler},
		{u_handler},
};

const static struct {
        uprobe_ret_handler_t ret;
} u_ret_handler_map [] = {
        {u_ret_handler},
		{u_ret_handler},
};


// --------------------- policy

// static int verify(struct genl_info *info){
// 	int di = DI_SPACE;
// 	for(; di != DI_MAX; di++ ){
// 		if (!info->attrs[di]) {
// 			pr_err("[VUL_PATCH] Invalid request: Missing symbol attribute: %d.\n", di);
// 			return -EINVAL;
// 		}
// 	}
// 	return 0;
// }

static void load_patch_info(struct genl_info *info, struct patch_info* pi){
	int i = 0;
	for(; i < 8; i++){
		pi->arg[i] = nla_get_u64(info->attrs[DI_ARG_1_VAL + i*3]);
		pi->arg_type[i] = nla_get_u64(info->attrs[DI_ARG_1_TYPE+ i*3]);
		pi->arg_offset[i] = nla_get_u64(info->attrs[DI_ARG_1_OFFSET+ i*3]);
	}
	i = 0;
	for(; i < 7; i++){
		pi->op[i] = nla_get_u64(info->attrs[DI_OP_0 + i]);
	}
	pi->policy = nla_get_u64(info->attrs[DI_HASH_ACTION1]);
	pi->rip_type = nla_get_u64(info->attrs[DI_RIP_TYPE]);
	pi->rip = nla_get_u64(info->attrs[DI_RIP]);
	pi->rax = nla_get_u64(info->attrs[DI_RAX]);
	pi->state_val=nla_get_u64(info->attrs[DI_STATE_1_VAL]);
	pi->state_val_type=nla_get_u64(info->attrs[DI_STATE_1_VAL_TYPE]);
	pi->state_val_offset=nla_get_u64(info->attrs[DI_STATE_1_VAL_OFFSET]);
	pi->state_code=nla_get_u64(info->attrs[DI_STATE_1_CODE]);
	pi->write_addr_offset=nla_get_u64(info->attrs[DI_WRITE_ADDR_OFFSET]);
	pi->write_op=nla_get_u64(info->attrs[DI_WRITE_OP]);
}

static int vulsheild_register_kprobe(char* symbol,uint64_t offset,struct patch_info* pi,struct genl_info *info,int handler_type){
        struct kprobe* kp=(struct kprobe*)kzalloc(sizeof(struct kprobe),GFP_KERNEL);
        kp->symbol_name    = symbol;
        kp->offset         = offset;

		// pr_err("symbol_name is %s,offset is %ld\n",symbol,offset);
		int hid = nla_get_u64(info->attrs[DI_HASH_POLICY]);
        switch (handler_type) {
                case HDL_PRE:
                        pr_err("[VUL_PATCH] pre_handler\n");
                        kp->pre_handler = pre_handler_map[hid].pre;
                        break;
                case HDL_POST:
                        pr_err("[VUL_PATCH] post_handler\n");
                        kp->post_handler = post_handler_map[hid].post;
                        break;
                //case HDL_FAULT:
                //        kp->fault_handler = fault_handler_map[hid].fault;
                //        break;
                default:
                        pr_err("[VUL_PATCH] Invalid kprobe handler type! \n");
        }

        // store kprobe info here
        add_k_patch_node(pi, kp);

        int ret = register_kprobe(kp);
        if(ret < 0){
                unregister_kprobe(kp);
                pr_err("[VUL_PATCH] register kprobe: fail with code: %d\n", ret);
                return ret;
        }
        pr_info("[VUL_PATCH] register kprobe: success\n");
	return ret;
}

typedef int (*kernel_policy_func_t) (char* ,uint64_t ,struct patch_info* ,struct genl_info *,int);

static struct {
        kernel_policy_func_t kpolicy_func;
} k_policy_func_map [20];
int kpolicy_func_num;

static void addKpolicyFunc(kernel_policy_func_t func){
	kpolicy_func_num++;
	k_policy_func_map[kpolicy_func_num].kpolicy_func=func;
	return;
}

static void initKpolicyFunc(void){
	pr_info("init the Kpolicy Func\n");
	kpolicy_func_num=0;
	addKpolicyFunc(vulsheild_register_kprobe);
	return;
}
static int launch_kernel_policy(struct sk_buff *skb, struct genl_info *info){
	pr_info("[VUL_PATCH] launch_kernel_policy: enter\n");
	kernel_policy_func_t policy_func=NULL;
	int hid = nla_get_u64(info->attrs[DI_HASH_POLICY]);
	policy_func=k_policy_func_map[hid].kpolicy_func;
	int ret = 0;

	ret = verify(info);
	if(!OK(ret)){
		return ret;
	}

	pr_info("[VUL_PATCH] launch_kernel_policy: verification done.\n");

	struct patch_info* pi = (struct patch_info*)kmalloc(sizeof(patch_info), GFP_KERNEL);

	load_patch_info(info, pi);
        char* const delim = ";";

	unsigned char* symbol_list = (unsigned char *)nla_data(info->attrs[DI_FILE]);
	char *token, *cur = symbol_list;
	int count=0;
	uint64_t offset=0;
	while (token = strsep(&cur, delim)) {
	    if(token=="\0"||token==NULL) break;
	    struct patch_info* pi_each=NULL;
		int handler_type=0;
        if(count==0){
		    offset = nla_get_u64(info->attrs[DI_BIN_OFFSET]);
		    pi_each=pi;
			handler_type=nla_get_u64(info->attrs[DI_HANDLER1]);
	    }
	    if(count==1){
		    offset = nla_get_u64(info->attrs[DI_BIN_OFFSET_2]);
		    pi_each=(struct patch_info*)kmalloc(sizeof(patch_info), GFP_KERNEL);
		    memcpy(pi_each,pi,sizeof(patch_info));
            pi_each->policy = nla_get_u64(info->attrs[DI_HASH_ACTION2]);
			pi_each->state_val=nla_get_u64(info->attrs[DI_STATE_2_VAL]);
			pi_each->state_val_type=nla_get_u64(info->attrs[DI_STATE_2_VAL_TYPE]);
			pi_each->state_val_offset=nla_get_u64(info->attrs[DI_STATE_2_VAL_OFFSET]);
			pi_each->state_code=nla_get_u64(info->attrs[DI_STATE_2_CODE]);
			handler_type=nla_get_u64(info->attrs[DI_HANDLER2]);
	    }
	    if(count==2){
		    offset = nla_get_u64(info->attrs[DI_BIN_OFFSET_3]);
		    pi_each=(struct patch_info*)kmalloc(sizeof(patch_info), GFP_KERNEL);
            memcpy(pi_each,pi,sizeof(patch_info));
		    pi_each->policy = nla_get_u64(info->attrs[DI_HASH_ACTION3]);
			pi_each->state_val=nla_get_u64(info->attrs[DI_STATE_3_VAL]);
			pi_each->state_val_type=nla_get_u64(info->attrs[DI_STATE_3_VAL_TYPE]);
			pi_each->state_val_offset=nla_get_u64(info->attrs[DI_STATE_3_VAL_OFFSET]);
			pi_each->state_code=nla_get_u64(info->attrs[DI_STATE_3_CODE]);
			handler_type=nla_get_u64(info->attrs[DI_HANDLER3]);
	    }
	    if(count>2){
		    pr_err("cannot support more kprobe\n");
		    break;
	    }
	    policy_func(token,offset,pi_each,info,handler_type);
        count=count+1;
        pr_err("the kprobe probe the func: %s\n", token);
    }

	if(count==0){
	    pr_err("not have the delim\n");
	    offset = nla_get_u64(info->attrs[DI_BIN_OFFSET]);
		int handler_type=nla_get_u64(info->attrs[DI_HANDLER1]);
        policy_func(symbol_list,offset,pi,info,handler_type);
	}
	return ret;
}

static int vulsheild_register_uprobe(struct inode *debuggee_inode, uint64_t offset, struct patch_info* pi, struct genl_info *info, int handler_type){
		pr_info("[VUL_PATCH] entering vulshield_register_uprobe\n");
        struct uprobe_consumer* uc=(struct uprobe_consumer*)kzalloc(sizeof(struct uprobe_consumer),GFP_KERNEL);
		int hid = nla_get_u64(info->attrs[DI_HASH_POLICY]);
        switch (handler_type) {
                case HDL_HANDLE:
                        pr_info("[VUL_PATCH] uprobe handler\n");
                        uc->handler = u_handler_map[hid].handler;
                        break;
                case HDL_RET:
                        pr_info("[VUL_PATCH] uprobe ret_handler\n");
                        uc->ret_handler = u_ret_handler_map[hid].ret;
                        break;
                default:
                        pr_err("[VUL_PATCH] Invalid uprobe handler type! \n");
        }

        // store uprobe info here
		add_u_patch_node(pi, uc,debuggee_inode,offset);

        int ret = uprobe_register(debuggee_inode, offset, uc);
        if(ret < 0){
                pr_err("[VUL_PATCH] register uprobe: fail\n");
                return ret;
        }
        pr_info("[VUL_PATCH] register uprobe: success\n");
	return ret;
}

static int hello_world(struct inode *debuggee_inode,uint64_t offset,struct patch_info* pi,struct genl_info *info,int handler_type){
        pr_info("[VUL_PATCH] hello world!\n");
		return 0;
}

typedef int (*user_policy_func_t) (struct inode *,uint64_t ,struct patch_info* ,struct genl_info *,int);

static struct {
        user_policy_func_t upolicy_func;
} u_policy_func_map [20];

int upolicy_func_num;

static void addUpolicyFunc(user_policy_func_t func){
	upolicy_func_num++;
	u_policy_func_map[upolicy_func_num].upolicy_func=func;
	return;
}

static void initUpolicyFunc(void){
	pr_info("init the Upolicy Func\n");
	upolicy_func_num=0;
	addUpolicyFunc(vulsheild_register_uprobe);
	addUpolicyFunc(hello_world);
	return;
}

static int launch_user_policy(struct sk_buff *skb, struct genl_info *info){
	pr_info("[VUL_PATCH] launch_user_policy: enter\n");
	user_policy_func_t usr_policy_func=NULL;
	int hid = nla_get_u64(info->attrs[DI_HASH_POLICY]);
	usr_policy_func=u_policy_func_map[hid].upolicy_func;
	int ret = 0;

	ret = verify(info);
	if(!OK(ret)){
		return ret;
	}

	pr_info("[VUL_PATCH] launch_user_policy: verification done.\n");

	struct patch_info* pi = (struct patch_info*)kmalloc(sizeof(patch_info), GFP_KERNEL);
	const char* TARGET_BINARY = (const char *)nla_data(info->attrs[DI_FILE]);
	struct path path;
	ret = kern_path(TARGET_BINARY, LOOKUP_FOLLOW, &path);
	if (ret) {
		pr_err("cannot find the target binary\n");
        return -1;
    }

	pr_info("[VUL_PATCH] launch_user_policy: kern path done.\n");

	struct inode *debuggee_inode =igrab(path.dentry->d_inode);
    path_put(&path);

	pr_info("[VUL_PATCH] launch_user_policy: inode grab done.\n");

	load_patch_info(info, pi);
	int handler_type=nla_get_u64(info->attrs[DI_HANDLER1]);
	uint64_t offset = nla_get_u64(info->attrs[DI_BIN_OFFSET]);

	pr_info("[VUL_PATCH] launch_user_policy: load patch done.\n");

	usr_policy_func(debuggee_inode, offset, pi, info, handler_type);

	pr_info("[VUL_PATCH] launch_user_policy: first policy done.\n");

	if(nla_get_u64(info->attrs[DI_BIN_OFFSET_2])!=0){
		uint64_t offset = nla_get_u64(info->attrs[DI_BIN_OFFSET_2]);
		struct patch_info* pi_each=(struct patch_info*)kmalloc(sizeof(patch_info), GFP_KERNEL);
		memcpy(pi_each,pi,sizeof(patch_info));
		pi_each->state_val=nla_get_u64(info->attrs[DI_STATE_2_VAL]);
		pi_each->state_val_type=nla_get_u64(info->attrs[DI_STATE_2_VAL_TYPE]);
		pi_each->state_val_offset=nla_get_u64(info->attrs[DI_STATE_2_VAL_OFFSET]);
		pi_each->state_code=nla_get_u64(info->attrs[DI_STATE_2_CODE]);
		pi_each->policy = nla_get_u64(info->attrs[DI_HASH_ACTION2]);
		handler_type=nla_get_u64(info->attrs[DI_HANDLER2]);
		usr_policy_func(debuggee_inode, offset, pi_each,info,handler_type);
		pr_info("[VUL_PATCH] launch_user_policy: second policy done.\n");
	}
	if(nla_get_u64(info->attrs[DI_BIN_OFFSET_3])!=0){
		uint64_t offset = nla_get_u64(info->attrs[DI_BIN_OFFSET_3]);
		struct patch_info* pi_each=(struct patch_info*)kmalloc(sizeof(patch_info), GFP_KERNEL);
		memcpy(pi_each,pi,sizeof(patch_info));
		pi_each->state_val=nla_get_u64(info->attrs[DI_STATE_3_VAL]);
		pi_each->state_val_type=nla_get_u64(info->attrs[DI_STATE_3_VAL_TYPE]);
		pi_each->state_val_offset=nla_get_u64(info->attrs[DI_STATE_3_VAL_OFFSET]);
		pi_each->state_code=nla_get_u64(info->attrs[DI_STATE_3_CODE]);
		pi_each->policy = nla_get_u64(info->attrs[DI_HASH_ACTION3]);
		handler_type=nla_get_u64(info->attrs[DI_HANDLER3]);
		usr_policy_func(debuggee_inode, offset, pi_each,info,handler_type);
		pr_info("[VUL_PATCH] launch_user_policy: third policy done.\n");
	}
	return ret;
}

// --------------------- Netlink 

/*
 * A "policy" is a bunch of rules. The kernel will validate the request's fields
 * match these data types (and other defined constraints) for us.
 */
struct nla_policy const user_policy[DI_COUNT] = {
	[DI_SPACE] = { .type = NLA_U64 },
	[DI_HASH_DETECT] = { .type = NLA_STRING },
	[DI_HASH_POLICY] = { .type = NLA_U64 },
	[DI_HASH_ACTION1] = { .type = NLA_U64 },
	[DI_HASH_ACTION2] = { .type = NLA_U64 },
	[DI_HASH_ACTION3] = { .type = NLA_U64 },
	[DI_HANDLER1] = { .type = NLA_U64 },
	[DI_HANDLER2] = { .type = NLA_U64 },
	[DI_HANDLER3] = { .type = NLA_U64 },
	[DI_FILE] = { .type = NLA_STRING },
	[DI_BIN_OFFSET] = { .type = NLA_U64 },
	[DI_BIN_OFFSET_2] = { .type = NLA_U64 },
	[DI_BIN_OFFSET_3] = { .type = NLA_U64 },
	[DI_OP_0] = { .type = NLA_U64 },
	[DI_OP_1] = { .type = NLA_U64 },
	[DI_OP_2] = { .type = NLA_U64 },
	[DI_OP_3] = { .type = NLA_U64 },
	[DI_OP_4] = { .type = NLA_U64 },
	[DI_OP_5] = { .type = NLA_U64 },
	[DI_OP_6] = { .type = NLA_U64 },
	[DI_ARG_1_TYPE] = { .type = NLA_U64 },
	[DI_ARG_1_VAL] = { .type = NLA_U64 },
	[DI_ARG_1_OFFSET] = { .type = NLA_U64 },
	[DI_ARG_2_TYPE] = { .type = NLA_U64 },
	[DI_ARG_2_VAL] = { .type = NLA_U64 },
	[DI_ARG_2_OFFSET] = { .type = NLA_U64 },
	[DI_ARG_3_TYPE] = { .type = NLA_U64 },
	[DI_ARG_3_VAL] = { .type = NLA_U64 },
	[DI_ARG_3_OFFSET] = { .type = NLA_U64 },
	[DI_ARG_4_TYPE] = { .type = NLA_U64 },
	[DI_ARG_4_VAL] = { .type = NLA_U64 },
	[DI_ARG_4_OFFSET] = { .type = NLA_U64 },
	[DI_ARG_5_TYPE] = { .type = NLA_U64 },
	[DI_ARG_5_VAL] = { .type = NLA_U64 },
	[DI_ARG_5_OFFSET] = { .type = NLA_U64 },
	[DI_ARG_6_TYPE] = { .type = NLA_U64 },
	[DI_ARG_6_VAL] = { .type = NLA_U64 },
	[DI_ARG_6_OFFSET] = { .type = NLA_U64 },
	[DI_ARG_7_TYPE] = { .type = NLA_U64 },
	[DI_ARG_7_VAL] = { .type = NLA_U64 },
	[DI_ARG_7_OFFSET] = { .type = NLA_U64 },
	[DI_ARG_8_TYPE] = { .type = NLA_U64 },
	[DI_ARG_8_VAL] = { .type = NLA_U64 },
	[DI_ARG_8_OFFSET] = { .type = NLA_U64 },
	[DI_STATE_1_VAL]={ .type = NLA_U64 },
	[DI_STATE_1_VAL_TYPE]={ .type = NLA_U64 },
	[DI_STATE_1_VAL_OFFSET]={ .type = NLA_U64 },
	[DI_STATE_1_CODE] = { .type = NLA_U64 },
	[DI_STATE_2_VAL]={ .type = NLA_U64 },
	[DI_STATE_2_VAL_TYPE]={ .type = NLA_U64 },
	[DI_STATE_2_VAL_OFFSET]={ .type = NLA_U64 },
	[DI_STATE_2_CODE] = { .type = NLA_U64 },
	[DI_STATE_3_VAL]={ .type = NLA_U64 },
	[DI_STATE_3_VAL_TYPE]={ .type = NLA_U64 },
	[DI_STATE_3_VAL_OFFSET]={ .type = NLA_U64 },
	[DI_STATE_3_CODE] = { .type = NLA_U64 },
	[DI_RIP] = { .type = NLA_U64 },
	[DI_RIP_TYPE] = { .type = NLA_U64 },
	[DI_RAX] = { .type = NLA_U64 },
	[DI_ERROR_CODE] = { .type = NLA_U64 },
	[DI_WRITE_ADDR_OFFSET] = { .type = NLA_U64 },
	[DI_WRITE_OP] = { .type = NLA_U64 },
};

static const struct genl_ops ops[] = {
	/*
	 * This is what tells the kernel to use the function above whenever
	 * userspace sends requests.
	 * Add more array entries if you define more sample_operations.
	 */

	// User Space
	{
		.cmd = USER_CVE,
		.doit = launch_user_policy,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
		/* Before kernel 5.2, each op had its own policy. */
		.policy = user_policy,
#endif
	},
	// Kernel Space
	{
		.cmd = KERNEL_CVE,
		.doit = launch_kernel_policy,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
		/* Before kernel 5.2, each op had its own policy. */
		.policy = user_policy,
#endif
	},
};

/* Descriptor of our Generic Netlink family */
static struct genl_family vp_family = {
	.name = SAMPLE_FAMILY,
	.version = 1,
	.maxattr = DI_MAX,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
	/* Since kernel 5.2, the policy is family-wide. */
	.policy = user_policy,
#endif
	.module = THIS_MODULE,
	.ops = ops,
	.n_ops = ARRAY_SIZE(ops),
};

static int test_init(void)
{
	int error;

	pr_info("[VUL_PATCH] _+_+_+_+_+_+_ INIT _+_+_+_+_+_+_ \n");

	pr_debug("[VUL_PATCH] Registering Generic Netlink family...\n");
	error = genl_register_family(&vp_family);
	if (error) {
		pr_err("[VUL_PATCH] Family registration failed: %d\n", error);
		return error;
	}
	pr_info("the DI_SPACE IS %d\n",DI_SPACE);
	pr_info("the DI_COUNT IS %d\n",DI_COUNT);
	initKpolicyFunc();
	initUpolicyFunc();
	init_shield_quarantine();

	return 0;
}

static void test_exit(void)
{	
	exit_shield_quarantine();
	
	shield_quarantine_all_reduce();
	del_all_k_patch_node();
	del_all_u_patch_node();
	genl_unregister_family(&vp_family);
	kfree(isolation_obj);
	pr_info("[VUL_PATCH]: _+_+_+_+_+_+_ EXIT _+_+_+_+_+_+_ \n");
}

module_init(test_init);
module_exit(test_exit);

MODULE_LICENSE("GPL");

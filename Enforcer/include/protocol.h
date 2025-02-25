#define SAMPLE_FAMILY "Sample Family"
#define VUL_PATCH_FAMILY "Vul_patch Family"


enum vuls{
	BUF_OVFL,
	UAF,
	INT_OVFL,
	NULL_DEREF,
	// kernel space bug
	K_OUTOF_BOUND,
	KERNEL_CVE,
	USER_CVE,
	/*List more for different vulnerabilities*/
};

enum op{
	OP_AND,
	OP_XOR,
	OP_OR,
	OP_ADD,
	OP_MUL,
	OP_DIV,
	OP_REM,
	OP_GT,
	OP_GE,
	OP_LT,
	OP_LE,
	OP_EQ,
	OP_NE,
	OP_RVAL, // Special OP for returning rval: arg1 op_rval arg2 = arg2
	OP_SHL,
	OP_SHR,
	OP_AND_BOOL,
	OP_OR_BOOL,
	OP_UNKOWN,
	/*Temporary hack for arithmetic on target*/
};

enum x86_reg{
	/*Register in x86-64*/
	AX,
	BX,
	CX,
	DX,
	SI,
	DI,
	BP,
	SP,
	R8,
	R9,
	R10,
	R11,
	R12,
	R13,
	R14,
	R15,
	/* Vulshield regs*/
	VR1,
	VR2,
	VR3,
	VR4,
	VR5,
	VR6,
	VR7,
	VR8,
	VR9,
};

enum reg_type{
	RT_ADDR,
	RT_VAL,
};

enum arg_type{
	ARG_ADDR, // (%rax)
	ARG_REG, // %rax
	ARG_NUM, // 1
	ARG_STATE_REG_COUNT,
	ARG_STATE_REG_RANGE,
	ARG_STATE_NUM,
	ARG_STRLEN_U, // strlen(%rax)
	ARG_STRLEN_K,
	ARG_VALID,
	ARG_VR_1,
};

enum action{
	ACT_RIP,
	ACT_RET, // potential RIP
	ACT_QRT,
	ACT_NOP,
	ACT_INC,
	ACT_DEC,
	ACT_TEST,
	ACT_INIT_COMPLETION,
	ACT_SET_COMPLETION,
	ACT_SLEEP,
	ACT_RECORD_RAX,
	ACT_RECORD_RBX,
	ACT_RECORD_RCX,
	ACT_RECORD_RDX,
	ACT_RECORD_RSI,
	ACT_RECORD_RDI,
	ACT_RECORD_R8,
	ACT_RECORD_R9,
	ACT_RECORD_R10,
	// User Space
	ACT_KILL,
	ACT_RECORD_MALLOC,
	ACT_WARMING,
	ACT_HANG,
};

enum handler{
	HDL_PRE,
	HDL_POST,
	HDL_FAULT,
	HDL_HANDLE,
	HDL_RET,
};

enum ip{
	IP_ABS,
	IP_REL,
	IP_NO,
};

enum debug_info {
	// Kernel SPACE 0 & User SPACE 1
	DI_SPACE = 1, 	
	// DETECT:
	// - 1: Expression detection
	DI_HASH_DETECT,
	DI_HASH_POLICY,
	// ACTION:
	// - 0: Change IP
	// - 2: Quanrantine(ACT_QRT)
	// ACT_INIT_COMPLETION: init the completion value
	// ACT_KFREE: use the vulshield free to deallocate the target object 
	DI_HASH_ACTION1,
	DI_HASH_ACTION2,
	DI_HASH_ACTION3,
	//HANDLER:
	//HDL_POST:post handler
	//HDL_PRE:pre handler
	DI_HANDLER1,
	DI_HANDLER2,
	DI_HANDLER3,
	DI_FILE, 	  	// Kernel SPACE: Symbol Name & User SPACE: Binary Path
	DI_BIN_OFFSET,// Kernel SPACE: Offset to symbol & User SPACE: Offset to the binary
	DI_BIN_OFFSET_2,// Backup Offset
	DI_BIN_OFFSET_3,// Backup Offset
	// Parsing Expression
	// arg1   arg2         arg3   arg4
	//  |- op1 -|           |- op2 -|      arg5   arg6
	//      |------- op3 -------|           |- op4 -|       arg7   arg8
	//                      |------- op5 -------|            |- op6 -| 
	//                                       |------- op7 -------| 
	//                                                  |
	//                                              bool result
	DI_OP_0,                                                
	DI_OP_1,
	DI_OP_2,
	DI_OP_3,
	DI_OP_4,
	DI_OP_5,
	DI_OP_6,

	//Type:the type of args,such as:ARG_NUM/ARG_REG/ARG_ADDR, which means the args is a number/value of reg/address
	DI_ARG_1_TYPE,
	DI_ARG_1_VAL,//number or the regs(such as 0 or AX/BX/CX/R11/R12)
	DI_ARG_1_OFFSET,//if the target vaule is rax+11,then the offset is 11;if the target addr is 0x8(rax),then the offset is 0x8
	
	DI_ARG_2_TYPE,
	DI_ARG_2_VAL,
	DI_ARG_2_OFFSET,
	
	DI_ARG_3_TYPE,
	DI_ARG_3_VAL,
	DI_ARG_3_OFFSET,
	
	DI_ARG_4_TYPE,
	DI_ARG_4_VAL,
	DI_ARG_4_OFFSET,
	
	DI_ARG_5_TYPE,
	DI_ARG_5_VAL,
	DI_ARG_5_OFFSET,

	DI_ARG_6_TYPE,
	DI_ARG_6_VAL,
	DI_ARG_6_OFFSET,

	DI_ARG_7_TYPE,
	DI_ARG_7_VAL,
	DI_ARG_7_OFFSET,

	DI_ARG_8_TYPE,
	DI_ARG_8_VAL,
	DI_ARG_8_OFFSET,
	// For ACT_RIP
	// Type:IP_ABS/IP_REL
	// if the type is IP_REL,then the jump target: regs->rip=regs->rip+DI_RIP;
	// if the type is IP_ABS,then the jump target: regs->rip=DI_RIP;
	// Plz note that:  regs->rip is the starting address of the next instruction to be executed. 
	// if the handler is POST,for example,0xdeadbeef is the probe instruction,and the DI_BIN_OFFSET=(0xdeadbeef - func_entry),the regs->rip=0xdeadbeef+size(the probe inst))
	DI_RIP,//number
	DI_RIP_TYPE,
	// FOR ACT_RET
	DI_RAX,// if the jump target is the return inst,and we need change the return value,then set the DI_RAX.
	DI_ERROR_CODE,//not used
	//FOR ACT_WRITE
	DI_WRITE_ADDR_OFFSET,//if we need to write the memory, we need to handle such case: ldr 0x32(%rax),%rbx; and we need to store 0 to 0x8(%rbx). so we could choose the state value is addr type,and the DI_WRITE_ADDR_OFFSET is 0x8.
	DI_WRITE_OP,// if we need to write the value of (%rax xor 0) to %rax, then we could choose the WRITE_OP is OP_AND
	// FOR STATE
	// to handle the case that need other value,such sleep(10000)/free(obj)/write 0 to %rbx(rbx is the state value;type is reg;write offset is 0;state code is 0,and the write op is OP_AND/OP_RVAL ) 
	DI_STATE_1_VAL,
	DI_STATE_1_VAL_TYPE,
	DI_STATE_1_VAL_OFFSET,
	DI_STATE_1_CODE,
	DI_STATE_2_VAL,
	DI_STATE_2_VAL_TYPE,
	DI_STATE_2_VAL_OFFSET,
	DI_STATE_2_CODE,
	DI_STATE_3_VAL,
	DI_STATE_3_VAL_TYPE,
	DI_STATE_3_VAL_OFFSET,
	DI_STATE_3_CODE,
	// TODO: Add constraint for op and rval
	DI_COUNT,
#define DI_MAX (DI_COUNT -1 )
};



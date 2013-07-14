#ifndef __HYPERVISOR_H
#define __HYPERVISOR_H

#include "libcflat.h"

struct vmcs {
	u32 revision_id; // vmcs revision identifier
	u32 abort; // VMX-abort indicator
	// VMCS data
	char data[0];
};

struct exec_regs {
	u64 r15;
	u64 r14;
	u64 r13;
	u64 r12;
	u64 r11;
	u64 r10;
	u64 r9;
	u64 r8;
	u64 rdi;
	u64 rsi;
	u64 rbp;
	u64 cr2;
	u64 rbx;
	u64 rdx;
	u64 rcx;
	u64 rax;
};

struct exec_cxt {
	struct vmcs *vmcs;
	struct exec_regs regs;
	void *stack;
	void *syscall_stack;
};

ulong fix_cr0_set, fix_cr0_clr;
ulong fix_cr4_set, fix_cr4_clr;

static union vmx_basic {
	u64 val;
	struct {
		u32 revision;
		u32	size : 13,
			: 3,
			width : 1,
			dual : 1,
			type : 4,
			insouts : 1,
			ctrl : 1;
	};
} basic;

static union vmx_ctrl_pin {
	u64 val;
	struct {
		u32 set, clr;
	};
} ctrl_pin;

static union vmx_ctrl_cpu {
	u64 val;
	struct {
		u32 set, clr;
	};
} ctrl_cpu[2];

static union vmx_ctrl_exit {
	u64 val;
	struct {
		u32 set, clr;
	};
} ctrl_exit;

static union vmx_ctrl_ent {
	u64 val;
	struct {
		u32 set, clr;
	};
} ctrl_enter;

static union vmx_ept_vpid {
	u64 val;
	struct {
		u32	: 16,
			super: 2,
			: 2,
			invept : 1,
			: 11;
		u32 	invvpid : 1;
	};
} ept_vpid;

struct descr {
	u16 limit;
	u64 addr;
};

enum Encoding
{
	// 16-Bit Control Fields
	VPID		= 0x0000ul,
	PINV		= 0x0002ul, // Posted-interrupt notification vector
	EPTP_IDX	= 0x0004ul, // EPTP index

	// 16-Bit Guest State Fields
	GUEST_SEL_ES		= 0x0800ul,
	GUEST_SEL_CS		= 0x0802ul,
	GUEST_SEL_SS		= 0x0804ul,
	GUEST_SEL_DS		= 0x0806ul,
	GUEST_SEL_FS		= 0x0808ul,
	GUEST_SEL_GS		= 0x080aul,
	GUEST_SEL_LDTR		= 0x080cul,
	GUEST_SEL_TR		= 0x080eul,
	GUEST_INT_STATUS	= 0x0810ul,

	// 16-Bit Host State Fields
	HOST_SEL_ES		= 0x0c00ul,
	HOST_SEL_CS		= 0x0c02ul,
	HOST_SEL_SS		= 0x0c04ul,
	HOST_SEL_DS		= 0x0c06ul,
	HOST_SEL_FS		= 0x0c08ul,
	HOST_SEL_GS		= 0x0c0aul,
	HOST_SEL_TR		= 0x0c0cul,

	// 64-Bit Control Fields
	IO_BITMAP_A		= 0x2000ul,
	IO_BITMAP_B		= 0x2002ul,
	MSR_BITMAP		= 0x2004ul,
	EXIT_MSR_ST_ADDR	= 0x2006ul,
	EXIT_MSR_LD_ADDR	= 0x2008ul,
	ENTER_MSR_LD_ADDR	= 0x200aul,
	VMCS_EXEC_PTR		= 0x200cul,
	TSC_OFFSET		= 0x2010ul,
	TSC_OFFSET_HI		= 0x2011ul,
	APIC_VIRT_ADDR		= 0x2012ul,
	APIC_ACCS_ADDR	= 0x2014ul,
	EPTP			= 0x201aul,
	EPTP_HI			= 0x201bul,

	// 64-Bit Readonly Data Field
	INFO_PHYS_ADDR	= 0x2400ul,

	// 64-Bit Guest State
	VMCS_LINK_PTR			= 0x2800ul,
	VMCS_LINK_PTR_HI		= 0x2801ul,
	GUEST_DEBUGCTL		= 0x2802ul,
	GUEST_DEBUGCTL_HI		= 0x2803ul,
	GUEST_EFER			= 0x2806ul,
	GUEST_PERF_GLOBAL_CTRL	= 0x2808ul,
	GUEST_PDPTE			= 0x280aul,

	// 64-Bit Host State
	HOST_EFER			= 0x2c02ul,
	HOST_PERF_GLOBAL_CTRL	= 0x2c04ul,

	// 32-Bit Control Fields
	PIN_CONTROLS		= 0x4000ul,
	CPU_EXEC_CTRL0	= 0x4002ul,
	EXC_BITMAP		= 0x4004ul,
	PF_ERROR_MASK		= 0x4006ul,
	PF_ERROR_MATCH	= 0x4008ul,
	CR3_TARGET_COUNT	= 0x400aul,
	EXI_CONTROLS		= 0x400cul,
	EXI_MSR_ST_CNT		= 0x400eul,
	EXI_MSR_LD_CNT	= 0x4010ul,
	ENT_CONTROLS		= 0x4012ul,
	ENT_MSR_LD_CNT	= 0x4014ul,
	ENT_INTR_INFO		= 0x4016ul,
	ENT_INTR_ERROR		= 0x4018ul,
	ENT_INST_LEN		= 0x401aul,
	TPR_THRESHOLD		= 0x401cul,
	CPU_EXEC_CTRL1	= 0x401eul,

	// 32-Bit R/O Data Fields
	VMX_INST_ERROR	= 0x4400ul,
	EXI_REASON		= 0x4402ul,
	EXI_INTR_INFO		= 0x4404ul,
	EXI_INTR_ERROR		= 0x4406ul,
	IDT_VECT_INFO		= 0x4408ul,
	IDT_VECT_ERROR		= 0x440aul,
	EXI_INST_LEN		= 0x440cul,
	EXI_INST_INFO		= 0x440eul,

	// 32-Bit Guest State Fields
	GUEST_LIMIT_ES		= 0x4800ul,
	GUEST_LIMIT_CS		= 0x4802ul,
	GUEST_LIMIT_SS		= 0x4804ul,
	GUEST_LIMIT_DS		= 0x4806ul,
	GUEST_LIMIT_FS		= 0x4808ul,
	GUEST_LIMIT_GS		= 0x480aul,
	GUEST_LIMIT_LDTR	= 0x480cul,
	GUEST_LIMIT_TR		= 0x480eul,
	GUEST_LIMIT_GDTR	= 0x4810ul,
	GUEST_LIMIT_IDTR	= 0x4812ul,
	GUEST_AR_ES		= 0x4814ul,
	GUEST_AR_CS		= 0x4816ul,
	GUEST_AR_SS		= 0x4818ul,
	GUEST_AR_DS 		= 0x481aul,
	GUEST_AR_FS		= 0x481cul,
	GUEST_AR_GS		= 0x481eul,
	GUEST_AR_LDTR		= 0x4820ul,
	GUEST_AR_TR		= 0x4822ul,
	GUEST_INTR_STATE	= 0x4824ul,
	GUEST_ACTV_STATE	= 0x4826ul,
	GUEST_SMBASE		= 0x4828ul,
	GUEST_SYSENTER_CS	= 0x482aul,

	// 32-Bit Host State Fields
	HOST_SYSENTER_CS	= 0x4c00ul,

	// Natural-Width Control Fields
	CR0_MASK		= 0x6000ul,
	CR4_MASK		= 0x6002ul,
	CR0_READ_SHADOW	= 0x6004ul,
	CR4_READ_SHADOW	= 0x6006ul,
	CR3_TARGET_0		= 0x6008ul,
	CR3_TARGET_1		= 0x600aul,
	CR3_TARGET_2		= 0x600cul,
	CR3_TARGET_3		= 0x600eul,

	// Natural-Width R/O Data Fields
	EXI_QUALIFICATION	= 0x6400ul,
	IO_RCX			= 0x6402ul,
	IO_RSI			= 0x6404ul,
	IO_RDI			= 0x6406ul,
	IO_RIP			= 0x6408ul,
	GUEST_LINEAR_ADDRESS	= 0x640aul,

	// Natural-Width Guest State Fields
	GUEST_CR0		= 0x6800ul,
	GUEST_CR3		= 0x6802ul,
	GUEST_CR4		= 0x6804ul,
	GUEST_BASE_ES		= 0x6806ul,
	GUEST_BASE_CS		= 0x6808ul,
	GUEST_BASE_SS		= 0x680aul,
	GUEST_BASE_DS		= 0x680cul,
	GUEST_BASE_FS		= 0x680eul,
	GUEST_BASE_GS		= 0x6810ul,
	GUEST_BASE_LDTR	= 0x6812ul,
	GUEST_BASE_TR		= 0x6814ul,
	GUEST_BASE_GDTR	= 0x6816ul,
	GUEST_BASE_IDTR	= 0x6818ul,
	GUEST_DR7		= 0x681aul,
	GUEST_RSP		= 0x681cul,
	GUEST_RIP		= 0x681eul,
	GUEST_RFLAGS		= 0x6820ul,
	GUEST_PENDING_DEBUG	= 0x6822ul,
	GUEST_SYSENTER_ESP	= 0x6824ul,
	GUEST_SYSENTER_EIP	= 0x6826ul,

	// Natural-Width Host State Fields
	HOST_CR0		= 0x6c00ul,
	HOST_CR3		= 0x6c02ul,
	HOST_CR4		= 0x6c04ul,
	HOST_BASE_FS		= 0x6c06ul,
	HOST_BASE_GS		= 0x6c08ul,
	HOST_BASE_TR		= 0x6c0aul,
	HOST_BASE_GDTR	= 0x6c0cul,
	HOST_BASE_IDTR	= 0x6c0eul,
	HOST_SYSENTER_ESP	= 0x6c10ul,
	HOST_SYSENTER_EIP	= 0x6c12ul,
	HOST_RSP		= 0x6c14ul,
	HOST_RIP		= 0x6c16ul
};

enum Reason
{
	VMX_EXC_NMI		= 0,
	VMX_EXTINT		= 1,
	VMX_TRIPLE_FAULT	= 2,
	VMX_INIT		= 3,
	VMX_SIPI		= 4,
	VMX_SMI_IO		= 5,
	VMX_SMI_OTHER		= 6,
	VMX_INTR_WINDOW	= 7,
	VMX_NMI_WINDOW	= 8,
	VMX_TASK_SWITCH	= 9,
	VMX_CPUID		= 10,
	VMX_GETSEC		= 11,
	VMX_HLT		= 12,
	VMX_INVD		= 13,
	VMX_INVLPG		= 14,
	VMX_RDPMC		= 15,
	VMX_RDTSC		= 16,
	VMX_RSM		= 17,
	VMX_VMCALL		= 18,
	VMX_VMCLEAR		= 19,
	VMX_VMLAUNCH		= 20,
	VMX_VMPTRLD		= 21,
	VMX_VMPTRST		= 22,
	VMX_VMREAD		= 23,
	VMX_VMRESUME		= 24,
	VMX_VMWRITE		= 25,
	VMX_VMXOFF		= 26,
	VMX_VMXON		= 27,
	VMX_CR			= 28,
	VMX_DR			= 29,
	VMX_IO			= 30,
	VMX_RDMSR		= 31,
	VMX_WRMSR		= 32,
	VMX_FAIL_STATE		= 33,
	VMX_FAIL_MSR		= 34,
	VMX_MWAIT		= 36,
	VMX_MTF		= 37,
	VMX_MONITOR		= 39,
	VMX_PAUSE		= 40,
	VMX_FAIL_MCHECK	= 41,
	VMX_TPR_THRESHOLD	= 43,
	VMX_APIC_ACCESS	= 44,
	VMX_GDTR_IDTR		= 46,
	VMX_LDTR_TR		=47,
	VMX_EPT_VIOLATION	= 48,
	VMX_EPT_MISCONFIG	= 49,
	VMX_INVEPT		= 50,
	VMX_PREEMPT		= 52,
	VMX_INVVPID		= 53,
	VMX_WBINVD		= 54,
	VMX_XSETBV		= 55
};

#define X86_EFLAGS_CF	0x00000001 /* Carry Flag */
#define X86_EFLAGS_ZF	0x00000040 /* Zero Flag */

enum Ctrl_exi
{
	EXI_HOST_64             = 1UL << 9,
	EXI_LOAD_PERF			= 1UL << 12,
	EXI_INTA                = 1UL << 15,
	EXI_LOAD_EFER           = 1UL << 21,
};

enum Ctrl_ent
{
	ENT_GUEST_64            = 1UL << 9,
	ENT_LOAD_EFER           = 1UL << 15,
};

enum Ctrl_pin
{
	PIN_EXTINT              = 1ul << 0,
	PIN_NMI                 = 1ul << 3,
	PIN_VIRT_NMI            = 1ul << 5,
};

enum Ctrl0
{
	CPU_INTR_WINDOW 		= 1ul << 2,
	CPU_HLT 			= 1ul << 7,
	CPU_INVLPG			= 1ul << 9,
	CPU_CR3_LOAD			= 1ul << 15,
	CPU_CR3_STORE			= 1ul << 16,
	CPU_TPR_SHADOW			= 1ul << 21,
	CPU_NMI_WINDOW			= 1ul << 22,
	CPU_IO				= 1ul << 24,
	CPU_IO_BITMAP			= 1ul << 25,
	CPU_SECONDARY			= 1ul << 31,
};

enum Ctrl1
{
	CPU_EPT 			= 1ul << 1,
	CPU_VPID			= 1ul << 5,
	CPU_URG 			= 1ul << 7,
};

#define SEL_NULL_DESC   0x0
#define SEL_KERN_CODE_64   0x8
#define SEL_KERN_DATA_64   0x10
#define SEL_USER_CODE_64   0x18
#define SEL_USER_DATA_64   0x20
#define SEL_CODE_32   0x28
#define SEL_DATA_32   0x30
#define SEL_CODE_16   0x38
#define SEL_DATA_16   0x40
#define SEL_TSS_RUN   0x48

#define SAVE_GPR			\
		"push %rax \n\t"		\
		"push %rbx \n\t"		\
		"push %rcx \n\t"		\
		"push %rdx \n\t"		\
		"push %rbp \n\t"		\
		"push %rsi \n\t"		\
		"push %rdi \n\t"		\
		"push %r8 \n\t"		\
		"push %r9 \n\t"		\
		"push %r10 \n\t"		\
		"push %r11 \n\t"		\
		"push %r12 \n\t"		\
		"push %r13 \n\t"		\
		"push %r14 \n\t"		\
		"push %r15 \n\t"		

#define LOAD_GPR			\
		"pop %r15 \n\t"		\
		"pop %r14 \n\t"		\
		"pop %r13 \n\t"		\
		"pop %r12 \n\t"		\
		"pop %r11 \n\t"		\
		"pop %r10 \n\t"		\
		"pop %r9 \n\t"		\
		"pop %r8 \n\t"		\
		"pop %rdi \n\t"		\
		"pop %rsi \n\t"		\
		"pop %rbp \n\t"		\
		"pop %rdx \n\t"		\
		"pop %rcx \n\t"		\
		"pop %rbx \n\t"		\
		"pop %rax \n\t"		

#define CR0_PG		1ul << 31
#define CR0_PE		1ul << 0
#define CR4_VMXE	1ul << 0
#define CR4_PCIDE	1ul << 17
#define CR4_PAE		1ul << 5
#define MSR_EFER_LMA	1ul << 10
#define MSR_EFER_LME	1ul << 8

#define VMX_IO_SIZE_MASK		0x7
#define _VMX_IO_BYTE			1
#define _VMX_IO_WORD			2
#define _VMX_IO_LONG			3
#define VMX_IO_DIRECTION_MASK		1ul << 3
#define VMX_IO_IN			1ul << 3
#define VMX_IO_OUT			0
#define VMX_IO_STRING			1ul << 4
#define VMX_IO_REP			1ul << 5
#define VMX_IO_OPRAND_DX		1ul << 6
#define VMX_IO_PORT_MASK		0xFFFF0000
#define VMX_IO_PORT_SHIFT		16

#endif



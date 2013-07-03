#ifndef __HYPERVISOR_H
#define __HYPERVISOR_H

#include "libcflat.h"

struct vmcs {
	u32 revision_id; // vmcs revision identifier
	u32 abort; // VMX-abort indicator
	// VMCS data
	char data[0];
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
} ctrl_ent;

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

enum Encoding
{
	// 16-Bit Control Fields
	VPID	= 0x0000ul,

	// 16-Bit Guest State Fields
	GUEST_SEL_ES	= 0x0800ul,
	GUEST_SEL_CS	= 0x0802ul,
	GUEST_SEL_SS	= 0x0804ul,
	GUEST_SEL_DS	= 0x0806ul,
	GUEST_SEL_FS	= 0x0808ul,
	GUEST_SEL_GS	= 0x080aul,
	GUEST_SEL_LDTR	= 0x080cul,
	GUEST_SEL_TR	= 0x080eul,
};

#define CPU_SECONDARY		1ul << 31
#define CPU_EPT			1ul << 1
#define CPU_VPID		1ul << 5
#define CPU_HLT			1ul << 7
#define CPU_IO			1ul << 24
#define CPU_IO_BITMAP		1ul << 25
#define CPU_URG			1ul << 7

#define X86_EFLAGS_CF	0x00000001 /* Carry Flag */
#define X86_EFLAGS_ZF	0x00000040 /* Zero Flag */



#endif



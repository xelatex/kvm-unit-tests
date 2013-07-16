#include "libcflat.h"
#include "processor.h"
#include "vm.h"
#include "desc.h"
#include "vmx.h"
#include "msr.h"
#include "smp.h"
#include "io.h"


int fails = 0, tests = 0;
u32 *vmxon_region;
struct vmcs *vmcs_root;
void *io_bmp1, *io_bmp2;
void *msr_bmp;
u32 vpid_ctr;
char *guest_stack, *host_stack;
char *guest_syscall_stack, *host_syscall_stack;
u32 ctrl_pin, ctrl_enter, ctrl_exit, ctrl_cpu[2];
ulong fix_cr0_set, fix_cr0_clr;
ulong fix_cr4_set, fix_cr4_clr;
struct regs regs;

extern u64 gdt64_desc[];
extern u64 idt_descr[];
extern u64 tss_descr[];
extern void *entry_vmx;
extern void *entry_sysenter;
extern void *entry_guest;

void report(const char *name, int result)
{
	++tests;
	if (result)
		printf("PASS: %s\n", name);
	else {
		printf("FAIL: %s\n", name);
		++fails;
	}
}

u64 inline get_rflags(void)
{
	u64 r;
	asm volatile("pushf; pop %0\n\t" : "=q"(r) :: "cc");
	return r;
}

void inline set_rflags(u64 r)
{
	asm volatile("push %0; popf\n\t" :: "q"(r) : "cc");
}

int vmcs_clear(struct vmcs *vmcs)
{
	bool ret;
	asm volatile ("vmclear %1; seta %0" : "=q" (ret) : "m" (vmcs) : "cc");
	return !ret;
}

u64 vmcs_read(enum Encoding enc)
{
	u64 val;
	asm volatile ("vmread %1, %0" : "=rm" (val) : "r" ((u64)enc) : "cc");
	return val;
}

int vmcs_write(enum Encoding enc, u64 val)
{
	bool ret;
	asm volatile ("vmwrite %1, %2; seta %0"
		: "=q"(ret) : "rm" (val), "r" ((u64)enc) : "cc");
	return !ret;
}

int make_vmcs_current(struct vmcs *vmcs)
{
	bool ret;

	asm volatile ("vmptrld %1; seta %0" : "=q" (ret) : "m" (vmcs) : "cc");
	return !ret;
}

int save_vmcs(struct vmcs **vmcs)
{
	bool ret;

	asm volatile ("vmptrst %1; seta %0" : "=q" (ret) : "m" (*vmcs) : "cc");
	return !ret;
}

// entry_vmx
asm(
	".align	4, 0x90 \n\t"
	".globl	entry_vmx \n\t"
	"entry_vmx: \n\t"
	SAVE_GPR
	"	call	vmx_handler \n\t"
	LOAD_GPR
	"	vmresume\n\t"
);

// entry_sysenter
asm(
	".align	4, 0x90 \n\t"
	".globl	entry_sysenter \n\t"
	"entry_sysenter: \n\t"
	SAVE_GPR
	"	and	$0xf, %rax \n\t"
	"	push	%rax \n\t"
	"	call	syscall_handler \n\t"
);

void syscall_handler(u64 syscall_no)
{
	printf("Here in syscall_handler, syscall_no = %d\n", syscall_no);
}

void vmx_run()
{
	bool ret;
	printf("Now run vm.\n\n");
	asm volatile("vmlaunch \n\t seta %0\n\t":"=m"(ret));
	printf("VMLAUNCH error, ret=%d\n", ret);
}

void vmx_resume()
{
	asm volatile(LOAD_GPR
		"vmresume\n\t");
	// VMRESUME fail if reach here
}

void print_vmexit_info()
{
	u64 guest_rip, guest_rsp;
	ulong reason = vmcs_read(EXI_REASON) & 0xff;
	ulong exit_qual = vmcs_read(EXI_QUALIFICATION);
	guest_rip = vmcs_read(GUEST_RIP);
	guest_rsp = vmcs_read(GUEST_RSP);
	printf("VMEXIT info:\n");
	printf("\tvmexit reason = %d\n", reason);
	printf("\texit qualification = 0x%x\n", exit_qual);
	printf("\tBit 31 of reason = %x\n", (vmcs_read(EXI_REASON) >> 31) & 1);
	printf("\tguest_rip = 0x%llx\n", guest_rip);
	printf("\tRAX=0x%llx    RBX=0x%llx    RCX=0x%llx    RDX=0x%llx\n",
		regs.rax, regs.rbx, regs.rcx, regs.rdx);
	printf("\tRSP=0x%llx    RBP=0x%llx    RSI=0x%llx    RDI=0x%llx\n",
		guest_rsp, regs.rbp, regs.rsi, regs.rdi);
	printf("\tR8 =0x%llx    R9 =0x%llx    R10=0x%llx    R11=0x%llx\n",
		regs.r8, regs.r9, regs.r10, regs.r11);
	printf("\tR12=0x%llx    R13=0x%llx    R14=0x%llx    R15=0x%llx\n",
		regs.r12, regs.r13, regs.r14, regs.r15);
}

void test_vmclear(void)
{
	u64 rflags;

	rflags = get_rflags() | X86_EFLAGS_CF | X86_EFLAGS_ZF;
	set_rflags(rflags);
	report("test vmclear", vmcs_clear(vmcs_root) == 0);
}

void test_vmxoff(void)
{
	bool ret;
	u64 rflags;

	rflags = get_rflags() | X86_EFLAGS_CF | X86_EFLAGS_ZF;
	set_rflags(rflags);
	asm volatile ("vmxoff; seta %0 \n\t" : "=q"(ret) :: "cc");
	report("test vmxoff", ret);
}

void vmx_exit(void)
{
	test_vmxoff();
	printf("\nSUMMARY: %d tests, %d failures\n", tests, fails);
	exit(fails ? -1 : 0);
}

void vmx_handler()
{
	u64 guest_rip;
	ulong reason = vmcs_read(EXI_REASON) & 0xff;
	//ulong exit_qual = vmcs_read(EXI_QUALIFICATION);

	if ((read_cr4() & CR4_PAE) && (read_cr0() & CR0_PG)
		&& !(rdmsr(MSR_EFER) & EFER_LMA))
		printf("ERROR : PDPTEs should be checked\n");

	guest_rip = vmcs_read(GUEST_RIP);

	switch (reason) {
		case VMX_VMCALL:
			switch (regs.rax){
				case TEST_VMRESUME:
					regs.rax = 0xFFFF;
					break;
				default:
					printf("ERROR : Invalid VMCALL param : %d\n", regs.rax);
			}
			vmcs_write(GUEST_RIP, guest_rip + 3);
			goto vmx_resume;
		case VMX_IO:
			print_vmexit_info();
			break;
		case VMX_HLT:
			printf("\nVM exit.\n");
			vmx_exit();
			// Should not reach here
			goto vmx_exit;
		case VMX_EXC_NMI:
		case VMX_EXTINT:
		case VMX_INVLPG:
		case VMX_CR:
		case VMX_EPT_VIOLATION:
		default:
			break;
	}
	printf("ERROR : Unhandled vmx exit.\n");
	print_vmexit_info();
vmx_exit:
	exit(-1);
vmx_resume:
	vmx_resume();
	// Should not reach here
	exit(-1);
}

void test_vmresume()
{
	u64 rax;
	u64 rsp, resume_rsp;

	rax = 0;
	asm volatile("mov %%rsp, %0\n\t" : "=r"(rsp));
	asm volatile("mov %2, %%rax\n\t"
		"vmcall\n\t"
		"mov %%rax, %0\n\t"
		"mov %%rsp, %1\n\t"
		: "=r"(rax), "=r"(resume_rsp)
		: "g"(TEST_VMRESUME));
	report("test vmresume", (rax == 0xFFFF) && (rsp == resume_rsp));
}

// entry_guest
asm(
	".align	4, 0x90 \n\t"
	".globl	entry_guest \n\t"
	"entry_guest: \n\t"
	"	call	guest_main \n\t"
	"	hlt \n\t"
);

void guest_main(void)
{
	// If reach here, VMLAUNCH runs OK
	report("test vmlaunch", 1);
	printf("cr0 in guest = %llx\n", read_cr0());
	printf("cr3 in guest = %llx\n", read_cr3());
	printf("cr4 in guest = %llx\n", read_cr4());
	printf("\nHello World!\n");
	test_vmresume();
	//asm volatile("mov $0x1234567890ABCDEF, %rax\n\t");
	//asm volatile("vmcall\n\t");
	//asm volatile("shr $0x20, %rax\n\t");
	//asm volatile("vmcall\n\t");
}

void init_vmcs_ctrl(void)
{
	// 26.2 CHECKS ON VMX CONTROLS AND HOST-STATE AREA
	// 26.2.1.1
	vmcs_write(PIN_CONTROLS, ctrl_pin);
	// Disable VMEXIT of IO instruction
	vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu[0]);
	if (ctrl_cpu_rev[0].set & CPU_SECONDARY){
		ctrl_cpu[1] |= ctrl_cpu_rev[1].set & ctrl_cpu_rev[1].clr;
		vmcs_write(CPU_EXEC_CTRL1, ctrl_cpu[1]);
	}
	vmcs_write(CR3_TARGET_COUNT, 0);
	io_bmp1 = alloc_page();
	io_bmp2 = alloc_page();
	memset(io_bmp1, 0, PAGE_SIZE);
	memset(io_bmp2, 0, PAGE_SIZE);
	vmcs_write(IO_BITMAP_A, (u64)io_bmp1);
	vmcs_write(IO_BITMAP_B, (u64)io_bmp2);
	msr_bmp = alloc_page();
	memset(msr_bmp, 0, PAGE_SIZE);
	vmcs_write(MSR_BITMAP, (u64)msr_bmp);
	vmcs_write(VPID, ++vpid_ctr);
}

void init_vmcs_host(void)
{
	// 26.2 CHECKS ON VMX CONTROLS AND HOST-STATE AREA
	// 26.2.1.2
	vmcs_write(HOST_EFER, rdmsr(MSR_EFER));

	// 26.2.1.3
	vmcs_write(ENT_CONTROLS, ctrl_enter);
	vmcs_write(EXI_CONTROLS, ctrl_exit);

	// 26.2.2
	vmcs_write(HOST_CR0, read_cr0());
	vmcs_write(HOST_CR3, read_cr3());
	vmcs_write(HOST_CR4, read_cr4());
	vmcs_write(HOST_SYSENTER_ESP, (u64)(host_syscall_stack + PAGE_SIZE - 1));
	vmcs_write(HOST_SYSENTER_EIP, (u64)(&entry_sysenter));
	vmcs_write(HOST_SYSENTER_CS,  SEL_KERN_CODE_64);

	// 26.2.3
	vmcs_write(HOST_SEL_CS, SEL_KERN_CODE_64);
	vmcs_write(HOST_SEL_SS, SEL_KERN_DATA_64);
	vmcs_write(HOST_SEL_DS, SEL_KERN_DATA_64);
	vmcs_write(HOST_SEL_ES, SEL_KERN_DATA_64);
	vmcs_write(HOST_SEL_FS, SEL_KERN_DATA_64);
	vmcs_write(HOST_SEL_GS, SEL_KERN_DATA_64);
	vmcs_write(HOST_SEL_TR, SEL_TSS_RUN);
	vmcs_write(HOST_BASE_TR,   (u64)tss_descr);
	vmcs_write(HOST_BASE_GDTR, (u64)gdt64_desc);
	//vmcs_write(HOST_BASE_GDTR, 0xffffffffffff);
	vmcs_write(HOST_BASE_IDTR, (u64)idt_descr);
	vmcs_write(HOST_BASE_FS, 0);
	vmcs_write(HOST_BASE_GS, 0);

	// Set other vmcs area
	vmcs_write(PF_ERROR_MASK, 0);
	vmcs_write(PF_ERROR_MATCH, 0);
	vmcs_write(VMCS_LINK_PTR, ~0ul);
	vmcs_write(VMCS_LINK_PTR_HI, ~0ul);
	vmcs_write(HOST_RSP, (u64)(host_stack + PAGE_SIZE - 1));
	vmcs_write(HOST_RIP, (u64)(&entry_vmx));
}

void init_vmcs_guest(void)
{
	// 26.3 CHECKING AND LOADING GUEST STATE
	ulong guest_cr0, guest_cr4, guest_cr3;
	// 26.3.1.1
	guest_cr0 = read_cr0();
	guest_cr4 = read_cr4();
	guest_cr3 = read_cr3();
	if (ctrl_enter & ENT_GUEST_64) {
		guest_cr0 |= CR0_PG;
		guest_cr4 |= CR4_PAE;
	}
	if ((ctrl_enter & ENT_GUEST_64) == 0){
		guest_cr4 &= (~CR4_PCIDE);
	}
	if (guest_cr0 & CR0_PG)
		guest_cr0 |= CR0_PE;
	vmcs_write(GUEST_CR0, guest_cr0);
	vmcs_write(GUEST_CR3, guest_cr3);
	vmcs_write(GUEST_CR4, guest_cr4);
	vmcs_write(GUEST_SYSENTER_CS,  SEL_KERN_CODE_64);
	vmcs_write(GUEST_SYSENTER_ESP, (u64)(guest_syscall_stack + PAGE_SIZE - 1));
	vmcs_write(GUEST_SYSENTER_EIP, (u64)(&entry_sysenter));
	vmcs_write(GUEST_DR7, 0);
	vmcs_write(GUEST_EFER, rdmsr(MSR_EFER));

	// 26.3.1.2
	vmcs_write(GUEST_SEL_CS, SEL_KERN_CODE_64);
	vmcs_write(GUEST_SEL_SS, SEL_KERN_DATA_64);
	vmcs_write(GUEST_SEL_DS, SEL_KERN_DATA_64);
	vmcs_write(GUEST_SEL_ES, SEL_KERN_DATA_64);
	vmcs_write(GUEST_SEL_FS, SEL_KERN_DATA_64);
	vmcs_write(GUEST_SEL_GS, SEL_KERN_DATA_64);
	vmcs_write(GUEST_SEL_TR, SEL_TSS_RUN);
	vmcs_write(GUEST_SEL_LDTR, 0);

	vmcs_write(GUEST_BASE_CS, 0);
	vmcs_write(GUEST_BASE_ES, 0);
	vmcs_write(GUEST_BASE_SS, 0);
	vmcs_write(GUEST_BASE_DS, 0);
	vmcs_write(GUEST_BASE_FS, 0);
	vmcs_write(GUEST_BASE_GS, 0);
	vmcs_write(GUEST_BASE_TR,   (u64)tss_descr);
	vmcs_write(GUEST_BASE_LDTR, 0);

	vmcs_write(GUEST_LIMIT_CS, 0xFFFFFFFF);
	vmcs_write(GUEST_LIMIT_DS, 0xFFFFFFFF);
	vmcs_write(GUEST_LIMIT_ES, 0xFFFFFFFF);
	vmcs_write(GUEST_LIMIT_SS, 0xFFFFFFFF);
	vmcs_write(GUEST_LIMIT_FS, 0xFFFFFFFF);
	vmcs_write(GUEST_LIMIT_GS, 0xFFFFFFFF);
	vmcs_write(GUEST_LIMIT_LDTR, 0xffff);
	vmcs_write(GUEST_LIMIT_TR, ((struct descr *)tss_descr)->limit);

	vmcs_write(GUEST_AR_CS, 0xa09b);
	vmcs_write(GUEST_AR_DS, 0xc093);
	vmcs_write(GUEST_AR_ES, 0xc093);
	vmcs_write(GUEST_AR_FS, 0xc093);
	vmcs_write(GUEST_AR_GS, 0xc093);
	vmcs_write(GUEST_AR_SS, 0xc093);
	vmcs_write(GUEST_AR_LDTR, 0x82);
	vmcs_write(GUEST_AR_TR, 0x8b);

	// 26.3.1.3
	vmcs_write(GUEST_BASE_GDTR, (u64)gdt64_desc);
	//vmcs_write(GUEST_BASE_GDTR, 0xffffffffffff);
	vmcs_write(GUEST_BASE_IDTR, (u64)idt_descr);
	vmcs_write(GUEST_LIMIT_GDTR, ((struct descr *)gdt64_desc)->limit & 0xffff);
	vmcs_write(GUEST_LIMIT_IDTR, ((struct descr *)idt_descr)->limit & 0xffff);

	// 26.3.1.4
	vmcs_write(GUEST_RIP, (u64)(&entry_guest));
	vmcs_write(GUEST_RSP, (u64)(guest_stack + PAGE_SIZE - 1));
	vmcs_write(GUEST_RFLAGS, 0x2);

	// 26.3.1.5
	vmcs_write(GUEST_ACTV_STATE, 0);
	vmcs_write(GUEST_INTR_STATE, 0);
}

int init_vmcs(struct vmcs **vmcs)
{
	*vmcs = alloc_page();
	memset(*vmcs, 0, PAGE_SIZE);
	(*vmcs)->revision_id = basic.revision;
	// vmclear first to init vmcs
	if (vmcs_clear(*vmcs)) {
		printf("%s : vmcs_clear error\n", __func__);
		return 1;
	}

	if (make_vmcs_current(*vmcs)) {
		printf("%s : make_vmcs_current error\n", __func__);
		return 1;
	}

	// All settings to pin/exit/enter/cpu control fields should place here
	ctrl_pin |= PIN_EXTINT | PIN_NMI | PIN_VIRT_NMI;
	ctrl_exit = EXI_LOAD_EFER | EXI_HOST_64;
	ctrl_enter = (ENT_LOAD_EFER | ENT_GUEST_64);
	ctrl_cpu[0] |= CPU_HLT;
	ctrl_cpu[0] &= (~(CPU_IO | CPU_IO_BITMAP)); // DIsable IO instruction VMEXIT now
	ctrl_cpu[1] = 0;

	ctrl_pin = (ctrl_pin |ctrl_pin_rev.set) & ctrl_pin_rev.clr;
	ctrl_enter = (ctrl_enter | ctrl_enter_rev.set) & ctrl_enter_rev.clr;
	ctrl_exit = (ctrl_exit | ctrl_exit_rev.set) & ctrl_exit_rev.clr;
	ctrl_cpu[0] = (ctrl_cpu[0] | ctrl_cpu_rev[0].set) & ctrl_cpu_rev[0].clr;

	init_vmcs_ctrl();
	init_vmcs_host();
	init_vmcs_guest();
	return 0;
}

void init_vmx(void)
{
	vmxon_region = alloc_page();
	memset(vmxon_region, 0, PAGE_SIZE);

	fix_cr0_set =  rdmsr(MSR_IA32_VMX_CR0_FIXED0);
	fix_cr0_clr =  rdmsr(MSR_IA32_VMX_CR0_FIXED1);
	fix_cr4_set =  rdmsr(MSR_IA32_VMX_CR4_FIXED0);
	fix_cr4_clr = rdmsr(MSR_IA32_VMX_CR4_FIXED1);
	basic.val = rdmsr(MSR_IA32_VMX_BASIC);
	ctrl_pin_rev.val = rdmsr(basic.ctrl ? MSR_IA32_VMX_TRUE_PIN
			: MSR_IA32_VMX_PINBASED_CTLS);
	ctrl_exit_rev.val = rdmsr(basic.ctrl ? MSR_IA32_VMX_TRUE_EXIT
			: MSR_IA32_VMX_EXIT_CTLS);
	ctrl_enter_rev.val = rdmsr(basic.ctrl ? MSR_IA32_VMX_TRUE_ENTRY
			: MSR_IA32_VMX_ENTRY_CTLS);
	ctrl_cpu_rev[0].val = rdmsr(basic.ctrl ? MSR_IA32_VMX_TRUE_PROC
			: MSR_IA32_VMX_PROCBASED_CTLS);
	if (ctrl_cpu_rev[0].set & CPU_SECONDARY)
		ctrl_cpu_rev[1].val = rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
	if (ctrl_cpu_rev[1].set & CPU_EPT || ctrl_cpu_rev[1].set & CPU_VPID)
		ept_vpid.val = rdmsr(MSR_IA32_VMX_EPT_VPID_CAP);

	write_cr0 ((read_cr0() & fix_cr0_clr) | fix_cr0_set);
	write_cr4 ((read_cr4() & fix_cr4_clr) | fix_cr4_set | CR4_VMXE);

	*vmxon_region = basic.revision;

	guest_stack = alloc_page();
	memset(guest_stack, 0, PAGE_SIZE);
	guest_syscall_stack = alloc_page();
	memset(guest_syscall_stack, 0, PAGE_SIZE);
	host_stack = alloc_page();
	memset(host_stack, 0, PAGE_SIZE);
	host_syscall_stack = alloc_page();
	memset(host_syscall_stack, 0, PAGE_SIZE);
}

int test_vmx_capability(void)
{
	struct cpuid r;
	u64 ret1, ret2;
	r = cpuid(1);
	ret1 = ((r.c) >> 5) & 1;
	ret2 = ((rdmsr(MSR_IA32_FEATURE_CONTROL) & 0x5) == 0x5);
	if (ret2 == 0){
		wrmsr(MSR_IA32_FEATURE_CONTROL, 0x5);
		ret2 = ((rdmsr(MSR_IA32_FEATURE_CONTROL) & 0x5) == 0x5);
	}
	report("test vmx capability", ret1 & ret2);
	// TODO: Fix here after patches are accepted
	return 0;
	return !(ret1 & ret2);
}

int test_vmxon(void)
{
	bool ret;
	u64 rflags;

	rflags = get_rflags() | X86_EFLAGS_CF | X86_EFLAGS_ZF;
	set_rflags(rflags);
	asm volatile ("vmxon %1; seta %0 \n\t" : "=q"(ret) : "m"(vmxon_region) : "cc");
	report("test vmxon", ret);
	// TODO: Change here after bug fixed
	return 0;
	//return !ret;
}

void test_vmptrld(void)
{
	u64 rflags;
	struct vmcs *vmcs;

	vmcs = alloc_page();
	vmcs->revision_id = basic.revision;
	rflags = get_rflags() | X86_EFLAGS_CF | X86_EFLAGS_ZF;
	set_rflags(rflags);
	report("test vmptrld", make_vmcs_current(vmcs) == 0);
}

void test_vmptrst(void)
{
	u64 rflags;
	int ret;
	struct vmcs *vmcs1, *vmcs2;

	vmcs1 = alloc_page();
	memset(vmcs1, 0, PAGE_SIZE);
	init_vmcs(&vmcs1);
	rflags = get_rflags() | X86_EFLAGS_CF | X86_EFLAGS_ZF;
	set_rflags(rflags);
	ret = save_vmcs(&vmcs2);
	report("test vmptrst", (!ret) && (vmcs1 == vmcs2));
}

int main(void)
{
	setup_vm();
	setup_idt();

	if (test_vmx_capability() != 0) {
		printf("ERROR : vmx not supported, check +vmx option\n");
		goto exit;
	}
	init_vmx();
	if (test_vmxon() != 0)
		goto exit;
	test_vmptrld();
	test_vmclear();
	test_vmptrst();
	init_vmcs(&vmcs_root);

	vmx_run();
	// Should not reach here
	report("test vmlaunch", 0);

exit:
	printf("\nSUMMARY: %d tests, %d failures\n", tests, fails);
	return fails ? 1 : 0;
}

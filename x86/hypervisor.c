#include "libcflat.h"
#include "processor.h"
#include "vm.h"
#include "desc.h"
#include "hypervisor.h"
#include "msr.h"


int fails = 0, tests = 0;
u32 *vmxon_region;
struct vmcs *vmcs_root;
struct exec_cxt *current, ec_root;
void *io_bmp1, *io_bmp2;
u32 vpid_ctr;
char *stack, *syscall_stack;

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

asm(
	".align	4, 0x90 \n\t"
	".globl	entry_vmx \n\t"
	"entry_vmx: \n\t"
	SAVE_GPR
	"	mov	stack + 4095, %rsp \n\t"
	"	jmp	vmx_handler \n\t"
);

asm(
	".align	4, 0x90 \n\t"
	".globl	entry_sysenter \n\t"
	"entry_sysenter: \n\t"
	SAVE_GPR
	"	mov	stack + 4095, %rsp \n\t"
	"	and	$0xf, %rax \n\t"
	"	push	%rax \n\t"
	"	jmp	syscall_handler \n\t"
);

void syscall_handler(u64 syscall_no)
{

}

void vmx_resume(struct exec_cxt *current)
{
	if (make_vmcs_current(current->vmcs)){
		printf("%s : make_vmcs_current failed\n", __func__);
		return;
	}
	asm volatile ("lea %0, %%rsp\n\t"
		LOAD_GPR
		"vmresume \n\t"
		"vmlaunch \n\t"
		"mov %1, %%rsp\n\t"
		: : "m" (current->regs), "rm" ((u64)(current->stack + PAGE_SIZE - 1))
		: "memory");
}

void vmx_run()
{
	bool ret;
	printf("Now run vm!!!\n\n\n");
	asm volatile("vmlaunch \n\t seta %0\n\t":"=m"(ret));
	printf("VMLAUNCH error, ret=%d\n", ret);
}

void vmx_handler()
{
	ulong reason = vmcs_read(EXI_REASON) & 0xff;

	switch (reason) {
	    case VMX_EXC_NMI:
	    case VMX_EXTINT:
	    case VMX_INVLPG:
	    case VMX_CR:
	    case VMX_EPT_VIOLATION:
		break;
	}
	printf("Here in vmx_handler\n");
	vmx_resume(current);
}

asm(
	".align	4, 0x90 \n\t"
	".globl	entry_guest \n\t"
	"entry_guest: \n\t"
	"	mov	stack + 4095, %rsp \n\t"
	"	call	guest_main \n\t"
	"	hlt \n\t"
);

void guest_main()
{
	printf("Hello World!\n");
	asm volatile("vmcall\n\t");
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


	u32 pin = PIN_EXTINT | PIN_NMI | PIN_VIRT_NMI;
	u32 exit = EXI_INTA;
	u32 enter = 0;
	extern void *gdt64_desc;
	extern void *idt_descr;
	extern void *tss_descr;
	extern void *entry_vmx;
	extern void *entry_sysenter;
	extern void *entry_guest;

	vmcs_write(PF_ERROR_MASK, 0);
	vmcs_write(PF_ERROR_MATCH, 0);
	vmcs_write(CR3_TARGET_COUNT, 0);

	vmcs_write(VMCS_LINK_PTR,    ~0ul);
	vmcs_write(VMCS_LINK_PTR_HI, ~0ul);

	vmcs_write(VPID, ++vpid_ctr);

	io_bmp1 = alloc_page();
	io_bmp2 = alloc_page();
	memset(io_bmp1, 0, PAGE_SIZE);
	memset(io_bmp2, 0, PAGE_SIZE);
	vmcs_write(IO_BITMAP_A, (u64)io_bmp1);
	vmcs_write(IO_BITMAP_B, (u64)io_bmp2);

	vmcs_write(HOST_EFER, MSR_K6_EFER);
	exit |= EXI_LOAD_EFER | EXI_HOST_64;
	enter |= ENT_LOAD_EFER;

	vmcs_write(PIN_CONTROLS, (pin | ctrl_pin.set) & ctrl_pin.clr);
	vmcs_write(EXI_CONTROLS, (exit | ctrl_exit.set) & ctrl_exit.clr);
	vmcs_write(ENT_CONTROLS, (enter | ctrl_enter.set) & ctrl_enter.clr);

	vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu[0].set | ctrl_cpu[0].clr);
	if (ctrl_cpu[0].set & CPU_SECONDARY)
		vmcs_write(CPU_EXEC_CTRL1, ctrl_cpu[1].set | ctrl_cpu[1].clr);

	vmcs_write(HOST_SEL_CS, SEL_KERN_CODE_64);
	vmcs_write(HOST_SEL_SS, SEL_KERN_DATA_64);
	vmcs_write(HOST_SEL_DS, SEL_KERN_DATA_64);
	vmcs_write(HOST_SEL_ES, SEL_KERN_DATA_64);
	vmcs_write(HOST_SEL_TR, SEL_TSS_RUN);

	vmcs_write(HOST_CR0, read_cr0());
	vmcs_write(HOST_CR3, read_cr3());
	vmcs_write(HOST_CR4, read_cr4());

	vmcs_write(HOST_BASE_TR,   (u64)tss_descr);
	vmcs_write(HOST_BASE_GDTR, (u64)gdt64_desc);
	vmcs_write(HOST_BASE_IDTR, (u64)idt_descr);

	vmcs_write(HOST_SYSENTER_CS,  SEL_KERN_CODE_64);
	vmcs_write(HOST_SYSENTER_ESP, (u64)(syscall_stack + PAGE_SIZE - 1));
	vmcs_write(HOST_SYSENTER_EIP, (u64)(&entry_sysenter));

	vmcs_write(HOST_RSP, (u64)(stack + PAGE_SIZE - 1));
	vmcs_write(HOST_RIP, (u64)(&entry_vmx));

	vmcs_write(GUEST_RIP, (u64)(&entry_guest));
	vmcs_write (GUEST_RSP, (u64)(stack + PAGE_SIZE - 1));

	vmcs_write(GUEST_SEL_CS, SEL_KERN_CODE_64);
	vmcs_write(GUEST_SEL_SS, SEL_KERN_DATA_64);
	vmcs_write(GUEST_SEL_DS, SEL_KERN_DATA_64);
	vmcs_write(GUEST_SEL_ES, SEL_KERN_DATA_64);
	vmcs_write(GUEST_SEL_TR, SEL_TSS_RUN);

	vmcs_write(GUEST_CR0, read_cr0());
	vmcs_write(GUEST_CR3, read_cr3());
	vmcs_write(GUEST_CR4, read_cr4());

	vmcs_write(GUEST_BASE_TR,   (u64)tss_descr);
	vmcs_write(GUEST_BASE_GDTR, (u64)gdt64_desc);
	vmcs_write(GUEST_BASE_IDTR, (u64)idt_descr);

	vmcs_write(GUEST_SYSENTER_CS,  SEL_KERN_CODE_64);
	vmcs_write(GUEST_SYSENTER_ESP, (u64)(syscall_stack + PAGE_SIZE - 1));
	vmcs_write(GUEST_SYSENTER_EIP, (u64)(&entry_sysenter));

	vmcs_write(GUEST_ACTV_STATE, 0);
	return 0;
}

void init_vmx(void)
{
	ulong cr4;

	cr4 = read_cr4();
	cr4 = cr4 | (1<<13);
	write_cr4(cr4);
	vmxon_region = alloc_page();
	memset(vmxon_region, 0, PAGE_SIZE);

	fix_cr0_set =  rdmsr(MSR_IA32_VMX_CR0_FIXED0);
	fix_cr0_clr =  rdmsr(MSR_IA32_VMX_CR0_FIXED1);
	fix_cr4_set =  rdmsr(MSR_IA32_VMX_CR4_FIXED0);
	fix_cr4_clr = rdmsr(MSR_IA32_VMX_CR4_FIXED1);
	basic.val = rdmsr(MSR_IA32_VMX_BASIC);
	ctrl_pin.val = rdmsr(basic.ctrl ? MSR_IA32_VMX_TRUE_PIN
			: MSR_IA32_VMX_PINBASED_CTLS);
	ctrl_exit.val = rdmsr(basic.ctrl ? MSR_IA32_VMX_TRUE_EXIT
			: MSR_IA32_VMX_EXIT_CTLS);
	ctrl_enter.val = rdmsr(basic.ctrl ? MSR_IA32_VMX_TRUE_ENTRY
			: MSR_IA32_VMX_ENTRY_CTLS);
	ctrl_cpu[0].val = rdmsr(basic.ctrl ? MSR_IA32_VMX_TRUE_PROC
			: MSR_IA32_VMX_PROCBASED_CTLS);
	if (ctrl_cpu[0].set & CPU_SECONDARY)
		ctrl_cpu[1].val = rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
	if (ctrl_cpu[1].set & CPU_EPT || ctrl_cpu[1].set & CPU_VPID)
		ept_vpid.val = rdmsr(MSR_IA32_VMX_EPT_VPID_CAP);

	ctrl_cpu[0].set |= CPU_HLT | CPU_IO | CPU_IO_BITMAP | CPU_INVLPG;
	ctrl_cpu[1].set |= CPU_VPID | CPU_URG;

	write_cr0 ((read_cr0() & fix_cr0_clr) | fix_cr0_set);
	write_cr4 ((read_cr4() & fix_cr4_clr) | fix_cr4_set);

	*vmxon_region = basic.revision;
	stack = alloc_page();
	memset(stack, 0, PAGE_SIZE);
	syscall_stack = alloc_page();
	memset(syscall_stack, 0, PAGE_SIZE);
}

void init_ec_root()
{
	memset(&ec_root, 0, sizeof(struct exec_cxt));
	ec_root.vmcs = vmcs_root;
	ec_root.stack = stack;
	ec_root.syscall_stack = syscall_stack;
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

void test_vmxoff(void)
{
	bool ret;
	u64 rflags;

	rflags = get_rflags() | X86_EFLAGS_CF | X86_EFLAGS_ZF;
	set_rflags(rflags);
	asm volatile ("vmxoff; seta %0 \n\t" : "=q"(ret) :: "cc");
	report("test vmxoff", ret);
}

void test_vmptrld(void)
{
	u64 rflags;

	rflags = get_rflags() | X86_EFLAGS_CF | X86_EFLAGS_ZF;
	set_rflags(rflags);
	report("test vmptrld", make_vmcs_current(vmcs_root) == 0);
}

void test_vmclear(void)
{
	u64 rflags;

	rflags = get_rflags() | X86_EFLAGS_CF | X86_EFLAGS_ZF;
	set_rflags(rflags);
	report("test vmclear", vmcs_clear(vmcs_root) == 0);
}

int main(void)
{
	setup_vm();
	setup_idt();
	//setup_gdt();
	//setup_tss32();

	if (test_vmx_capability() != 0) {
		printf("ERROR : vmx not supported, check +vmx option\n");
		goto exit;
	}
	init_vmx();
	if (test_vmxon() != 0)
		goto exit;
	init_vmcs(&vmcs_root);
	init_ec_root();

	vmx_run();

	test_vmclear();
	test_vmxoff();

exit:
	printf("\nSUMMARY: %d tests, %d failures\n", tests, fails);
	return fails ? 1 : 0;
}

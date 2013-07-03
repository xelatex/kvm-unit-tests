#include "libcflat.h"
#include "processor.h"
#include "vm.h"
#include "desc.h"
#include "hypervisor.h"
#include "msr.h"


int fails = 0, tests = 0;
u32 *vmxon_region;
struct vmcs *vmcs_root;

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
	// TODO: Fix here after patches are accepted
	//ret2 = ((rdmsr(MSR_IA32_FEATURE_CONTROL) & 0x5) == 0x5);
	ret2 = 1;
	report("test vmx capability", ret1 & ret2);
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
	ctrl_pin.val = rdmsr(MSR_IA32_VMX_PINBASED_CTLS);
	ctrl_exit.val = rdmsr(MSR_IA32_VMX_EXIT_CTLS);
	ctrl_ent.val = rdmsr(MSR_IA32_VMX_ENTRY_CTLS);
	ctrl_cpu[0].val = rdmsr(MSR_IA32_VMX_PROCBASED_CTLS);
	if (ctrl_cpu[0].clr & CPU_SECONDARY)
		ctrl_cpu[1].val = rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
	if (ctrl_cpu[1].clr & CPU_EPT || ctrl_cpu[1].clr & CPU_VPID)
		ept_vpid.val = rdmsr(MSR_IA32_VMX_EPT_VPID_CAP);

	ctrl_cpu[0].set |= CPU_HLT | CPU_IO | CPU_IO_BITMAP | CPU_SECONDARY;
	write_cr0 ((read_cr0() & fix_cr0_clr) | fix_cr0_set);
	write_cr4 ((read_cr4() & fix_cr4_clr) | fix_cr4_set);

	vmcs_root = alloc_page();
	memset(vmcs_root, 0, PAGE_SIZE);
	vmcs_root->revision_id = basic.revision;
	*vmxon_region = basic.revision;

}

int test_vmxon(void)
{
	bool ret;
	u64 rflags = get_rflags();

	rflags |= X86_EFLAGS_CF | X86_EFLAGS_ZF;
	set_rflags(rflags);
	asm volatile ("vmxon %1; seta %0 \n\t" : "=q"(ret) : "m"(vmxon_region) : "cc");
	report("test vmxon", ret);
	return !ret;
}

void test_vmxoff(void)
{
	bool ret;
	u64 rflags = get_rflags();

	rflags |= X86_EFLAGS_CF | X86_EFLAGS_ZF;
	set_rflags(rflags);
	asm volatile ("vmxoff; seta %0 \n\t" : "=q"(ret) :: "cc");
	report("test vmxoff", ret);
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


	test_vmxoff();

exit:
	printf("\nSUMMARY: %d tests, %d failures\n", tests, fails);
	return fails ? 1 : 0;
}

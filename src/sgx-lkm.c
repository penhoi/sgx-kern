#include <linux/module.h>
#include <linux/kernel.h>
#include "sgx-kern.h"

#define SYS_CALL_TABLE 0xffffffff81801460
#define SYS_NI_SYSCALL 0xffffffff810955c0
#define MAX_NO 312
#define HOOKME 180
#ifndef ul
typedef unsigned long ul; 
typedef unsigned int ui;
#endif

typedef struct prog_info_t {
	char* base;
	int npages;
} prog_info_t;

struct {
	int flag;
	ul org_fun;
} g_hook_matrix[MAX_NO];

/*
   find out sys_call_table indices which is mapped to sys_ni_syscall.
 */
void print_sys_call_table(void)
{
	int nIdx;
	ul *pentry = (ul*) SYS_CALL_TABLE;
	for (nIdx = 0; nIdx < MAX_NO; nIdx++) {
		if (SYS_NI_SYSCALL == pentry[nIdx])
			printk(KERN_INFO "%d, %lx\n", nIdx, pentry[nIdx]);
	}
}

/*
   make a page is writable by setting the PTE entry.
 */
void make_page_RW(ul va)
{
	pte_t *e;
	ui l;

	e = lookup_address(va, &l);
	*(ul*)e |= _PAGE_RW;
	printk(KERN_INFO "va:%lx pte:%lx\n", va, *(ul*)e);
}

/*
   hook a system call by overwriting the correspoinding SYS_CALL_TABLE entry.
 */
void hook_syscall(int index, ul func)
{
	ul *pentry = (ul*)(SYS_CALL_TABLE + index * sizeof(long));
	if (*pentry == SYS_NI_SYSCALL) {
		make_page_RW((ul)pentry);
		g_hook_matrix[index].flag = 1;
		g_hook_matrix[index].org_fun = *pentry;
		*pentry = func;
	}
	else
		printk(KERN_INFO "Not a sys_ni_syscall entry!\n");
}

/*
   unhook a system call.
 */
void unhook_syscall(int index)
{
	if (g_hook_matrix[index].flag) {
		ul *pentry = (ul*)(SYS_CALL_TABLE + index * sizeof(long));
		*pentry = g_hook_matrix[index].org_fun;
	}
}

//The only one system call that is exported to user application
	asmlinkage
long sys_intel_sgx(prog_info_t* prog, tcs_t *tcs, sigstruct_t *sig, einittoken_t *token)
{
	void *base = prog->base;
	int npages = prog->npages;

	printk(KERN_INFO "%s\n", __FUNCTION__);	
	if (sys_sgx_init())
		return sys_create_enclave(base, npages, tcs, sig, token);
	else
		return (long)-1;
}

int init_module(void)
{
	printk(KERN_INFO "Hello world!\n");
	print_sys_call_table();
	hook_syscall(HOOKME, (ul)&sys_intel_sgx);
	return 0;
}

void cleanup_module(void)
{

	printk(KERN_INFO "Goodbye world!\n");
	unhook_syscall(HOOKME);
}

MODULE_LICENSE("GPL");

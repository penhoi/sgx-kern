#define SGX_KERNEL

#include <linux/kernel.h>
#include <linux/slab.h>

#include "sgx-kern.h"
#include "sgx-utils.h"
#include "sgx-epc.h"
#include "sgx-crypto.h"


#define NUM_THREADS 1

keid_t ENCLAVES[MAX_ENCLAVES];
#define INVALID_KEID -1


char *empty_page;
static epc_page *enclave_heap_beg;
static epc_page *enclave_heap_end;
static epc_page *enclave_stack_end;

static einittoken_t *app_token;

static void sgx_qemu_init(uint64_t startPage, uint64_t endPage);
static void set_cpusvn(uint8_t svn);
static void set_intel_pubkey(uint64_t pubKey);
static void set_stack(uint64_t sp);

void set_app_token(einittoken_t *token)
{
	app_token = token;
}

// encls() : Execute an encls instruction
// out_regs store the output value returned from qemu
	static
void encls(encls_inst leaf, uint64_t rbx, uint64_t rcx,
		uint64_t rdx, out_regs_t* out)
{
	//(sgx_dbg(kern,
	//        "leaf=%d, rbx=0x%"PRIx64", rcx=0x%"PRIx64", rdx=0x%"PRIx64")",
	//        leaf, rbx, rcx, rdx);

	out_regs_t tmp;
	asm volatile(".byte 0x0F\n\t"
			".byte 0x01\n\t"
			".byte 0xcf\n\t"
			:"=a"(tmp.oeax),
			"=b"(tmp.orbx),
			"=c"(tmp.orcx),
			"=d"(tmp.ordx)
			:"a"((uint32_t)leaf),
			"b"(rbx),
			"c"(rcx),
			"d"(rdx)
			:"memory");

	if (out != NULL) {
		*out = tmp;
	}
}

	static
void ECREATE(pageinfo_t *pi, epc_page *page)
{
	// RBX: PAGEINFO(In, EA)
	// RCX: EPCPAGE(In, EA)
	encls(ENCLS_ECREATE,
			(uint64_t)pi,
			(uint64_t)get_epc_page_vaddr(page),
			0x0, NULL);
}

	static
int EINIT(uint64_t sigstruct, epc_page *secs, uint64_t einittoken)
{
	// RBX: SIGSTRUCT(In, EA)
	// RCX: SECS(In, EA)
	// RDX: EINITTOKEN(In, EA)
	// RAX: ERRORCODE(Out)
	out_regs_t out;
	encls(ENCLS_EINIT, sigstruct, (uint64_t)get_epc_page_vaddr(secs), einittoken, &out);
	return -(int)(out.oeax);
}

	static
void EADD(pageinfo_t *pi, epc_page *page)
{
	// RBX: PAGEINFO(In, EA)
	// RCX: EPCPAGE(In, EA)
	encls(ENCLS_EADD,
			(uint64_t)pi,
			(uint64_t)get_epc_page_vaddr(page),
			0x0, NULL);
}

	static
void EEXTEND(uint64_t pageChunk)
{
	// RCX: 256B Page Chunk to be hashed(In, EA)
	encls(ENCLS_EEXTEND, 0x0, pageChunk, 0x0, NULL);
}

	static
void EAUG(pageinfo_t *pi, epc_page *page)
{
	// RBX: PAGEINFO(In, EA)
	// RCX: EPCPAGE(In, EA)
	encls(ENCLS_EAUG,
			(uint64_t)pi,
			(uint64_t)get_epc_page_vaddr(page),
			0x0, NULL);
}

	static
void EMODPR(secinfo_t *si, uint64_t page_addr)
{
	// RBX: Secinfo Addr(In)
	// RCX: Destination EPC Addr(In)
	// EAX: Error Code(out)
	out_regs_t out;
	encls(ENCLS_EMODPR, (uint64_t)si, page_addr, 0x0, &out);
}

int EBLOCK(uint64_t page_addr)
{
	// RCX: EPC Addr(In, EA)
	// EAX: Error Code(Out)
	out_regs_t out;
	encls(ENCLS_EBLOCK, 0x0, page_addr, 0x0, &out);

	return (int)(out.oeax);
}

int EWB(pageinfo_t *pi, epc_page *page_addr, uint64_t *VA_slot_addr)
{
	// EAX: Error(Out)
	// RBX: Pageinfo Addr(In)
	// RCX: EPC addr(In)
	// RDX: VA slot addr(In)
	out_regs_t out;
	encls(ENCLS_EWB, (uint64_t)pi, (uint64_t)page_addr, (uint64_t)VA_slot_addr, &out);
	return (int)(out.oeax);
}

void EPA(int enclave_id)
{
	// RBX: PT_VA (In, Const)
	// RCX: EPC Addr(In, EA)
	uint64_t addr = (uint64_t)reserve_epc_pages(enclave_id, 1);
	// Assume that we maintain the one Enclave...
	enclave_id = 0;
	encls(ENCLS_EPA, PT_VA, addr, 0, NULL);
}

	static
void sgx_qemu_init(uint64_t start_epc_page, uint64_t end_epc_page)
{
	// Function just for initializing EPCM within QEMU
	// based on EPC address in user code
	encls(ENCLS_OSGX_INIT, start_epc_page, end_epc_page, 0x0, NULL);
}

	static
void encls_epcm_clear(uint64_t target_epc_page)
{
	encls(ENCLS_OSGX_EPCM_CLR, target_epc_page, 0x0, 0x0, NULL);
}

	static
void encls_stat(int enclave_id, qstat_t *qstat)
{
	encls(ENCLS_OSGX_STAT, enclave_id, (uint64_t)qstat, 0x0, NULL);
}

	static
void set_intel_pubkey(uint64_t pubKey)
{
	// Function to set CSR_INTELPUBKEYHASH
	encls(ENCLS_OSGX_PUBKEY, pubKey, 0x0, 0x0, NULL);
}

	static
void set_cpusvn(uint8_t svn)
{
	// Set cpu svn.
	encls(ENCLS_OSGX_CPUSVN, svn, 0x0, 0x0, NULL);
}

	static
void set_stack(uint64_t sp)
{
	// Set enclave stack pointer.
	encls(ENCLS_OSGX_SET_STACK, sp, 0x0, 0x0, NULL);
}

	static
int init_enclave(epc_page *secs, sigstruct_t *sig, einittoken_t *token)
{
	return EINIT((uint64_t)sig, secs, (uint64_t)token);
}

static
secinfo_t *alloc_secinfo(bool r, bool w, bool x, epc_page_type pt) {
	secinfo_t *secinfo = memalign(SECINFO_ALIGN_SIZE, sizeof(secinfo_t));
	if (!secinfo)
		return NULL;

	//memset(secinfo, 0, sizeof(secinfo_t));

	secinfo->flags.page_type = pt;
	secinfo->flags.r = r;
	secinfo->flags.w = w;
	secinfo->flags.x = x;

	return secinfo;
}

	static
secs_t *alloc_secs(uint64_t enclave_addr, uint64_t enclave_size)
{
	const int SECS_SIZE = MIN_ALLOC * PAGE_SIZE;
	secs_t *secs = (secs_t *)memalign(SECS_SIZE, sizeof(secs_t));
	if (!secs)
		return NULL;

	//memset(secs, 0, sizeof(secs_t));

	// XXX. set ssaFramesize, currently use it as 1 temporarily
	secs->ssaFrameSize         = 1;
	secs->attributes.mode64bit = true;
	secs->attributes.debug     = false;
	secs->attributes.xfrm      = 0x03;

	if (1) {
		secs->attributes.provisionkey  = false;
		secs->attributes.einittokenkey = true;
	} else {
		secs->attributes.provisionkey  = true;
		secs->attributes.einittokenkey = false;
	}

	secs->baseAddr = enclave_addr;
	secs->size     = enclave_size;

	return secs;
}

	static
epc_page *ecreate(int enclave_id, uint64_t enclave_addr, uint64_t enclave_size)
{
	pageinfo_t *pi = NULL;
	secs_t *secs = NULL;
	secinfo_t *si = NULL;
	epc_page *epc = NULL;

	pi = memalign(PAGEINFO_ALIGN_SIZE, sizeof(pageinfo_t));
	if (!pi)
		printk(KERN_INFO  "failed to allocate pageinfo");

	secs = alloc_secs(enclave_addr, enclave_size);
	if (!secs)
		printk(KERN_INFO  "failed to allocate sec");

	si = alloc_secinfo(true, true, false, PT_SECS);
	if (!si)
		printk(KERN_INFO  "failed to allocate secinfo");

	pi->srcpge  = (uint64_t)secs;
	pi->secinfo = (uint64_t)si;
	pi->secs    = 0; // not used
	pi->linaddr = 0; // not used

	epc = get_epc_pages(enclave_id, 1, EPT_SECS_PAGE);
	if (!epc)
		printk(KERN_INFO  "failed to allocate EPC page for SECS");

	ECREATE(pi, epc);

	//
	// NOTE.
	//  upon ECREATE error, it faults. safely assumes it succeeds.
	//

	kfree(pi);
	kfree(si);
	kfree(secs);

	return epc;
}

	static
void measure_enclave_page(uint64_t page_chunk_addr)
{
	EEXTEND(page_chunk_addr);
}

// add (copy) a single page to a epc page
	static
bool _submit_page_to_enclave(void *normal_page, epc_page *page, epc_page *secs, epc_page_type pt)
{
	pageinfo_t *pi = NULL;
	secinfo_t *si = NULL;
	int i;

	pi = memalign(PAGEINFO_ALIGN_SIZE, sizeof(pageinfo_t));
	if (!pi)
		printk(KERN_INFO  "failed to allocate pageinfo");

	si = alloc_secinfo(true, true, false, pt);
	if (!si)
		printk(KERN_INFO  "failed to allocate secinfo");

	if (pt == PT_REG) {
		si->flags.x = true;
		// change permissions of a page table entry
		//if (mprotect(epc, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC) == -1)
		//    printk(KERN_INFO  "failed to add executable permission");
	}

	pi->srcpge  = (uint64_t)normal_page;
	pi->secinfo = (uint64_t)si;
	pi->secs    = (uint64_t)get_epc_page_vaddr(secs);
	pi->linaddr = (uint64_t)get_epc_page_vaddr(page);


	EADD(pi, page);

	// for EEXTEND
	for(i = 0; i < PAGE_SIZE/MEASUREMENT_SIZE; i++)
		measure_enclave_page((uint64_t)get_epc_page_vaddr(page) + i*MEASUREMENT_SIZE);

	kfree(pi);
	kfree(si);

	return true;
}

// add multiple pages to epc pages (will be allocated)
	static
bool submit_pages_to_enclave(int enclave_id, void *normal_page, int npages,
		epc_page *secs, epc_page_status status, epc_page_type pt)
{
	epc_page *epcpg_iter;
	void* nrmpg_iter;
	int i;

	epcpg_iter = get_epc_pages(enclave_id, npages, status);
	if (NULL == epcpg_iter)
		return false;

	for (i = 0; i < npages; i++) {
		if (!_submit_page_to_enclave(nrmpg_iter, epcpg_iter, secs, pt)) {
			printk(KERN_INFO "%s sever error!\n", __FUNCTION__);
			return false;
		}
		nrmpg_iter = (void *)((uintptr_t)nrmpg_iter + PAGE_SIZE);
		epcpg_iter = (epc_page *)((uintptr_t)epcpg_iter + PAGE_SIZE);		
	}
	return true;
}


// add multiple empty pages to epc pages (will be allocated)
	static
bool submit_empty_pages_to_enclave(int enclave_id, int npages, epc_page *secs,
		epc_page_status status, epc_page_type pt, mem_type mt)
{
	epc_page *first_epc, *epc;
	int i;

	epc = first_epc = get_epc_pages(enclave_id, npages, status);
	if (NULL == epc)
		return false;

	for (i = 0; i < npages; i ++) {
		if (!_submit_page_to_enclave(empty_page, epc, secs, pt))
			return false;
		epc = (epc_page *)((uintptr_t)epc + PAGE_SIZE);
	}

	if (mt == MT_HEAP) {
		enclave_heap_beg = first_epc;
		enclave_heap_end = (epc_page *)((char *)first_epc + PAGE_SIZE * npages - 1);
	}

	if (mt == MT_STACK) {
		enclave_stack_end = (epc_page *)((char *)first_epc + PAGE_SIZE * (npages -1));
	}

	return true;
}


	static
bool aug_epc_page_to_enclave(epc_page *page, epc_page *secs)
{
	pageinfo_t *pi = memalign(PAGEINFO_ALIGN_SIZE, sizeof(pageinfo_t));
	if (!pi) {
		printk(KERN_INFO  "failed to allocate pageinfo");
		return false;
	}

	pi->srcpge  = 0;
	pi->secinfo = 0;
	pi->secs    = (uint64_t)secs;
	pi->linaddr = (uint64_t)get_epc_page_vaddr(page);

	EAUG(pi, page);

	kfree(pi);
	return true;
}


// init custom data structures for qemu-sgx
bool sys_sgx_init(void)
{
	// enclave map
	int i;

	memset(ENCLAVES, 0, sizeof(keid_t) * MAX_ENCLAVES);
	for (i = 0; i < MAX_ENCLAVES; i ++) {
		ENCLAVES[i].nEID = -1;
	}

	if (!init_epc_system()) {
		printk(KERN_INFO "EPC ALLOC FAIL");
		return false;
	}

	// QEMU Setup initialization for SGX
	sgx_qemu_init((uint64_t)&EPC_PAGES[0], (uint64_t)&EPC_PAGES[NUM_EPCPAGE_TOTAL]);

	// Set default cpu svn
	set_cpusvn(CPU_SVN);

	// Initialize an empty page for later use.
	empty_page = memalign(PAGE_SIZE, PAGE_SIZE);

	return true;
}

// allocate enclave_id
	static
int alloc_enclave_id(void)
{
	int i;
	for (i = 0; i < MAX_ENCLAVES; i ++) {
		if (ENCLAVES[i].nEID == INVALID_KEID) {
			ENCLAVES[i].nEID = i;
			return i;
		}
	}
	return INVALID_KEID;
}

// TODO. 1. param entry should be deleted
//       2. param intel_flag looks ugly, integrate it to sig or tcs
// init an enclave
// XXX. need a big lock
// XXX. sig should reflects intel_flag, so don't put it as an arugment

int sys_create_enclave(void *base, unsigned int code_pages,
		tcs_t *tcs, sigstruct_t *sig, einittoken_t *token)
{
	//      enclave (@eid) w/ npages
	//      |
	//      v
	// EPC: [SECS][TCS][TLS]+[CODE][DATA]+[SSA][HEAP][RESV]
	//
	// Note, npages must be power of 2.
	int sec_npages  = 1;
	int tcs_npages  = 1;
	int tls_npages  = get_tls_npages(tcs);
	int ssa_npages  = 2; // XXX: Temperily set
	int stack_npages = STACK_PAGE_FRAMES_PER_THREAD;
	int heap_npages = HEAP_PAGE_FRAMES;
	int total_npages = rop2(sec_npages + tcs_npages + tls_npages \
			+ code_pages + ssa_npages + stack_npages + heap_npages);
	int tls_page_offset;
	int ssa_page_offset;

	epc_page *enclave = NULL;	
	void *enclave_addr = NULL;
	int enclave_size = PAGE_SIZE * total_npages;

	epc_page *secs = NULL;
	epc_page *tcs_epc = NULL;
	int eid = INVALID_KEID;
	int ret = -1;

	eid = alloc_enclave_id();
	if (INVALID_KEID == eid)
		goto err;

	ENCLAVES[eid].nEID = eid;
	ENCLAVES[eid].kin_n++;

	enclave = reserve_epc_pages(eid, total_npages);
	if (NULL == enclave)
		goto err;
	else
		enclave_addr = get_epc_page_vaddr(enclave);

	// allocate secs
	secs = ecreate(eid, (uint64_t)enclave_addr, enclave_size);
	if (!secs)
		goto err;
	ENCLAVES[eid].secs = secs;

	// get epc for TCS
	tcs_epc = get_epc_pages(eid, 1, EPT_TCS_PAGE);
	if (!tcs_epc)
		goto err;

	tls_page_offset = sec_npages + tcs_npages;
	ssa_page_offset = sec_npages + tcs_npages + tls_npages + code_pages;
	update_tcs_fields(tcs, tls_page_offset, ssa_page_offset);

	if (!submit_pages_to_enclave(eid, tcs, 1, secs, EPT_TCS_PAGE, PT_TCS))
		goto err;

	// allocate TLS pages
	if (!submit_empty_pages_to_enclave(eid, tls_npages, secs, EPT_REG_PAGE, PT_REG, MT_TLS))
		printk(KERN_INFO  "failed to add pages");

	// allocate code pages
	if (!submit_pages_to_enclave(eid, base, code_pages, secs, EPT_REG_PAGE, PT_REG))
		printk(KERN_INFO  "failed to add pages");

	// allocate SSA pages
	if (!submit_empty_pages_to_enclave(eid, ssa_npages, secs, EPT_REG_PAGE, PT_REG, MT_SSA))
		printk(KERN_INFO  "failed to add pages");
	ENCLAVES[eid].prealloc_ssa = ssa_npages * PAGE_SIZE;

	// allocate stack pages
	if (!submit_empty_pages_to_enclave(eid, stack_npages, secs, EPT_REG_PAGE, PT_REG, MT_STACK))
		printk(KERN_INFO  "failed to add pages");
	ENCLAVES[eid].prealloc_stack = stack_npages * PAGE_SIZE;

	// allocate heap pages
	//(sgx_dbg(info, "add heap pages: %p (%d pages)",
	//        empty_page, heap_npages);
	if (!submit_empty_pages_to_enclave(eid, heap_npages, secs, EPT_REG_PAGE, PT_REG, MT_HEAP))
		printk(KERN_INFO  "failed to add pages");
	ENCLAVES[eid].prealloc_heap = heap_npages * PAGE_SIZE;

	// Stack enclave stack pointer.
	set_stack((uint64_t)enclave_stack_end);

	if (init_enclave(secs, sig, token))
		goto err;

	// commit
	ret = eid;

	// update per-enclave info
	ENCLAVES[eid].tcs = get_epc_page_vaddr(tcs_epc);
	ENCLAVES[eid].enclave = (uint64_t)enclave;

	ENCLAVES[eid].kout_n++;
	return ret;
err:
	dereserve_epc_pages(enclave, total_npages);
	ENCLAVES[eid].kout_n++;
	return ret;
}


int sys_stat_enclave(int enclave_id, keid_t *stat)
{
	if (enclave_id < 0 || enclave_id >= MAX_ENCLAVES) {
		return -1;
	}
	//*stat = ENCLAVES[enclave_id];
	if (stat == NULL) {
		return -1;
	}

	ENCLAVES[enclave_id].kin_n++;
	encls_stat(enclave_id, &(ENCLAVES[enclave_id].qstat));
	ENCLAVES[enclave_id].kout_n++;
	memcpy(stat, &(ENCLAVES[enclave_id]), sizeof(keid_t));

	return 0;
}

unsigned long sys_add_epc(int enclave_id)
{
	epc_page *free_epc_page = NULL;
	epc_page *secs = NULL;
	epc_page *epc = NULL;

	if (enclave_id < 0 || enclave_id >= MAX_ENCLAVES)
		return -1;

	ENCLAVES[enclave_id].kin_n++;
	free_epc_page = reserve_epc_pages(enclave_id, 1);

	if (free_epc_page == NULL)
		goto err;

	secs = ENCLAVES[enclave_id].secs;
	epc = get_epc_pages(enclave_id, 1, (uint64_t)EPT_REG_PAGE);
	if (!epc)
		goto err;

	if (!aug_epc_page_to_enclave(epc, secs))
		goto err;

	ENCLAVES[enclave_id].augged_heap += PAGE_SIZE;

err:
	ENCLAVES[enclave_id].kout_n++;
	return (unsigned long)epc;
}

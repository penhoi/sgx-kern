#define SGX_KERNEL

#include <linux/kernel.h>
#include <linux/slab.h>

#include "sgx-kern.h"
#include "sgx-utils.h"
#include "sgx-epc.h"
#include "sgx-crypto.h"

bool SGX_INITED = false;

#define NUM_THREADS 1
keid_t ENCLAVES[MAX_ENCLAVES];

uchar *EMPTY_PAGE;
static epc_page *ENCV_HEAP_BGN;
static epc_page *ENCV_HEAP_END;
static epc_page *ENCV_STACK_END;

static einittoken_t *app_token;

static void sgx_qemu_init(ulong startPage, ulong nPages);
static void set_cpusvn(uint8_t svn);
static void set_intel_pubkey(ulong pubKey);
static void set_stack(ulong sp);

void set_app_token(einittoken_t *token)
{
	app_token = token;
}

// encls() : Execute an encls instruction
// out_regs store the output value returned from qemu
	static
void encls(encls_inst leaf, ulong rbx, ulong rcx,
		ulong rdx, out_regs_t* out)
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
			(ulong)pi,
			get_epc_page_vaddr(page),
			0x0, NULL);
}

	static
int EINIT(ulong sigstruct, epc_page *secs, ulong einittoken)
{
	// RBX: SIGSTRUCT(In, EA)
	// RCX: SECS(In, EA)
	// RDX: EINITTOKEN(In, EA)
	// RAX: ERRORCODE(Out)
	out_regs_t out;
	encls(ENCLS_EINIT, sigstruct, get_epc_page_vaddr(secs), einittoken, &out);
	return -(int)(out.oeax);
}

	static
void EADD(pageinfo_t *pi, epc_page *page)
{
	// RBX: PAGEINFO(In, EA)
	// RCX: EPCPAGE(In, EA)
	encls(ENCLS_EADD,
			(ulong)pi,
			get_epc_page_vaddr(page),
			0x0, NULL);
}

	static
void EEXTEND(secs_t *secs, ulong pageChunk)
{
	// RCX: 256B Page Chunk to be hashed(In, EA)
	encls(ENCLS_EEXTEND, (ulong)secs, pageChunk, 0x0, NULL);
}

	static
void EAUG(pageinfo_t *pi, epc_page *page)
{
	// RBX: PAGEINFO(In, EA)
	// RCX: EPCPAGE(In, EA)
	encls(ENCLS_EAUG,
			(ulong)pi,
			get_epc_page_vaddr(page),
			0x0, NULL);
}

	static
void EMODPR(secinfo_t *si, ulong page_addr)
{
	// RBX: Secinfo Addr(In)
	// RCX: Destination EPC Addr(In)
	// EAX: Error Code(out)
	out_regs_t out;
	encls(ENCLS_EMODPR, (ulong)si, page_addr, 0x0, &out);
}

int EBLOCK(ulong page_addr)
{
	// RCX: EPC Addr(In, EA)
	// EAX: Error Code(Out)
	out_regs_t out;
	encls(ENCLS_EBLOCK, 0x0, page_addr, 0x0, &out);

	return (int)(out.oeax);
}

int EWB(pageinfo_t *pi, epc_page *page_addr, ulong *VA_slot_addr)
{
	// EAX: Error(Out)
	// RBX: Pageinfo Addr(In)
	// RCX: EPC addr(In)
	// RDX: VA slot addr(In)
	out_regs_t out;
	encls(ENCLS_EWB, (ulong)pi, (ulong)page_addr, (ulong)VA_slot_addr, &out);
	return (int)(out.oeax);
}

void EPA(int nEID)
{
	// RBX: PT_VA (In, Const)
	// RCX: EPC Addr(In, EA)
	ulong addr = (ulong)reserve_epc_pages(nEID, 1);
	// Assume that we maintain the one Enclave...
	nEID = 0;
	encls(ENCLS_EPA, PT_VA, addr, 0, NULL);
}

	static
void sgx_qemu_init(ulong first_epc_page, ulong nPages)
{
	// Function just for initializing EPCM within QEMU
	// based on EPC address in user code
	encls(ENCLS_OSGX_INIT, first_epc_page, nPages, 0x0, NULL);
}

	static
void encls_epcm_clear(ulong target_epc_page)
{
	encls(ENCLS_OSGX_EPCM_CLR, target_epc_page, 0x0, 0x0, NULL);
}

	static
void encls_stat(int nEID, qstat_t *qstat)
{
	encls(ENCLS_OSGX_STAT, nEID, (ulong)qstat, 0x0, NULL);
}

	static
void set_intel_pubkey(ulong pubKey)
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
void set_stack(ulong sp)
{
	// Set enclave stack pointer.
	encls(ENCLS_OSGX_SET_STACK, sp, 0x0, 0x0, NULL);
}

	static
int init_enclave(epc_page *secs, sigstruct_t *sig, einittoken_t *token)
{
	return EINIT((ulong)sig, secs, (ulong)token);
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
secs_t *alloc_secs(ulong encv_addr, ulong encv_size)
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

	secs->baseAddr = encv_addr;
	secs->size     = encv_size;

	return secs;
}

	static
epc_page *ecreate(int nEID, ulong encv_addr, ulong encv_size)
{
	pageinfo_t *pi = NULL;
	secs_t *secs = NULL;
	secinfo_t *si = NULL;
	epc_page *epc = NULL;

	pi = memalign(PAGEINFO_ALIGN_SIZE, sizeof(pageinfo_t));
	if (!pi)
		printk(KERN_INFO  "failed to allocate pageinfo");

	secs = alloc_secs(encv_addr, encv_size);
	if (!secs)
		printk(KERN_INFO  "failed to allocate sec");

	si = alloc_secinfo(true, true, false, PT_SECS);
	if (!si)
		printk(KERN_INFO  "failed to allocate secinfo");

	pi->srcpge  = (ulong)secs;
	pi->secinfo = (ulong)si;
	pi->secs    = 0; // not used
	pi->linaddr = 0; // not used

	epc = get_epc_pages(nEID, 1, EPT_SECS_PAGE);
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
void measure_enclave_page(secs_t *secs, ulong page_chunk_addr)
{
	EEXTEND(secs, page_chunk_addr);
}

// add (copy) a single page to a epc page
	static
bool _add_page_to_enclave(void *normal_page, epc_page *page, epc_page *secs, epc_page_type pt)
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

	pi->srcpge  = (ulong)normal_page;
	pi->secinfo = (ulong)si;
	pi->secs    = get_epc_page_vaddr(secs);
	pi->linaddr = get_epc_page_vaddr(page);


	EADD(pi, page);

	// for EEXTEND
	for(i = 0; i < PAGE_SIZE/MEASUREMENT_SIZE; i++)
		measure_enclave_page(secs, get_epc_page_vaddr(page) + i*MEASUREMENT_SIZE);

	kfree(pi);
	kfree(si);

	return true;
}

// add multiple pages to epc pages (will be allocated)
	static
bool add_pages_to_enclave(int nEID, void *first_normal_page, int npages,
		epc_page *secs, epc_page_status status, epc_page_type pt)
{
	epc_page *epcpg_iter;
	void* nrmpg_iter;
	int i;

	epcpg_iter = get_epc_pages(nEID, npages, status);
	if (NULL == epcpg_iter)
		return false;
	nrmpg_iter= first_normal_page;
	for (i = 0; i < npages; i++) {
		if (!_add_page_to_enclave(nrmpg_iter, epcpg_iter, secs, pt)) {
			printk(KERN_INFO "%s sever error!\n", __FUNCTION__);
			return false;
		}
		nrmpg_iter = (void *)((uchar*)nrmpg_iter + PAGE_SIZE);
		epcpg_iter = (epc_page *)((uchar*)epcpg_iter + PAGE_SIZE);		
	}
	return true;
}


// add multiple empty pages to epc pages (will be allocated)
	static
bool add_empty_pages_to_enclave(int nEID, int npages, epc_page *secs,
		epc_page_status status, epc_page_type pt, mem_type mt)
{
	epc_page *first_epc, *epc;
	int i;

	epc = first_epc = get_epc_pages(nEID, npages, status);
	if (NULL == epc)
		return false;

	for (i = 0; i < npages; i++) {
		if (!_add_page_to_enclave(EMPTY_PAGE, epc, secs, pt))
			return false;
		epc = (epc_page *)((uchar*)epc + PAGE_SIZE);
	}

	if (mt == MT_HEAP) {
		ENCV_HEAP_BGN = first_epc;
		ENCV_HEAP_END = (epc_page *)((uchar *)first_epc + PAGE_SIZE * npages - 1);
	}

	if (mt == MT_STACK) {
		ENCV_STACK_END = (epc_page *)((uchar *)first_epc + PAGE_SIZE * (npages -1));
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
	pi->secs    = (ulong)secs;
	pi->linaddr = get_epc_page_vaddr(page);

	EAUG(pi, page);

	kfree(pi);
	return true;
}


// init custom data structures for qemu-sgx
bool sys_sgx_init(void)
{
	// enclave map
	int i;

	if (SGX_INITED)
		return true;
	
	memset(ENCLAVES, 0, sizeof(keid_t) * MAX_ENCLAVES);
	for (i = 0; i < MAX_ENCLAVES; i ++) {
		ENCLAVES[i].nEID = INVALID_EID;
	}

	if (!init_epc_system()) {
		printk(KERN_INFO "EPC ALLOC FAIL");
		return false;
	}

	// QEMU Setup initialization for SGX
	sgx_qemu_init((ulong)EPC_PAGES, NUM_EPCPAGE_TOTAL);

	// Set default cpu svn
	set_cpusvn(CPU_SVN);

	// Initialize an empty page for later use.
	EMPTY_PAGE = memalign(PAGE_SIZE, PAGE_SIZE);
	SGX_INITED = true;
	return true;
}

// allocate nEID
	static
uint alloc_enclave_ID(void)
{
	int i;
	for (i = 0; i < MAX_ENCLAVES; i ++) {
		if (ENCLAVES[i].nEID == INVALID_EID) {
			ENCLAVES[i].nEID = i;
			return i;
		}
	}
	return INVALID_EID;
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
	long encv_addr = 0;
	int encv_size = PAGE_SIZE * total_npages;

	epc_page *secs = NULL;
	epc_page *tcs_epc = NULL;
	uint nEID = INVALID_EID;
	int ret = -1;

	nEID = alloc_enclave_ID();
	if (INVALID_EID == nEID)
		goto err;

	ENCLAVES[nEID].nEID = nEID;
	ENCLAVES[nEID].kin_n++;

	enclave = reserve_epc_pages(nEID, total_npages);
	if (NULL == enclave)
		goto err;
	else
		encv_addr = get_epc_page_vaddr(enclave);

	// allocate secs
	secs = ecreate(nEID, encv_addr, encv_size);
	if (!secs)
		goto err;
	ENCLAVES[nEID].secs = secs;

	// get epc for TCS
	tcs_epc = get_epc_pages(nEID, 1, EPT_TCS_PAGE);
	if (!tcs_epc)
		goto err;

	tls_page_offset = sec_npages + tcs_npages;
	ssa_page_offset = sec_npages + tcs_npages + tls_npages + code_pages;
	update_tcs_fields(tcs, tls_page_offset, ssa_page_offset);

	if (!_add_page_to_enclave(tcs, tcs_epc, secs, PT_TCS))
		goto err;

	// allocate TLS pages
	if (!add_empty_pages_to_enclave(nEID, tls_npages, secs, EPT_REG_PAGE, PT_REG, MT_TLS))
		printk(KERN_INFO  "failed to add pages");

	// allocate code pages
	if (!add_pages_to_enclave(nEID, base, code_pages, secs, EPT_REG_PAGE, PT_REG))
		printk(KERN_INFO  "failed to add pages");

	// allocate SSA pages
	if (!add_empty_pages_to_enclave(nEID, ssa_npages, secs, EPT_REG_PAGE, PT_REG, MT_SSA))
		printk(KERN_INFO  "failed to add pages");
	ENCLAVES[nEID].prealloc_ssa = ssa_npages * PAGE_SIZE;

	// allocate stack pages
	if (!add_empty_pages_to_enclave(nEID, stack_npages, secs, EPT_REG_PAGE, PT_REG, MT_STACK))
		printk(KERN_INFO  "failed to add pages");
	ENCLAVES[nEID].prealloc_stack = stack_npages * PAGE_SIZE;

	// allocate heap pages
	//(sgx_dbg(info, "add heap pages: %p (%d pages)",
	//        EMPTY_PAGE, heap_npages);
	if (!add_empty_pages_to_enclave(nEID, heap_npages, secs, EPT_REG_PAGE, PT_REG, MT_HEAP))
		printk(KERN_INFO  "failed to add pages");
	ENCLAVES[nEID].prealloc_heap = heap_npages * PAGE_SIZE;

	// Stack enclave stack pointer.
	set_stack((ulong)ENCV_STACK_END);

	if (init_enclave(secs, sig, token))
		goto err;

	// commit
	ret = nEID;

	// update per-enclave info
	ENCLAVES[nEID].tcs = get_epc_page_vaddr(tcs_epc);
	ENCLAVES[nEID].enclave = (ulong)enclave;

	ENCLAVES[nEID].kout_n++;
	return ret;
err:
	dereserve_epc_pages(enclave, total_npages);
	ENCLAVES[nEID].kout_n++;
	return ret;
}


int sys_stat_enclave(int nEID, keid_t *stat)
{
	if (nEID < 0 || nEID >= MAX_ENCLAVES) {
		return -1;
	}
	//*stat = ENCLAVES[nEID];
	if (stat == NULL) {
		return -1;
	}

	ENCLAVES[nEID].kin_n++;
	encls_stat(nEID, &(ENCLAVES[nEID].qstat));
	ENCLAVES[nEID].kout_n++;
	memcpy(stat, &(ENCLAVES[nEID]), sizeof(keid_t));

	return 0;
}

unsigned long sys_add_epc(int nEID)
{
	epc_page *free_epc_page = NULL;
	epc_page *secs = NULL;
	epc_page *epc = NULL;

	if (nEID < 0 || nEID >= MAX_ENCLAVES)
		return -1;

	ENCLAVES[nEID].kin_n++;
	free_epc_page = reserve_epc_pages(nEID, 1);

	if (free_epc_page == NULL)
		goto err;

	secs = ENCLAVES[nEID].secs;
	epc = get_epc_pages(nEID, 1, (ulong)EPT_REG_PAGE);
	if (!epc)
		goto err;

	if (!aug_epc_page_to_enclave(epc, secs))
		goto err;

	ENCLAVES[nEID].augged_heap += PAGE_SIZE;

err:
	ENCLAVES[nEID].kout_n++;
	return (unsigned long)epc;
}

/*
 *  Copyright (C) 2015, OpenSGX team, Georgia Tech & KAIST, All Rights Reserved
 *
 *  This file is part of OpenSGX (https://github.com/sslab-gatech/opensgx).
 *
 *  OpenSGX is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  OpenSGX is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with OpenSGX.  If not, see <http://www.gnu.org/licenses/>.
 */


#include <linux/mman.h>
#include <linux/slab.h>

#include "sgx-struct.h"
#include "sgx-epc.h"

epc_page *EPC_PAGES;
epc_page_info EPC_PGINFO[NUM_EPCPAGE_TOTAL];

	static
bool _alloc_epc_memory(void)
{
	//toward making NUM_EPCPAGE_TOTAL configurable
	EPC_PAGES  = (epc_page *)alloc_pages(GFP_KERNEL, NUM_EPCPAGE_ORDER);
	return (NULL != EPC_PAGES);
}

	static
void _free_epc_memory(void)
{
	if (NULL != EPC_PAGES)
		free_pages((unsigned long)EPC_PAGES, NUM_EPCPAGE_ORDER);
	EPC_PAGES = NULL;
}


bool init_epc_system(void) 
{
	return _alloc_epc_memory();
}

// linear address is in fact just addr of epc page (physical page)
inline
void* get_epc_page_vaddr(epc_page *epc) {
	return epc;
}

int get_epc_page_type(epc_page *epc)
{
	int i;

	i = ((unsigned long)epc - (unsigned long)EPC_PAGES) / 
		sizeof(epc_page);
	if (i < 0 || i>= NUM_EPCPAGE_TOTAL){
		printk(KERN_INFO "%s: out of index\n", __FUNCTION__);
		return EPT_END_ERROR;
	}
	else
		return EPC_PGINFO[i].status;
}

epc_page * get_epc_pages(int enclave_id, int npages, epc_page_status status)
{
	static int last = 0;
	int idx, cnt, i;
	int first = 0;

	for (i = 0, cnt = 0; (i < NUM_EPCPAGE_TOTAL) && (cnt < npages); i++) {
		idx = (i + last) % NUM_EPCPAGE_TOTAL;
		if (EPC_PGINFO[idx].enclave_id == enclave_id && 
				EPC_PGINFO[idx].status == EPT_RESERVED) {
			EPC_PGINFO[idx].status = status;
			if (cnt == 0)
				first = idx;
			cnt ++;
		}
	}
	if (cnt == npages)
		return &EPC_PAGES[first];
	else {
		if (first != 0)
			printk(KERN_INFO "The epc system is corrputed!\n");
		return NULL;	
	}
}

void put_epc_pages(int start_index, int npages)
{
	int i;

	if (start_index < 0 || start_index + npages >= NUM_EPCPAGE_TOTAL) {
		printk(KERN_INFO "out of index\n");
		return;
	}

	for (i = start_index; i < npages; i++) {
		EPC_PGINFO[i].status = EPT_FREE_PAGE;
	}
}

	static
const char *_epc_bitmap_to_str(epc_page_status type)
{
	switch (type) {
		case EPT_FREE_PAGE: return "FREE";
		case EPT_SECS_PAGE: return "SECS";
		case EPT_TCS_PAGE : return "TCS ";
		case EPT_REG_PAGE : return "REG ";
		case EPT_RESERVED : return "RERV";
		default: return "ERROR";
	}
}

void dbg_dump_epc(void)
{
	int i;
	for (i = 0; i < NUM_EPCPAGE_TOTAL; i++) {
		printk(KERN_INFO  "[%02d] %p (%02d/%s)\n",
				i, EPC_PAGES[i],
				EPC_PGINFO[i].enclave_id,
				_epc_bitmap_to_str(EPC_PGINFO[i].status));
	}
	printk(KERN_INFO  "\n");
}

epc_page* reserve_epc_pages(int enclave_id, int npages)
{
	static int last = 0;
	int	beg = INVALID_EPC_INDEX;
	int idx, i;

	//find the first epc page
	for (i = 0; i < NUM_EPCPAGE_TOTAL; i++) {
		idx = (i + last) % NUM_EPCPAGE_TOTAL;
		if (EPC_PGINFO[idx].status == EPT_FREE_PAGE) {
			EPC_PGINFO[idx].enclave_id = enclave_id;
			EPC_PGINFO[idx].status = EPT_RESERVED;
			last = idx + 1;
			break;
		}
	}
	if (i == NUM_EPCPAGE_TOTAL)
		return NULL;

	//meets the requirement of npages
	beg = idx;
	if (1 == npages)
		goto success;	
	// request too many pages
	else if (beg + npages >= NUM_EPCPAGE_TOTAL) {
		put_epc_pages(beg, 1);
		return NULL;
	}

	// check if we have npages
	for (i = beg + 1; i < beg + npages; i++) {
		if (EPC_PGINFO[i].status != EPT_FREE_PAGE) {
			// restore and return
			put_epc_pages(beg, i-beg);
			return NULL;
		}
		EPC_PGINFO[i].enclave_id = enclave_id;
		EPC_PGINFO[i].status = EPT_RESERVED;
	}
	//update the last variable
	last = i;

success:
	// npages epcs allocated
	return &EPC_PAGES[beg];

}

void dereserve_epc_pages(epc_page *first_epc, int npages)
{
	int beg, enclave_id, cnt, i;

	beg = ((unsigned long)first_epc - (unsigned long)EPC_PAGES) / 
		sizeof(epc_page);
	if (beg < 0 || beg + npages >= NUM_EPCPAGE_TOTAL){
		printk(KERN_INFO "%s: out of index\n", __FUNCTION__);
		return;
	}

	enclave_id = EPC_PGINFO[beg].enclave_id;
	cnt = 0;	
	for (i = beg; (i < NUM_EPCPAGE_TOTAL) && (cnt < npages); i++) {
		if (EPC_PGINFO[i].enclave_id == enclave_id && EPC_PGINFO[i].status == EPT_RESERVED) {
			EPC_PGINFO[i].enclave_id = 0;
			EPC_PGINFO[i].status = EPT_FREE_PAGE;
			cnt++;
		}
	}
	if (cnt != npages) {
		printk(KERN_INFO "%s: no so many pages to dereserve!\n", __FUNCTION__);
	}
}

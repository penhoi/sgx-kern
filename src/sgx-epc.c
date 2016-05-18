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
		free_pages((ulong)EPC_PAGES, NUM_EPCPAGE_ORDER);
	EPC_PAGES = NULL;
}


bool init_epc_system(void) 
{
	uint i;
	if (!_alloc_epc_memory())
		return false;

	//Initalize epc_page_info
	for (i = 0; i < NUM_EPCPAGE_TOTAL; i++) {
		EPC_PGINFO[i].status = EPT_FREE_PAGE;
	}
	return true;
}

// linear address is in fact just addr of epc page (physical page)
inline
ulong get_epc_page_vaddr(epc_page *epc) {
	return (ulong)epc;
}

int get_epc_page_type(epc_page *epc)
{
	uint i;

	i = ((ulong)epc - (ulong)EPC_PAGES) / 
		sizeof(epc_page);
	if (i < 0 || i>= NUM_EPCPAGE_TOTAL){
		printk(KERN_INFO "%s: out of index\n", __FUNCTION__);
		return EPT_END_ERROR;
	}
	else
		return EPC_PGINFO[i].status;
}

epc_page * get_epc_pages(uint nEID, uint nPages, epc_page_status status)
{
	static uint last = 0;
	uint idx, cnt, i;
	uint first = 0;

	for (i = 0, cnt = 0; (i < NUM_EPCPAGE_TOTAL) && (cnt < nPages); i++) {
		idx = (i + last) % NUM_EPCPAGE_TOTAL;
		if (EPC_PGINFO[idx].nEID == nEID && 
				EPC_PGINFO[idx].status == EPT_RESERVED) {
			EPC_PGINFO[idx].status = status;
			if (cnt == 0)
				first = idx;
			cnt ++;
		}
	}
	last = idx;
	if (cnt == nPages)
		return &EPC_PAGES[first];
	else {
		if (first != 0)
			printk(KERN_INFO "The epc system is corrputed!\n");
		return NULL;	
	}
}

void put_epc_pages(uint start_index, uint nPages)
{
	uint i;

	if (start_index < 0 || start_index + nPages >= NUM_EPCPAGE_TOTAL) {
		printk(KERN_INFO "out of index\n");
		return;
	}

	for (i = start_index; i < nPages; i++) {
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
	uint i;
	for (i = 0; i < NUM_EPCPAGE_TOTAL; i++) {
		printk(KERN_INFO  "[%02d] %p (%02d/%s)\n",
				i, EPC_PAGES[i],
				EPC_PGINFO[i].nEID,
				_epc_bitmap_to_str(EPC_PGINFO[i].status));
	}
	printk(KERN_INFO  "\n");
}

epc_page* reserve_epc_pages(uint nEID, uint nPages)
{
	static uint last = 0;
	uint	bgn = INVALID_EPC_INDEX;
	uint idx, i;

	//find the first epc page
	for (i = 0; i < NUM_EPCPAGE_TOTAL; i++) {
		idx = (i + last) % NUM_EPCPAGE_TOTAL;
		if (EPC_PGINFO[idx].status == EPT_FREE_PAGE) {
			EPC_PGINFO[idx].nEID = nEID;
			EPC_PGINFO[idx].status = EPT_RESERVED;
			break;
		}
	}
	last = idx;
	if (i == NUM_EPCPAGE_TOTAL)
		return NULL;

	//meets the requirement of nPages
	bgn = idx;
	if (1 == nPages)
		goto success;	
	// request too many pages
	else if (bgn + nPages >= NUM_EPCPAGE_TOTAL) {
		put_epc_pages(bgn, 1);
		return NULL;
	}

	// check if we have nPages
	for (i = bgn + 1; i < bgn + nPages; i++) {
		if (EPC_PGINFO[i].status != EPT_FREE_PAGE) {
			// restore and return
			put_epc_pages(bgn, i-bgn);
			return NULL;
		}
		EPC_PGINFO[i].nEID = nEID;
		EPC_PGINFO[i].status = EPT_RESERVED;
	}
	//update the last variable
	last = i;

success:
	// nPages epcs allocated
	return &EPC_PAGES[bgn] ;

}

void dereserve_epc_pages(epc_page *first_page, uint nPages)
{
	uint bgn, cnt, i;
	uint nEID;

	bgn = ((ulong)first_page - (ulong)EPC_PAGES) / sizeof(epc_page);
	if (bgn < 0 || bgn + nPages >= NUM_EPCPAGE_TOTAL){
		printk(KERN_INFO "%s: out of index\n", __FUNCTION__);
		return;
	}

	nEID = EPC_PGINFO[bgn].nEID;
	cnt = 0;	
	for (i = bgn; (i < NUM_EPCPAGE_TOTAL) && (cnt < nPages); i++) {
		if (EPC_PGINFO[i].nEID == nEID && EPC_PGINFO[i].status == EPT_RESERVED) {
			EPC_PGINFO[i].nEID = INVALID_EID;
			EPC_PGINFO[i].status = EPT_FREE_PAGE;
			cnt++;
		}
	}
	if (cnt != nPages) {
		printk(KERN_INFO "%s: no so many pages to dereserve!\n", __FUNCTION__);
	}
}

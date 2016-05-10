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

#pragma once

#include "sgx-struct.h"

typedef enum {
	EPT_FREE_PAGE = 0x0,
	EPT_SECS_PAGE = 0x1,
	EPT_TCS_PAGE  = 0x2,
	EPT_REG_PAGE  = 0x3,
	EPT_RESERVED  = 0x4,
	EPT_END_ERROR = 0x5
} epc_page_status;

typedef struct {
	int enclave_id;
	epc_page_status status;
} epc_page_info;

extern epc_page *EPC_PAGES;
extern epc_page_info EPC_PGINFO[NUM_EPCPAGE_TOTAL];

#define INVALID_EPC_INDEX -1

// exported
bool init_epc_system(void);
epc_page* get_epc_pages(int enclave_id, int npages, epc_page_status status);
void put_epc_pages(int start_index, int npages);
void dbg_dump_epc(void);
int get_epc_page_type(epc_page *epc);
void* get_epc_page_vaddr(epc_page *epc);
epc_page* reserve_epc_pages(int enclave_id, int npages);
void dereserve_epc_pages(epc_page *first_page, int npages);

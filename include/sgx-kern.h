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
    MT_SECS,
    MT_TCS,
    MT_TLS,
    MT_CODE,
    MT_SSA,
    MT_STACK,
    MT_HEAP,
} mem_type;


// OS resource management for enclave
#define MAX_ENCLAVES 16

bool sys_sgx_init(void);
int sys_create_enclave(void *base_addr, uint npages,
                              tcs_t *tcs, sigstruct_t *sig, einittoken_t *token);
int sys_stat_enclave(int enclave_id, keid_t *stat);
ulong sys_add_epc(int enclave_id);

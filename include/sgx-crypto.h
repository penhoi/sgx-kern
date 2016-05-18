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
typedef struct rsa_context rsa_context;


#define STRING_ECREATE 0x0045544145524345
#define STRING_EADD    0x0000000044444145
#define STRING_EEXTEND 0x00444E4554584545

//extern void generate_enclavehash(void *hash, void *entry, size_t size, tcs_t *tcs);

//extern void generate_enclavehash(void *hash, void *entries[], unsigned int codes_size[],
//                                 int n_of_codes, tcs_t *tcs);
void generate_enclavehash(void *hash, void *code, int code_pages,
                                 size_t tcs);

//extern void generate_einittoken_mac(einittoken_t *token, uint64_t le_tcs,
//                                    uint64_t le_aep);

void generate_launch_key(unsigned char *device_key, unsigned char *launch_key);

uint8_t get_tls_npages(tcs_t *tcs);

void set_tcs_fields(tcs_t *tcs, size_t offset);
void update_tcs_fields(tcs_t *tcs, int tls_page_offset, int ssa_page_offset);

void rsa_key_generate(uint8_t *pubkey, uint8_t *seckey, rsa_context *rsa, int bits);


// for rsa key pair generation
rsa_context *load_rsa_keys(char *conf, uint8_t *pubkey, uint8_t *seckey,
                           int bits);
void rsa_sign(rsa_context *ctx, rsa_sig_t sig, unsigned char *bytes, int len);

// for mac generation
void cmac(unsigned char *key, unsigned char *input, size_t bytes, unsigned char *mac);

// linked from sgx-kern
extern uchar *EMPTY_PAGE;

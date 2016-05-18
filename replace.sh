#!/bin/bash

for i in *; do sed -i 's= sgx_dbg(=//(sgx_dbg(=g' "$i"; done
for i in *; do sed -i 's= assert(=//assert(=g' "$i"; done
for i in *; do sed -i 's= exit(=//exit(=g' "$i"; done
for i in *; do sed -i 's= memset(=//memset(=g' "$i"; done
for i in *; do sed -i 's= fclose(=//fclose(=g' "$i"; done

for i in *; do sed -i 's= err(1,=printk(KERN_INFO =g' "$i"; done
for i in *; do sed -i 's= fprintf(stderr,=printk(KERN_INFO =g' "$i"; done
for i in *; do sed -i 's= perror(=printk(KERN_INFO =g' "$i"; done
for i in *; do sed -i 's= fprintf(fd,=printk(KERN_INFO =g' "$i"; done
for i in *; do sed -i 's= printf(=printk(KERN_INFO =g' "$i"; done
for i in *; do sed -i 's= err(ret,=printk(KERN_INFO =g' "$i"; done

for i in *; do sed -i 's= malloc(bytes)=kmalloc(bytes, GFP_KERNEL)=g' "$i"; done
for i in *; do sed -i 's= malloc(size)=kmalloc(size, GFP_KERNEL)=g' "$i"; done
for i in *; do sed -i 's= malloc(=kmalloc(=g' "$i"; done
for i in *; do sed -i 's= free(=kfree(=g' "$i"; done
for i in *; do sed -i 's=MAP_FAILED=NULL=g' "$i"; done
for i in *; do sed -i 's=FILE *=char *=g' "$i"; done
for i in *; do sed -i 's=^extern ==g' "$i"; done

for i in *; do sed -i 's=for (int i=int i;\n for (i=g' "$i"; done
for i in *; do sed -i 's=for(int i=int i;\n for (i=g' "$i"; done

for i in *; do sed -i 's=#include <stdlib.h>=#include <linux/kernel.h>=g' "$i"; done
for i in *; do sed -i 's=#include <string.h>==g' "$i"; done
for i in *; do sed -i 's=#include <inttypes.h>==g' "$i"; done
for i in *; do sed -i 's=#include <malloc.h>=#include <linux/slab.h>=g' "$i"; done
for i in *; do sed -i 's=#include <err.h>==g' "$i"; done
for i in *; do sed -i 's=#include <errno.h>==g' "$i"; done
for i in *; do sed -i 's=#include <assert.h>==g' "$i"; done
for i in *; do sed -i 's=#include <stdint.h>==g' "$i"; done
for i in *; do sed -i 's=#include <sys/mman.h>=#include <linux/mman.h>=g' "$i"; done

for i in *; do sed -i 's=#include <stdio.h>==g' "$i"; done
for i in *; do sed -i 's=#include <sgx.h>=#include "../include/sgx.h"=g' "$i"; done
for i in *; do sed -i 's=#include <sgx-kern-epc.h>=#include "../include/sgx-kern-epc.h"=g' "$i"; done
for i in *; do sed -i 's=#include <sgx-user.h>=#include "../include/sgx-user.h"=g' "$i"; done
for i in *; do sed -i 's=#include <sgx-utils.h>=#include "../include/sgx-utils.h"=g' "$i"; done
for i in *; do sed -i 's=#include <sgx-crypto.h>=#include "../include/sgx-crypto.h"=g' "$i"; done
for i in *; do sed -i 's=#include <sgx-signature.h>=#include "../include/sgx-signature.h"=g' "$i"; done
for i in *; do sed -i 's=#include <sgx-loader.h>=#include "../include/sgx-loader.h"=g' "$i"; done
for i in *; do sed -i 's=#include <sgx-kern.h>=#include "../include/sgx-kern.h"=g' "$i"; done




for i in *; do sed -i 's=^#include <stdlib.h>=//#include <stdlib.h>=g' "$i"; done
for i in *; do sed -i 's=^#include <string.h>=//#include <string.h>=g' "$i"; done
for i in *; do sed -i 's=#include <inttypes.h>=//#include <inttypes.h>=g' "$i"; done
for i in *; do sed -i 's=^#include <stdio.h>=//#include <stdio.h>=g' "$i"; done

for i in *; do sed -i 's=//#include <inttypes.h>=#include <linux/kernel.h>=g' "$i"; done


for i in *; do sed -i 's=#include <malloc.h>=#include <linux/slab.h>=g' "$i"; done
for i in *; do sed -i 's=#include <err.h>==g' "$i"; done
for i in *; do sed -i 's=#include <errno.h>==g' "$i"; done
for i in *; do sed -i 's=#include <assert.h>==g' "$i"; done
for i in *; do sed -i 's=#include <stdint.h>==g' "$i"; done
for i in *; do sed -i 's=#include <sys/mman.h>=#include <linux/mman.h>=g' "$i"; done



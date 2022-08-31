#include "eapp.h"
#include "print.h"
#include <stdlib.h>
#include "mage.h"
#include "sm3.h"

void printHash(unsigned char *hash)
{
	char hex[17] = "0123456789abcdef";
	char tmp[65] = {0};
	int i;
	for (i = 0; i < HASH_SIZE; i++) {
    tmp[i + i] = hex[hash[i] / 16];
	  tmp[i + i + 1] = hex[hash[i] % 16];
	}
  eapp_print("%s\n", tmp);
}

int hello(unsigned long * args)
{
  eapp_print("hello-mage-0 begin to run...\n");
	unsigned char hash[32] = {0};
	unsigned long size = sgx_mage_get_size();
	if (size > 0) {
		for (unsigned long mage_idx = 0; mage_idx < size; mage_idx++) {
			eapp_print("sgx mage entry %d:\n", mage_idx);
			sgx_mage_derive_measurement(mage_idx, hash);
			printHash(hash);
		}
	}
	size = penglai_mage_get_size();
	if (size > 0) {
		for (unsigned long mage_idx = 0; mage_idx < size; mage_idx++) {
			eapp_print("penglai mage entry %d:\n", mage_idx);
			penglai_mage_derive_measurement(mage_idx, hash, 0);
			printHash(hash);
		}
	}

  EAPP_RETURN(0);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  hello(args);
}

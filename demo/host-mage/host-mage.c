#include "penglai-enclave.h"
#include <stdlib.h>
#include <pthread.h>
#include <time.h>

#define MAGIC_SHM_VALUE 11111
#define MAGIC_RELAY_PAGE_VALUE 22222
#define PENGLAI_MAGE_SEC_ADDR 0xfffffff000000000UL
struct args
{
  void* in;
  int i;
};

void printHex(unsigned int *c, int n)
{
	int i;
	for (i = 0; i < n; i++) {
    printf("0x%x\n", c[i]);
	}
}

void printHash(unsigned char *hash)
{
	int i;
	for (i = 0; i < HASH_SIZE; i++) {
    printf("%02x", hash[i]);
	}
  printf("\n");
}

unsigned long pre[512] = {
  0x0000000000000003,

  0x00000000000b3f00,
  0x000000000003d000,
  0xef71679dec2b8ba4,
  0x3400475be7967cf8,
  0x30f39e4220feea2f,
  0x22991b9000e98006,

  0x00000000000b3f00,
  0x000000000003d000,
  0x57e5e62910ccac4e,
  0xa711626af87cad6c,
  0x89ecad5d986a46af,
  0x87b2e6c3e8a48372,

  0x00000000000b3f00,
  0x000000000003d000,
  0x12800d963e9c1dff,
  0x91cd1f86f2080ae9,
  0x36d6a655e0e1fce3,
  0x612e7d32696e6b24,

  0x0000000000000003,

  PENGLAI_MAGE_SEC_ADDR,
  0x0000000000026023,
  0x0000000000000000,
  0xfe901996647a1a46,
  0xffbd6306c008f3be,
  0x000001c65c3d2255,
  0x0000008c691966d9,
  0xfec13f29588c372f,
  0xfffddcc0d955880b,
  0x00055cd2ac5581e8,
  0x0003f0a3a5f8aa32,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000,

  PENGLAI_MAGE_SEC_ADDR,
  0x0000000000026023,
  0x0000000000000000,
  0xfe81385b227d9511,
  0xff9adf9dd0487477,
  0x000000cbb3c8b55e,
  0x0000009fbb49ecc8,
  0xffd8890c90a872cc,
  0xff80eb15446f33c9,
  0x00041c572f0a3641,
  0x000268cbc8a563bb,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000,

  PENGLAI_MAGE_SEC_ADDR,
  0x0000000000026023,
  0x0000000000000000,
  0xff81eca186901914,
  0xfffa321ad4be18df,
  0x0000019e38c37208,
  0x0000015c8eb23906,
  0xfe4963f589d05bce,
  0xff3a384dc99de2ae,
  0x00014102d1b188a5,
  0x00031ad51df07440,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000,
  0x0000000000000000,
};

void* create_enclave(void* in, int i)
{
  int ret = 0, result = 0;

  struct PLenclave* enclave = malloc(sizeof(struct PLenclave));
  struct enclave_args* params = malloc(sizeof(struct enclave_args));
  PLenclave_init(enclave);
  enclave_args_init(params);

  struct elf_args *enclaveFile = (struct elf_args *)in;

  params->mage_ptr = (unsigned long) pre;
  params->mage_size = 4096;

  char str_num[15];
  sprintf(str_num, "hello-mage-%d", i);
  strcpy(params->name, str_num);

  if(PLenclave_create(enclave, enclaveFile, params) < 0)
  {
    printf("host:%d: failed to create enclave\n", i);
  }
  else
  {
    printf("%s's measurement:\n", str_num);
    PLenclave_attest(enclave, 0);
    printHash(enclave->attest_param.report.enclave.hash);

    while (result = PLenclave_run(enclave))
    {
      switch (result)
      {
        case RETURN_USER_RELAY_PAGE:
          PLenclave_set_rerun_arg(enclave, RETURN_USER_RELAY_PAGE);
          break;
        default:
        {
          printf("[ERROR] host: result %d val is wrong!\n", result);
          goto free_enclave;
        }
      }
    }
  }
  PLenclave_destruct(enclave);
  printf("host: PLenclave run is finish \n");

free_enclave:
  free(enclave);
  free(params);
}

int main(int argc, char** argv)
{
  struct elf_args* enclaveFile0 = malloc(sizeof(struct elf_args));
  struct elf_args* enclaveFile1 = malloc(sizeof(struct elf_args));
  struct elf_args* enclaveFile2 = malloc(sizeof(struct elf_args));
  char* eappfile0 = "hello-mage-0";
  char* eappfile1 = "hello-mage-1";
  char* eappfile2 = "hello-mage-2";
  elf_args_init(enclaveFile0, eappfile0);
  elf_args_init(enclaveFile1, eappfile1);
  elf_args_init(enclaveFile2, eappfile2);

  if(!elf_valid(enclaveFile0) || !elf_valid(enclaveFile1) || !elf_valid(enclaveFile2))
  {
    printf("error when initializing enclaveFile\n");
    goto out;
  }

  create_enclave((void*)enclaveFile0, 0);
  create_enclave((void*)enclaveFile1, 1);
  create_enclave((void*)enclaveFile2, 2);
out:
  elf_args_destroy(enclaveFile0);
  elf_args_destroy(enclaveFile1);
  elf_args_destroy(enclaveFile2);
  free(enclaveFile0);
  free(enclaveFile1);
  free(enclaveFile2);

  return 0;
}

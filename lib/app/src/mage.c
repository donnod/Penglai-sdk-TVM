#include "attest.h"
#include "mage.h"
#include "sm3.h"
#include <string.h>
#include "wolfcrypt/sha256.h"

unsigned long sgx_mage_get_size()
{
  sgx_mage_t *sgx_mage = (sgx_mage_t *)PENGLAI_MAGE_SEC_ADDR;
  return sgx_mage->size;
}

unsigned long penglai_mage_get_size()
{
  sgx_mage_t *sgx_mage = (sgx_mage_t *)PENGLAI_MAGE_SEC_ADDR;
  penglai_mage_t *penglai_mage = (penglai_mage_t *)(&(sgx_mage->entries[sgx_mage->size]));
  return penglai_mage->size;
}

void measure_sim(struct sm3_context *hash_ctx, void* hash, unsigned long nonce)
{
  unsigned long curr_va = PENGLAI_MAGE_SEC_ADDR;
  unsigned char pte = 0;
  sm3_update(hash_ctx, (unsigned char*)&curr_va, sizeof(unsigned long));
  sm3_update(hash_ctx, &pte, 1);
  sm3_update(hash_ctx, (void*)curr_va, 4096);
  sm3_update(hash_ctx, (unsigned char*)(&nonce), sizeof(unsigned long));
  sm3_final(hash_ctx, hash);
}

void sgx_mage_derive_measurement(unsigned long mage_idx, void* hash)
{
  sgx_mage_t *sgx_mage = (sgx_mage_t *)PENGLAI_MAGE_SEC_ADDR;

  wc_Sha256 ctx;
  wc_InitSha256(&ctx);

  memcpy(ctx.digest, sgx_mage->entries[mage_idx].digest, SHA256_DIGEST_SIZE);
  memcpy(&ctx.loLen, &(sgx_mage->entries[mage_idx].size), sizeof(unsigned long));

  unsigned long page_offset = sgx_mage->entries[mage_idx].offset;
  unsigned char* source = (unsigned char*)PENGLAI_MAGE_SEC_ADDR;
  unsigned char* mage_sec_end_addr = source + SE_PAGE_SIZE;

  while (source < mage_sec_end_addr) {
      unsigned char eadd_val[SIZE_NAMED_VALUE] = "EADD\0\0\0";
      unsigned char sinfo[64] = {0x01, 0x02};

      unsigned char data_block[DATA_BLOCK_SIZE];
      size_t db_offset = 0;
      memset(data_block, 0, DATA_BLOCK_SIZE);
      memcpy(data_block, eadd_val, SIZE_NAMED_VALUE);
      db_offset += SIZE_NAMED_VALUE;
      memcpy(data_block+db_offset, &page_offset, sizeof(page_offset));
      db_offset += sizeof(page_offset);
      memcpy(data_block+db_offset, &sinfo, sizeof(data_block)-db_offset);

      wc_Sha256Update(&ctx, data_block, DATA_BLOCK_SIZE);

      unsigned char eextend_val[SIZE_NAMED_VALUE] = "EEXTEND";

      #define EEXTEND_TIME  4
      for(int i = 0; i < SE_PAGE_SIZE; i += (DATA_BLOCK_SIZE * EEXTEND_TIME))
      {
          db_offset = 0;
          memset(data_block, 0, DATA_BLOCK_SIZE);
          memcpy(data_block, eextend_val, SIZE_NAMED_VALUE);
          db_offset += SIZE_NAMED_VALUE;
          memcpy(data_block+db_offset, &page_offset, sizeof(page_offset));

          wc_Sha256Update(&ctx, data_block, DATA_BLOCK_SIZE);

          for(int j = 0; j < EEXTEND_TIME; j++)
          {
              memcpy(data_block, source, DATA_BLOCK_SIZE);

              wc_Sha256Update(&ctx, data_block, DATA_BLOCK_SIZE);

              source += DATA_BLOCK_SIZE;
              page_offset += DATA_BLOCK_SIZE;
          }
      }
  }
  wc_Sha256GetHash(&ctx, hash);
}

void penglai_mage_derive_measurement(unsigned long mage_idx, void* hash, unsigned long nonce)
{
  sgx_mage_t *sgx_mage = (sgx_mage_t *)PENGLAI_MAGE_SEC_ADDR;
  penglai_mage_t *penglai_mage = (penglai_mage_t *)(&(sgx_mage->entries[sgx_mage->size]));

  struct sm3_context hash_ctx;
  memcpy(&hash_ctx, (void*)(penglai_mage->entries[mage_idx].total), PENGLAI_SM3_SIZE);

	measure_sim(&hash_ctx, hash, 0);

	sm3_init(&hash_ctx);

  sm3_update(&hash_ctx, (unsigned char*)(hash), HASH_SIZE);

  sm3_update(&hash_ctx, (unsigned char*)(&nonce), sizeof(unsigned long));

  sm3_final(&hash_ctx, hash);
}

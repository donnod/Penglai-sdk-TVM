#ifndef _MAGE_H
#define _MAGE_H
#include "sm3.h"

#define PENGLAI_MAGE_SEC_ADDR 0xfffffff000000000UL
#define PENGLAI_SM3_SIZE sizeof(penglai_mage_entry_t)-sizeof(unsigned long)

#define DATA_BLOCK_SIZE 64
#define SIZE_NAMED_VALUE 8
#define SE_PAGE_SIZE 0x1000

typedef struct _sgx_mage_entry_t
{
  unsigned long size;              // number of blocks updated
  unsigned long offset;            // offset of sgx_mage section
  unsigned char digest[32];         // sha-256 internal state
} sgx_mage_entry_t;

typedef struct _sgx_mage_t
{
  unsigned long size;
  sgx_mage_entry_t entries[];
} sgx_mage_t;

typedef struct _penglai_mage_entry_t
{
  unsigned long offset;            // offset of penglai_mage section
  unsigned long total[2];     /*!< number of bytes processed  */
  unsigned long state[8];     /*!< intermediate digest state  */
  unsigned char buffer[64];   /*!< data block being processed */
} penglai_mage_entry_t;

typedef struct _penglai_mage_t
{
  unsigned long size;
  penglai_mage_entry_t entries[];
} penglai_mage_t;

unsigned long sgx_mage_get_size();
void sgx_mage_derive_measurement(unsigned long mage_idx, void* hash);

unsigned long penglai_mage_get_size();
void penglai_mage_derive_measurement(unsigned long mage_idx, void* hash, unsigned long nonce);

#endif /* _MAGE_H */

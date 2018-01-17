#include <stddef.h>
#include <stdint.h>

#include "sections.h"
#include "sparse.h"
#include "freebsd_helper.h"
#include "elf_helper.h"
#include "self_helper.h"
#include "sbl_helper.h"

#define PAGE_SIZE 0x4000

#define EKPFS_SIZE 0x20
#define EEKPFS_SIZE 0x100
#define PFS_SEED_SIZE 0x10
#define PFS_FINAL_KEY_SIZE 0x20

#define SIZEOF_PFS_KEY_BLOB 0x158


#define CCP_MAX_PAYLOAD_SIZE 0x88

#define CCP_OP(cmd) (cmd >> 24)

#define CCP_OP_XTS 2
#define CCP_OP_HMAC 9

#define CCP_USE_KEY_HANDLE (1 << 20)

#define RIF_DIGEST_SIZE 0x10
#define RIF_DATA_SIZE 0x90
#define RIF_KEY_TABLE_SIZE 0x230
#define RIF_MAX_KEY_SIZE 0x20
#define RIF_PAYLOAD_SIZE (RIF_DIGEST_SIZE + RIF_DATA_SIZE)

#define SIZEOF_ACTDAT 0x200

#define SCE_SBL_ERROR_NPDRM_ENOTSUP 0x800F0A25

#define CONTENT_KEY_SEED_SIZE 0x10
#define SELF_KEY_SEED_SIZE 0x10
#define EEKC_SIZE 0x20

#define SIZEOF_SBL_KEY_RBTREE_ENTRY 0xA8 

#define TYPE_SBL_KEY_RBTREE_ENTRY_DESC_OFFSET 0x04
#define TYPE_SBL_KEY_RBTREE_ENTRY_LOCKED_OFFSET 0x80

#define SIZEOF_SBL_KEY_DESC 0x7C 

#define CCP_OP(cmd) (cmd >> 24)

#define SIZEOF_RSA_KEY 0x48


#define	TRACEBUF	struct qm_trace trace;

#define	TAILQ_FIRST(head) ((head)->tqh_first)
#define	TAILQ_NEXT(elm, field) ((elm)->field.tqe_next)

#define	TAILQ_HEAD(name, type)						\
struct name {								\
	struct type *tqh_first;	/* first element */			\
	struct type **tqh_last;	/* addr of last next element */		\
	TRACEBUF							\
}

#define	TAILQ_ENTRY(type)						\
struct {								\
	struct type *tqe_next;	/* next element */			\
	struct type **tqe_prev;	/* address of previous next element */	\
	TRACEBUF							\
}

#define	LIST_ENTRY(type)						\
struct {								\
	struct type *le_next;	/* next element */			\
	struct type **le_prev;	/* address of previous next element */	\
}

#define	TAILQ_FOREACH(var, head, field)					\
	for ((var) = TAILQ_FIRST((head));				\
	    (var);							\
(var) = TAILQ_NEXT((var), field))


struct qm_trace {
	char * lastfile;
	int lastline;
	char * prevfile;
	int prevline;
};

union ccp_op {
	struct {
		uint32_t cmd;
		uint32_t status;
	} common;

	

	uint8_t buf[CCP_MAX_PAYLOAD_SIZE];
};

struct ccp_msg {
	union ccp_op op;

	uint32_t index;
	uint32_t result;

	TAILQ_ENTRY(ccp_msg) next;

	uint64_t message_id;
	LIST_ENTRY(ccp_link) links;
};

struct ccp_req {
	TAILQ_HEAD(, ccp_msg) msgs;

	void (*cb)(void* arg, int result);
	void* arg;

	uint64_t message_id;
	LIST_ENTRY(ccp_link) links;
};



struct rsa_buffer {
	uint8_t* ptr;
	size_t size;
};

union keymgr_payload {
	struct {
		uint32_t cmd;
		uint32_t status;
		void* mapped_buf;
	};

	uint8_t buf[0x80];
};


union sbl_key_desc {
	struct {
		uint16_t cmd;
		uint16_t pad;
		uint8_t key[0x20];
		uint8_t seed[0x10];
	} pfs;

	

	uint8_t raw[SIZEOF_SBL_KEY_DESC];
};


TYPE_BEGIN(struct rsa_key, SIZEOF_RSA_KEY);
	TYPE_FIELD(uint8_t* p, 0x20);
	TYPE_FIELD(uint8_t* q, 0x28);
	TYPE_FIELD(uint8_t* dmp1, 0x30);
	TYPE_FIELD(uint8_t* dmq1, 0x38);
	TYPE_FIELD(uint8_t* iqmp, 0x40);
TYPE_END();


TYPE_BEGIN(struct sbl_key_rbtree_entry, SIZEOF_SBL_KEY_RBTREE_ENTRY);
	TYPE_FIELD(uint32_t handle, 0x00);
	TYPE_FIELD(union sbl_key_desc desc, TYPE_SBL_KEY_RBTREE_ENTRY_DESC_OFFSET);
	TYPE_FIELD(uint32_t locked, TYPE_SBL_KEY_RBTREE_ENTRY_LOCKED_OFFSET);
	TYPE_FIELD(struct sbl_key_rbtree_entry* left, 0x88);
	TYPE_FIELD(struct sbl_key_rbtree_entry* right, 0x90);
	TYPE_FIELD(struct sbl_key_rbtree_entry* parent, 0x98);
	TYPE_FIELD(uint32_t set, 0xA0);
TYPE_END();

TYPE_CHECK_SIZE(union sbl_key_desc, SIZEOF_SBL_KEY_DESC);


struct ekc {
	uint8_t content_key_seed[CONTENT_KEY_SEED_SIZE];
	uint8_t self_key_seed[SELF_KEY_SEED_SIZE];
};

struct sx {
	struct lock_object	lock_object;
	volatile uintptr_t	sx_lock;
};

#define MAX_FAKE_KEYS 32

struct fake_key_desc {
	uint8_t key[0x20];
	int occupied;
};


 struct fake_key_desc s_fake_keys[MAX_FAKE_KEYS] PAYLOAD_DATA;
 struct sx s_fake_keys_lock PAYLOAD_DATA;


static const uint8_t s_fake_key_seed[0x10] PAYLOAD_RDATA = {
	0x46, 0x41, 0x4B, 0x45, 0x46, 0x41, 0x4B, 0x45, 0x46, 0x41, 0x4B, 0x45, 0x46, 0x41, 0x4B, 0x45,
};


size_t countof(   
   array  
);  

struct pfs_key_blob {
	uint8_t ekpfs[EKPFS_SIZE];
	uint8_t eekpfs[EEKPFS_SIZE];
	struct ekc eekc;
	uint32_t key_ver;
	uint32_t pubkey_ver;
	uint32_t type;
	uint32_t finalized;
	uint32_t is_disc;
	uint32_t pad;
};

typedef struct pfs_key_blob pfs_key_blob_t;

TYPE_CHECK_SIZE(pfs_key_blob_t, SIZEOF_PFS_KEY_BLOB);

int sceSblPfsKeymgrGenEKpfsForGDGPAC(struct pfs_key_blob* key_blob);

struct fpu_kern_ctx;

struct fpu_kern_ctx* fpu_kern_ctx;

struct ccp_link {
	void* p;
};

unsigned int long long __readmsr(unsigned long __register) {
	unsigned long __edx;
	unsigned long __eax;
	__asm__ ("rdmsr" : "=d"(__edx), "=a"(__eax) : "c"(__register));
	return (((unsigned int long long)__edx) << 32) | (unsigned int long long)__eax;
}


static inline struct thread* curthread(void) {
	struct thread* td;

	__asm__ __volatile__ (
		"mov %0, %%gs:0"
		: "=r"(td)
	);

	return td;
}




typedef uint64_t vm_offset_t;

extern void* M_TEMP PAYLOAD_DATA;
extern void* (*real_malloc)(unsigned long size, void* type, int flags) PAYLOAD_DATA;
extern void (*real_free)(void* addr, void* type) PAYLOAD_DATA;
extern void (*real_dealloc)(void*) PAYLOAD_DATA;
extern void* (*real_memcpy)(void* dst, const void* src, size_t len) PAYLOAD_DATA;
extern void* (*real_memset)(void *s, int c, size_t n) PAYLOAD_DATA;
extern void (*real_printf)(const char* fmt, ...) PAYLOAD_DATA;
extern int (*real_sceSblServiceMailbox)(unsigned long service_id, uint8_t request[SBL_MSG_SERVICE_MAILBOX_MAX_SIZE], void* response) PAYLOAD_DATA;
extern int (*real_sceSblAuthMgrGetSelfInfo)(struct self_context* ctx, struct self_ex_info** info) PAYLOAD_DATA;
extern void (*real_sceSblAuthMgrSmStart)(void**) PAYLOAD_DATA;
extern int (*real_sceSblAuthMgrIsLoadable2)(struct self_context* ctx, struct self_auth_info* old_auth_info, int path_id, struct self_auth_info* new_auth_info) PAYLOAD_DATA;
extern int (*real_sceSblAuthMgrVerifyHeader)(struct self_context* ctx) PAYLOAD_DATA;
 extern int (*real_fpu_kern_enter)(struct thread *td, struct fpu_kern_ctx *ctx, uint32_t flags) PAYLOAD_DATA;
extern int (*real_fpu_kern_leave)(struct thread *td, struct fpu_kern_ctx *ctx) PAYLOAD_DATA;
extern void (*real_Sha256Hmac)(uint8_t hash[0x20], const uint8_t* data, size_t data_size, const uint8_t* key, int key_size) PAYLOAD_DATA;
extern int (*real_AesCbcCfb128Decrypt)(uint8_t* out, const uint8_t* in, size_t data_size, const uint8_t* key, int key_size, uint8_t* iv) PAYLOAD_DATA;
extern int (*real_sceSblPfsKeymgrGenEKpfsForGDGPAC)(struct pfs_key_blob* key_blob) PAYLOAD_DATA;
extern int (*real_RsaesPkcs1v15Dec2048CRT)(struct rsa_buffer* out, struct rsa_buffer* in, struct rsa_key* key) PAYLOAD_DATA;
extern int (*real_sceSblPfsSetKey)(uint32_t* ekh, uint32_t* skh, uint8_t* key, uint8_t* iv, int type, int unused, uint8_t is_disc) PAYLOAD_DATA;
extern int (*real_sceSblServiceCryptAsync)(struct ccp_req* request) PAYLOAD_DATA;
extern int (*real_sceSblKeymgrSmCallfunc)(union keymgr_payload* payload) PAYLOAD_DATA;
extern int (*real_sx_xlock)(struct sx *sx, int opts) PAYLOAD_DATA;
extern int (*real_sx_xunlock)(struct sx *sx) PAYLOAD_DATA;

extern int my_sceSblAuthMgrIsLoadable2(struct self_context* ctx, struct self_auth_info* old_auth_info, int path_id, struct self_auth_info* new_auth_info) PAYLOAD_CODE;
extern int my_sceSblAuthMgrVerifyHeader(struct self_context* ctx) PAYLOAD_CODE;
extern int my_sceSblAuthMgrSmLoadSelfSegment__sceSblServiceMailbox(unsigned long service_id, uint8_t* request, void* response) PAYLOAD_CODE;
extern int my_sceSblAuthMgrSmLoadSelfBlock__sceSblServiceMailbox(unsigned long service_id, uint8_t* request, void* response) PAYLOAD_CODE;
extern int my_sceSblKeymgrSmCallfunc_npdrm_decrypt_isolated_rif(union keymgr_payload* payload) PAYLOAD_CODE;
extern int my_sceSblPfsKeymgrGenEKpfsForGDGPAC_sceSblPfsKeymgrIoctl(struct pfs_key_blob* key_blob) PAYLOAD_CODE;
extern int my_sceSblPfsSetKey_pfs_sbl_init(uint32_t* ekh, uint32_t* skh, uint8_t* key, uint8_t* iv, int type, int unused, uint8_t is_disc) PAYLOAD_CODE;
extern int my_sceSblServiceCryptAsync_pfs_crypto(struct ccp_req* request) PAYLOAD_CODE;
extern int my_sceSblKeymgrSmCallfunc_npdrm_decrypt_rif_new(union keymgr_payload* payload) PAYLOAD_CODE;

const struct sbl_map_list_entry** sbl_driver_mapped_pages PAYLOAD_DATA; // here?
const uint8_t* mini_syscore_self_binary PAYLOAD_DATA;
const struct sbl_key_rbtree_entry** sbl_keymgr_key_rbtree PAYLOAD_DATA;
void* fpu_ctx PAYLOAD_DATA;
extern void* M_TEMP PAYLOAD_DATA;

extern int (*npdrm_decrypt_rif_new)( int, struct rif_key_blob* key_blob, struct rif* rif) PAYLOAD_DATA;

extern void (*real_sx_init_flags)(struct sx *sx, const char *description, int opts) PAYLOAD_DATA;


PAYLOAD_CODE static inline void* alloc(uint32_t size)
{
  return real_malloc(size, M_TEMP, 2);
}

PAYLOAD_CODE static inline void dealloc(void* addr)
{
  real_free(addr, M_TEMP);
}

PAYLOAD_CODE static inline const struct sbl_map_list_entry* sceSblDriverFindMappedPageListByGpuVa(vm_offset_t gpu_va)
{
  const struct sbl_map_list_entry* entry;
  if (!gpu_va)
  {
    return NULL;
  }
  entry = *sbl_driver_mapped_pages;
  while (entry)
  {
    if (entry->gpu_va == gpu_va)
    {
      return entry;
    }
    entry = entry->next;
  }
  return NULL;
}

PAYLOAD_CODE static inline vm_offset_t sceSblDriverGpuVaToCpuVa(vm_offset_t gpu_va, size_t* num_page_groups)
{
  const struct sbl_map_list_entry* entry = sceSblDriverFindMappedPageListByGpuVa(gpu_va);
  if (!entry)
  {
    return 0;
  }
  if (num_page_groups)
  {
    *num_page_groups = entry->num_page_groups;
  }
  return entry->cpu_va;
}

PAYLOAD_CODE static inline int sceSblAuthMgrGetSelfAuthInfoFake(struct self_context* ctx, struct self_auth_info* info)
{
  struct self_header* hdr;
  struct self_fake_auth_info* fake_info;

  if (ctx->format == SELF_FORMAT_SELF)
  {
    hdr = (struct self_header*)ctx->header;
    fake_info = (struct self_fake_auth_info*)(ctx->header + hdr->header_size + hdr->meta_size - 0x100);
    if (fake_info->size == sizeof(fake_info->info))
    {
      real_memcpy(info, &fake_info->info, sizeof(*info));
      return 0;
    }
    return -37;
  }
  else
  {
    return -35;
  }
}

PAYLOAD_CODE static inline int is_fake_self(struct self_context* ctx)
{
  struct self_ex_info* ex_info;
  if (ctx && ctx->format == SELF_FORMAT_SELF)
  {
    if (real_sceSblAuthMgrGetSelfInfo(ctx, &ex_info))
    {
      return 0;
    }
    return ex_info->ptype == SELF_PTYPE_FAKE;
  }
  return 0;
}

PAYLOAD_CODE static inline int sceSblAuthMgrGetElfHeader(struct self_context* ctx, struct elf64_ehdr** ehdr)
{
  struct self_header* self_hdr;
  struct elf64_ehdr* elf_hdr;
  size_t pdata_size;


  if (ctx->format == SELF_FORMAT_ELF)
  {
    elf_hdr = (struct elf64_ehdr*)ctx->header;
    if (ehdr)
    {
      *ehdr = elf_hdr;
    }
    return 0;
  }
  else if (ctx->format == SELF_FORMAT_SELF)
  {
    self_hdr = (struct self_header*)ctx->header;
    pdata_size = self_hdr->header_size - sizeof(struct self_entry) * self_hdr->num_entries - sizeof(struct self_header);
    if (pdata_size >= sizeof(struct elf64_ehdr) && (pdata_size & 0xF) == 0)
    {
      elf_hdr = (struct elf64_ehdr*)((uint8_t*)self_hdr + sizeof(struct self_header) + sizeof(struct self_entry) * self_hdr->num_entries);
      if (ehdr)
      {
        *ehdr = elf_hdr;
      }
      return 0;
    }
    return -37;
  }
  return -35;
}

static const uint8_t s_auth_info_for_exec[] PAYLOAD_RDATA =
{
  0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x80, 0x03, 0x00, 0x20,
  0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x40, 0x00, 0x40,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
  0x00, 0x40, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t s_auth_info_for_dynlib[] PAYLOAD_RDATA =
{
  0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x30, 0x00, 0x30,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
  0x00, 0x40, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

PAYLOAD_CODE static int build_self_auth_info_fake(struct self_context* ctx, struct self_auth_info* parent_auth_info, struct self_auth_info* auth_info)
{
  struct self_auth_info fake_auth_info;
  struct self_ex_info* ex_info;
  struct elf64_ehdr* ehdr = NULL;
  int result;

  if (!ctx || !parent_auth_info || !auth_info)
  {
    result = EINVAL;
    goto error;
  }

  if (!is_fake_self(ctx))
  {
    result = EINVAL;
    goto error;
  }

  result = real_sceSblAuthMgrGetSelfInfo(ctx, &ex_info);
  if (result)
  {
    goto error;
  }

  result = sceSblAuthMgrGetElfHeader(ctx, &ehdr);
  if (result)
  {
    goto error;
  }

  if (!ehdr)
  {
    result = ESRCH;
    goto error;
  }

  result = sceSblAuthMgrGetSelfAuthInfoFake(ctx, &fake_auth_info);
  if (result)
  {
    switch (ehdr->type)
    {
      case ELF_ET_EXEC:
      case ELF_ET_SCE_EXEC:
      case ELF_ET_SCE_EXEC_ASLR:
      {
        real_memcpy(&fake_auth_info, s_auth_info_for_exec, sizeof(fake_auth_info));
        result = 0;
        break;
      }

      case ELF_ET_SCE_DYNAMIC:
      {
        real_memcpy(&fake_auth_info, s_auth_info_for_dynlib, sizeof(fake_auth_info));
        result = 0;
        break;
      }

      default:
      {
        result = ENOTSUP;
        goto error;
      }
    }

    fake_auth_info.paid = ex_info->paid;

    
  }

  if (auth_info)
  {
    real_memcpy(auth_info, &fake_auth_info, sizeof(*auth_info));
  }

error:
  return result;
}

PAYLOAD_CODE int my_sceSblAuthMgrIsLoadable2(struct self_context* ctx, struct self_auth_info* old_auth_info, int path_id, struct self_auth_info* new_auth_info)
{

	
  if (ctx->format == SELF_FORMAT_ELF || is_fake_self(ctx))
  {
    return build_self_auth_info_fake(ctx, old_auth_info, new_auth_info);
  }
  else
  {
    return real_sceSblAuthMgrIsLoadable2(ctx, old_auth_info, path_id, new_auth_info);
  }
}

static inline int auth_self_header(struct self_context* ctx)
{
  struct self_header* hdr;
  unsigned int old_total_header_size, new_total_header_size;
  int old_format;
  uint8_t* tmp;
  int is_unsigned;
  int result;

  is_unsigned = ctx->format == SELF_FORMAT_ELF || is_fake_self(ctx);
  if (is_unsigned)
  {
    old_format = ctx->format;
    old_total_header_size = ctx->total_header_size;

   
    hdr = (struct self_header*)mini_syscore_self_binary;

    new_total_header_size = hdr->header_size + hdr->meta_size;

    tmp = (uint8_t*)alloc(new_total_header_size);
    if (!tmp)
    {
      result = ENOMEM;
      goto error;
    }

    
    real_memcpy(tmp, ctx->header, new_total_header_size);
    real_memcpy(ctx->header, hdr, new_total_header_size);

    
    ctx->format = SELF_FORMAT_SELF;
    ctx->total_header_size = new_total_header_size;

    
    result = real_sceSblAuthMgrVerifyHeader(ctx);

    
    real_memcpy(ctx->header, tmp, new_total_header_size);
    ctx->format = old_format;
    ctx->total_header_size = old_total_header_size;

    dealloc(tmp);
  }
  else
  {
    result = real_sceSblAuthMgrVerifyHeader(ctx);
  }

error:
  return result;
}

PAYLOAD_CODE int my_sceSblAuthMgrVerifyHeader(struct self_context* ctx)
{
  void* dummy;	
  real_sceSblAuthMgrSmStart(&dummy);
  return auth_self_header(ctx);
}

PAYLOAD_CODE int my_sceSblAuthMgrSmLoadSelfSegment__sceSblServiceMailbox(unsigned long service_id, uint8_t* request, void* response)
{
  
  uint8_t* frame = (uint8_t*)__builtin_frame_address(1);
  
  struct self_context* ctx = *(struct self_context**)(frame - 0x110);
  int is_unsigned = ctx && is_fake_self(ctx);
  if (is_unsigned)
  {
    *(int*)(response + 0x04) = 0; 
    return 0;
  }
  return real_sceSblServiceMailbox(service_id, request, response);
}

PAYLOAD_CODE int my_sceSblAuthMgrSmLoadSelfBlock__sceSblServiceMailbox(unsigned long service_id, uint8_t* request, void* response)
{
  struct self_context* ctx;
  register struct self_context* ctx_reg __asm__("r12");
  vm_offset_t segment_data_gpu_va = *(unsigned long*)(request + 0x08);
  vm_offset_t cur_data_gpu_va = *(unsigned long*)(request + 0x50);
  vm_offset_t cur_data2_gpu_va = *(unsigned long*)(request + 0x58);
  unsigned int data_offset = *(unsigned int*)(request + 0x44);
  unsigned int data_size = *(unsigned int*)(request + 0x48);
  vm_offset_t segment_data_cpu_va, cur_data_cpu_va, cur_data2_cpu_va;
  unsigned int size1;

  ctx = ctx_reg;

  int is_unsigned = ctx && (ctx->format == SELF_FORMAT_ELF || is_fake_self(ctx));
  int result;

  if (is_unsigned)
  {
    
    segment_data_cpu_va = sceSblDriverGpuVaToCpuVa(segment_data_gpu_va, NULL);
    cur_data_cpu_va = sceSblDriverGpuVaToCpuVa(cur_data_gpu_va, NULL);
    cur_data2_cpu_va = cur_data2_gpu_va ? sceSblDriverGpuVaToCpuVa(cur_data2_gpu_va, NULL) : 0;

    if (segment_data_cpu_va && cur_data_cpu_va)
    {
      if (cur_data2_gpu_va && cur_data2_gpu_va != cur_data_gpu_va && data_offset > 0)
      {
        
        size1 = PAGE_SIZE - data_offset;
        real_memcpy((char*)segment_data_cpu_va, (char*)cur_data_cpu_va + data_offset, size1);
        real_memcpy((char*)segment_data_cpu_va + size1, (char*)cur_data2_cpu_va, data_size - size1);
      }
      else
      {
        real_memcpy((char*)segment_data_cpu_va, (char*)cur_data_cpu_va + data_offset, data_size);
      }
    }

    *(int*)(request + 0x04) = 0; 
    result = 0;
  }
  else
  {
    result = real_sceSblServiceMailbox(service_id, request, response);
  }

  return result;
}
#define SIZEOF_RSA_KEY 0x48
#define EKPFS_SIZE 0x20
#define EEKPFS_SIZE 0x100
#define PFS_SEED_SIZE 0x10
#define PFS_FINAL_KEY_SIZE 0x20
#define SIZEOF_PFS_KEY_BLOB 0x158
#define CCP_MAX_PAYLOAD_SIZE 0x88

#define CCP_OP(cmd) (cmd >> 24)
#define CCP_OP_XTS 2
#define CCP_OP_HMAC 9
#define CCP_USE_KEY_HANDLE (1 << 20)

#define SBL_MSG_SERVICE_MAILBOX_MAX_SIZE 0x80

struct sbl_mapped_page_group;

#define SIZEOF_SBL_MAP_LIST_ENTRY 0x50 
#define CONTENT_KEY_SEED_SIZE 0x10
#define SELF_KEY_SEED_SIZE 0x10
#define EEKC_SIZE 0x20

#define SIZEOF_SBL_KEY_RBTREE_ENTRY 0xA8 

#define TYPE_SBL_KEY_RBTREE_ENTRY_DESC_OFFSET 0x04
#define TYPE_SBL_KEY_RBTREE_ENTRY_LOCKED_OFFSET 0x80
#define RIF_DIGEST_SIZE 0x10
#define RIF_DATA_SIZE 0x90
#define RIF_KEY_TABLE_SIZE 0x230
#define RIF_MAX_KEY_SIZE 0x20
#define RIF_PAYLOAD_SIZE (RIF_DIGEST_SIZE + RIF_DATA_SIZE)

#define SIZEOF_ACTDAT 0x200

TYPE_BEGIN(struct actdat, SIZEOF_ACTDAT);
	TYPE_FIELD(uint32_t magic, 0x00);
	TYPE_FIELD(uint16_t version_major, 0x04);
	TYPE_FIELD(uint16_t version_minor, 0x06);
	TYPE_FIELD(uint64_t account_id, 0x08);
	TYPE_FIELD(uint64_t start_time, 0x10);
	TYPE_FIELD(uint64_t end_time, 0x18);
	TYPE_FIELD(uint64_t flags, 0x20);
	TYPE_FIELD(uint32_t unk3, 0x28);
	TYPE_FIELD(uint32_t unk4, 0x2C);
	TYPE_FIELD(uint8_t open_psid_hash[0x20], 0x60);
	TYPE_FIELD(uint8_t static_per_console_data_1[0x20], 0x80);
	TYPE_FIELD(uint8_t digest[0x10], 0xA0);
	TYPE_FIELD(uint8_t key_table[0x20], 0xB0);
	TYPE_FIELD(uint8_t static_per_console_data_2[0x10], 0xD0);
	TYPE_FIELD(uint8_t static_per_console_data_3[0x20], 0xE0);
	TYPE_FIELD(uint8_t signature[0x100], 0x100);
TYPE_END();

#define SIZEOF_RIF 0x400

TYPE_BEGIN(struct rif, SIZEOF_RIF);
	TYPE_FIELD(uint32_t magic, 0x00);
	TYPE_FIELD(uint16_t version_major, 0x04);
	TYPE_FIELD(uint16_t version_minor, 0x06);
	TYPE_FIELD(uint64_t account_id, 0x08);
	TYPE_FIELD(uint64_t start_time, 0x10);
	TYPE_FIELD(uint64_t end_time, 0x18);
	TYPE_FIELD(char content_id[0x30], 0x20);
	TYPE_FIELD(uint16_t format, 0x50);
	TYPE_FIELD(uint16_t drm_type, 0x52);
	TYPE_FIELD(uint16_t content_type, 0x54);
	TYPE_FIELD(uint16_t sku_flag, 0x56);
	TYPE_FIELD(uint64_t content_flags, 0x58);
	TYPE_FIELD(uint32_t iro_tag, 0x60);
	TYPE_FIELD(uint32_t ekc_version, 0x64);
	TYPE_FIELD(uint16_t unk3, 0x6A);
	TYPE_FIELD(uint16_t unk4, 0x6C);
	TYPE_FIELD(uint8_t digest[0x10], 0x260);
	TYPE_FIELD(uint8_t data[RIF_DATA_SIZE], 0x270);
	TYPE_FIELD(uint8_t signature[0x100], 0x300);
TYPE_END();


/*
PAYLOAD_CODE int hexDumpKern(const void *data, size_t size){

	unsigned char *d = (unsigned char *)data;
	size_t consoleSize = 16;
	char b[consoleSize + 3];
	size_t i;


	if(data == NULL){
		return -1;
		}
	b[0] = '|';
	b[consoleSize + 1] = '|';
	b[consoleSize + 2] = '\0';

	for (i = 0; i < size; i++)
	{
		if ((i % consoleSize) == 0)
		{
			if (i != 0){

				}

		}

		if(i % consoleSize == 8)


		if (d[i] >= ' ' && d[i] <= '~')
			b[i % consoleSize + 1] = d[i];

		else
			b[i % consoleSize + 1] = '.';
		}

		while((i % consoleSize) != 0)
		{

		if(i % consoleSize == 8)

	
		else

			b[i % consoleSize + 1] = '.';
			i++;
		}

		return 0;
}
*/
#define _countof(a) (sizeof(a)/sizeof(*(a)))

PAYLOAD_CODE static struct fake_key_desc* get_free_fake_key_slot(void) {
	struct fake_key_desc* slot = NULL;
	size_t i;


	real_sx_xlock(&s_fake_keys_lock,0);
	{

		for (i = 0; i < _countof(s_fake_keys); ++i) {
			if (!s_fake_keys[i].occupied) {
				s_fake_keys[i].occupied = 1;
				slot = s_fake_keys + i;
				break;
			}
		}
	}
	real_sx_xunlock(&s_fake_keys_lock);


	return slot;
}

PAYLOAD_CODE static inline struct sbl_key_rbtree_entry* sceSblKeymgrGetKey(unsigned int handle) {
	struct sbl_key_rbtree_entry* entry = *sbl_keymgr_key_rbtree;

	while (entry) {
		if (entry->handle < handle)
			entry = entry->right;
		else if (entry->handle > handle)
			entry = entry->left;
		else if (entry->handle == handle)
			return entry;
	}


	return NULL;
}


PAYLOAD_CODE static struct fake_key_desc* is_fake_pfs_key(uint8_t* key) {
	struct fake_key_desc* slot = NULL;
	size_t i;

	real_sx_xlock(&s_fake_keys_lock,0);
	{

		for (i = 0; i < _countof(s_fake_keys); ++i) {
			if (!s_fake_keys[i].occupied)
				continue;

			if (real_memcmp(s_fake_keys[i].key, key, sizeof(s_fake_keys[i].key)) == 0) {
				slot = s_fake_keys + i;
				break;
			}
		}
	}
	real_sx_xunlock(&s_fake_keys_lock);


	return slot;
}

PAYLOAD_CODE static void debug_pfs_cleanup(void* arg) {

	real_sx_destroy(&s_fake_keys_lock);

}

static const uint8_t s_ypkg_n[0x100] PAYLOAD_RDATA = {
  0x27, 0x3E, 0xBD, 0x7C, 0x3A, 0xE3, 0x8E, 0x58, 0x90, 0x45, 0x35, 0xC8, 0xAF, 0x22, 0x05, 0xB8,
  0xF9, 0xD1, 0x80, 0xFD, 0x3D, 0xA8, 0x3A, 0xF1, 0xB1, 0x50, 0xA0, 0xA2, 0x62, 0x2D, 0xCF, 0x40,
  0x93, 0xFF, 0x67, 0x24, 0xEF, 0x8D, 0xE5, 0x05, 0xC0, 0x34, 0x50, 0xA0, 0xC2, 0x4B, 0x7F, 0x68,
  0xDB, 0x6B, 0x1B, 0xD6, 0xCD, 0x2B, 0xA6, 0x5B, 0xC9, 0xE2, 0x97, 0x8B, 0xFD, 0x22, 0xFB, 0x3F,
  0x4A, 0x10, 0x2C, 0x57, 0xF4, 0x6C, 0xCF, 0x4C, 0xD2, 0xA2, 0x69, 0xC2, 0x53, 0xD3, 0x81, 0x94,
  0x34, 0x50, 0xBD, 0x80, 0xE1, 0x05, 0x18, 0x8E, 0x79, 0xB7, 0xBB, 0x9F, 0xBF, 0xBE, 0xC9, 0xFB,
  0xA8, 0x28, 0x75, 0xEA, 0x77, 0x52, 0xFF, 0xFE, 0x2E, 0x69, 0x80, 0x0E, 0x57, 0x09, 0x58, 0x03,
  0x4F, 0x95, 0x81, 0xDF, 0x0C, 0xCC, 0xF8, 0x0D, 0xB1, 0x96, 0xED, 0x79, 0x0D, 0x02, 0xA5, 0xD8,
  0xB2, 0x1B, 0x13, 0x30, 0x42, 0x2C, 0x83, 0xB9, 0x6A, 0x69, 0x52, 0xDC, 0xF3, 0x14, 0x67, 0xE7,
  0x64, 0x13, 0xAC, 0xC6, 0x6D, 0x2C, 0xF9, 0x01, 0x67, 0xBD, 0x00, 0x3D, 0xCB, 0xEA, 0xF8, 0x5F,
  0x4E, 0x47, 0x9F, 0xED, 0xFC, 0x3B, 0x33, 0x68, 0x19, 0x60, 0xBE, 0x5B, 0xBF, 0x8A, 0x4F, 0xA9,
  0x63, 0x1E, 0x24, 0x1D, 0xDE, 0x0C, 0x77, 0xFF, 0x9D, 0xE7, 0x20, 0xBF, 0x88, 0x15, 0xC3, 0x30,
  0x3D, 0xEB, 0x87, 0x4F, 0xE7, 0xC9, 0x03, 0x48, 0xA2, 0x16, 0xCF, 0x56, 0xEB, 0x18, 0x44, 0xB8,
  0x44, 0xC6, 0x23, 0x2B, 0x68, 0x02, 0x55, 0xAA, 0x7E, 0x08, 0x6C, 0x7D, 0xF2, 0xA0, 0xD7, 0xA0,
  0x9B, 0x25, 0x9D, 0x35, 0xDE, 0x7D, 0x49, 0xCD, 0x1D, 0x80, 0x17, 0x71, 0xC3, 0x8B, 0x05, 0x43,
  0xC1, 0x0E, 0x2A, 0xF9, 0x8B, 0x45, 0x2C, 0x2A, 0xD1, 0xF0, 0x9A, 0xE5, 0xE7, 0x71, 0xCF, 0xC6,
};

static const unsigned int s_ypkg_e = UINT32_C(0x10001);

static const uint8_t s_ypkg_d[0x100] PAYLOAD_RDATA = {
  0xB1, 0xC6, 0x89, 0x79, 0x8A, 0xFE, 0x6F, 0xD6, 0xC7, 0x80, 0xC5, 0x7D, 0x92, 0x80, 0xA6, 0x37,
  0x39, 0xEC, 0x4A, 0x40, 0x83, 0x37, 0x1F, 0x4D, 0xF5, 0xD7, 0x1A, 0x96, 0x79, 0x90, 0x99, 0x85,
  0x68, 0xC0, 0xC9, 0x6B, 0x45, 0x2D, 0xB4, 0x12, 0x09, 0x83, 0xDF, 0x1B, 0x56, 0x48, 0xC1, 0xE0,
  0x07, 0x22, 0x3F, 0x79, 0x99, 0x7D, 0x23, 0xC0, 0x24, 0x50, 0xDE, 0x9A, 0x6C, 0xE5, 0x63, 0x93,
  0xAB, 0x42, 0xD0, 0x73, 0x93, 0x46, 0x48, 0xAB, 0xF4, 0xAF, 0x67, 0x71, 0xB5, 0x43, 0x27, 0x1A,
  0x0E, 0xBB, 0x78, 0xAC, 0x44, 0x66, 0x22, 0x4A, 0xBA, 0xDB, 0x23, 0x93, 0x50, 0x3C, 0x2B, 0xC7,
  0x6A, 0xE2, 0x15, 0x97, 0x3C, 0x9D, 0xF4, 0xDF, 0x3D, 0xCE, 0xE0, 0x09, 0xB0, 0xA5, 0x8C, 0xC5,
  0xA1, 0x7C, 0x6E, 0xDA, 0x49, 0x82, 0x43, 0xD5, 0x58, 0x22, 0x13, 0x3D, 0x39, 0x97, 0x13, 0x0C,
  0x03, 0x11, 0x44, 0x8F, 0x52, 0xB8, 0x73, 0xF3, 0x90, 0x6B, 0xE9, 0xA2, 0x9E, 0x5E, 0x7E, 0x66,
  0x26, 0xD1, 0x20, 0xCE, 0xB9, 0x6B, 0xD4, 0x77, 0x1D, 0xAD, 0x51, 0xE6, 0xC0, 0x7B, 0xB8, 0xB9,
  0x2B, 0xF4, 0xA9, 0xA4, 0x27, 0x5B, 0x14, 0x4E, 0x0C, 0xBC, 0xCC, 0x68, 0x63, 0x9B, 0x0F, 0xD6,
  0xA3, 0x0B, 0xA0, 0xF6, 0x8A, 0x09, 0x83, 0x28, 0x21, 0xD2, 0x9E, 0xA4, 0xFB, 0xD1, 0xB8, 0xA1,
  0xA4, 0xCF, 0x1B, 0xD3, 0x8F, 0x2C, 0x49, 0xD1, 0x66, 0x26, 0x9A, 0x0B, 0x44, 0x07, 0xBE, 0x11,
  0x6E, 0x49, 0x56, 0x5C, 0x22, 0xB1, 0xB2, 0x63, 0x3E, 0xE2, 0x8B, 0xFB, 0x01, 0xBD, 0xBC, 0xC2,
  0xF8, 0xEE, 0xFD, 0xDB, 0xDD, 0x35, 0x87, 0x22, 0xF1, 0xF8, 0x40, 0x1A, 0x27, 0xAA, 0x1E, 0xCA,
  0x7B, 0xFA, 0x8D, 0x0E, 0xA8, 0xD9, 0xC6, 0x1C, 0x05, 0xDE, 0xD4, 0xE2, 0x0E, 0xCD, 0x76, 0x7F,
};




static const uint8_t s_ypkg_p[0x80] PAYLOAD_RDATA= {
  0x2D, 0xE8, 0xB4, 0x65, 0xBE, 0x05, 0x78, 0x6A, 0x89, 0x31, 0xC9, 0x5A, 0x44, 0xDE, 0x50, 0xC1,
  0xC7, 0xFD, 0x9D, 0x3E, 0x21, 0x42, 0x17, 0x40, 0x79, 0xF9, 0xC9, 0x41, 0xC1, 0xFC, 0xD7, 0x0F,
  0x34, 0x76, 0xA3, 0xE2, 0xC0, 0x1B, 0x5A, 0x20, 0x0F, 0xAF, 0x2F, 0x52, 0xCD, 0x83, 0x34, 0x72,
  0xAF, 0xB3, 0x12, 0x33, 0x21, 0x2C, 0x20, 0xB0, 0xC6, 0xA0, 0x2D, 0xB1, 0x59, 0xE3, 0xA7, 0xB0,
  0x4E, 0x1C, 0x4C, 0x5B, 0x5F, 0x10, 0x9A, 0x50, 0x18, 0xCC, 0x86, 0x79, 0x25, 0xFF, 0x10, 0x02,
  0x8F, 0x90, 0x03, 0xA9, 0x37, 0xBA, 0xF2, 0x1C, 0x13, 0xCC, 0x09, 0x45, 0x15, 0xB8, 0x55, 0x74,
  0x0A, 0x28, 0x24, 0x04, 0xD1, 0x19, 0xAB, 0xB3, 0xCA, 0x44, 0xB6, 0xF8, 0x3D, 0xB1, 0x2A, 0x72,
  0x88, 0x35, 0xE4, 0x86, 0x6B, 0x55, 0x47, 0x08, 0x25, 0x16, 0xAB, 0x69, 0x1D, 0xBF, 0xF6, 0xFE,
};

static const uint8_t s_ypkg_q[0x80] PAYLOAD_RDATA= {
  0x23, 0x80, 0x77, 0x84, 0x4D, 0x6F, 0x9B, 0x24, 0x51, 0xFE, 0x2A, 0x6B, 0x28, 0x80, 0xA1, 0x9E,
  0xBD, 0x6D, 0x18, 0xCA, 0x8D, 0x7D, 0x9E, 0x79, 0x5A, 0xE0, 0xB8, 0xEB, 0xD1, 0x3D, 0xF3, 0xD9,
  0x02, 0x90, 0x2A, 0xA7, 0xB5, 0x7E, 0x9A, 0xA2, 0xD7, 0x2F, 0x21, 0xA8, 0x50, 0x7D, 0x8C, 0xA1,
  0x91, 0x2F, 0xBF, 0x97, 0xBE, 0x92, 0xC2, 0xC1, 0x0D, 0x8C, 0x0C, 0x1F, 0xDE, 0x31, 0x35, 0x15,
  0x39, 0x90, 0xCC, 0x97, 0x47, 0x2E, 0x7F, 0x09, 0xE9, 0xC3, 0x9C, 0xCE, 0x91, 0xB2, 0xC8, 0x58,
  0x76, 0xE8, 0x70, 0x1D, 0x72, 0x5F, 0x4A, 0xE6, 0xAA, 0x36, 0x22, 0x94, 0xC6, 0x52, 0x90, 0xB3,
  0x9F, 0x9B, 0xF0, 0xEF, 0x57, 0x8E, 0x53, 0xC3, 0xE3, 0x30, 0xC9, 0xD7, 0xB0, 0x3A, 0x0C, 0x79,
  0x1B, 0x97, 0xA8, 0xD4, 0x81, 0x22, 0xD2, 0xB0, 0x82, 0x62, 0x7D, 0x00, 0x58, 0x47, 0x9E, 0xC7,
};

static const uint8_t s_ypkg_dmp1[0x80] PAYLOAD_RDATA= {
  0x25, 0x54, 0xDB, 0xFD, 0x86, 0x45, 0x97, 0x9A, 0x1E, 0x17, 0xF0, 0xE3, 0xA5, 0x92, 0x0F, 0x12,
  0x2A, 0x5C, 0x4C, 0xA6, 0xA5, 0xCF, 0x7F, 0xE8, 0x5B, 0xF3, 0x65, 0x1A, 0xC8, 0xCF, 0x9B, 0xB9,
  0x2A, 0xC9, 0x90, 0x5D, 0xD4, 0x08, 0xCF, 0xF6, 0x03, 0x5A, 0x5A, 0xFC, 0x9E, 0xB6, 0xDB, 0x11,
  0xED, 0xE2, 0x3D, 0x62, 0xC1, 0xFC, 0x88, 0x5D, 0x97, 0xAC, 0x31, 0x2D, 0xC3, 0x15, 0xAD, 0x70,
  0x05, 0xBE, 0xA0, 0x5A, 0xE6, 0x34, 0x9C, 0x44, 0x78, 0x2B, 0xE5, 0xFE, 0x38, 0x56, 0xD4, 0x68,
  0x83, 0x13, 0xA4, 0xE6, 0xFA, 0xD2, 0x9C, 0xAB, 0xAC, 0x89, 0x5F, 0x10, 0x8F, 0x75, 0x6F, 0x04,
  0xBC, 0xAE, 0xB9, 0xBC, 0xB7, 0x1D, 0x42, 0xFA, 0x4E, 0x94, 0x1F, 0xB4, 0x0A, 0x27, 0x9C, 0x6B,
  0xAB, 0xC7, 0xD2, 0xEB, 0x27, 0x42, 0x52, 0x29, 0x41, 0xC8, 0x25, 0x40, 0x54, 0xE0, 0x48, 0x6D,
};

static const uint8_t s_ypkg_dmq1[0x80]PAYLOAD_RDATA = {
  0x4D, 0x35, 0x67, 0x38, 0xBC, 0x90, 0x3E, 0x3B, 0xAA, 0x6C, 0xBC, 0xF2, 0xEB, 0x9E, 0x45, 0xD2,
  0x09, 0x2F, 0xCA, 0x3A, 0x9C, 0x02, 0x36, 0xAD, 0x2E, 0xC1, 0xB1, 0xB2, 0x6D, 0x7C, 0x1F, 0x6B,
  0xA1, 0x8F, 0x62, 0x20, 0x8C, 0xD6, 0x6C, 0x36, 0xD6, 0x5A, 0x54, 0x9E, 0x30, 0xA9, 0xA8, 0x25,
  0x3D, 0x94, 0x12, 0x3E, 0x0D, 0x16, 0x1B, 0xF0, 0x86, 0x42, 0x72, 0xE0, 0xD6, 0x9C, 0x39, 0x68,
  0xDB, 0x11, 0x80, 0x96, 0x18, 0x2B, 0x71, 0x41, 0x48, 0x78, 0xE8, 0x17, 0x8B, 0x7D, 0x00, 0x1F,
  0x16, 0x68, 0xD2, 0x75, 0x97, 0xB5, 0xE0, 0xF2, 0x6D, 0x0C, 0x75, 0xAC, 0x16, 0xD9, 0xD5, 0xB1,
  0xB5, 0x8B, 0xE8, 0xD0, 0xBF, 0xA7, 0x1F, 0x61, 0x5B, 0x08, 0xF8, 0x68, 0xE7, 0xF0, 0xD1, 0xBC,
  0x39, 0x60, 0xBF, 0x55, 0x9C, 0x7C, 0x20, 0x30, 0xE8, 0x50, 0x28, 0x44, 0x02, 0xCE, 0x51, 0x2A,
};




static const uint8_t s_ypkg_iqmp[0x80] PAYLOAD_RDATA= {
  0xF5, 0x73, 0xB8, 0x7E, 0x5C, 0x98, 0x7C, 0x87, 0x67, 0xF1, 0xDA, 0xAE, 0xA0, 0xF9, 0x4B, 0xAB,
  0x77, 0xD8, 0xCE, 0x64, 0x6A, 0xC1, 0x4F, 0xA6, 0x9B, 0xB9, 0xAA, 0xCC, 0x76, 0x09, 0xA4, 0x3F,
  0xB9, 0xFA, 0xF5, 0x62, 0x84, 0x0A, 0xB8, 0x49, 0x02, 0xDF, 0x9E, 0xC4, 0x1A, 0x37, 0xD3, 0x56,
  0x0D, 0xA4, 0x6E, 0x15, 0x07, 0x15, 0xA0, 0x8D, 0x97, 0x9D, 0x92, 0x20, 0x43, 0x52, 0xC3, 0xB2,
  0xFD, 0xF7, 0xD3, 0xF3, 0x69, 0xA2, 0x28, 0x4F, 0x62, 0x6F, 0x80, 0x40, 0x5F, 0x3B, 0x80, 0x1E,
  0x5E, 0x38, 0x0D, 0x8B, 0x56, 0xA8, 0x56, 0x58, 0xD8, 0xD9, 0x6F, 0xEA, 0x12, 0x2A, 0x40, 0x16,
  0xC1, 0xED, 0x3D, 0x27, 0x16, 0xA0, 0x63, 0x97, 0x61, 0x39, 0x55, 0xCC, 0x8A, 0x05, 0xFA, 0x08,
  0x28, 0xFD, 0x55, 0x56, 0x31, 0x94, 0x65, 0x05, 0xE7, 0xD3, 0x57, 0x6C, 0x0D, 0x1C, 0x67, 0x0B,
};

	static const uint8_t eekpfs_flatz[EEKPFS_SIZE] PAYLOAD_RDATA = {0xB7, 0x67, 0xD3, 0x81, 0x21, 0x31, 0x58, 0xA2, 0xAB, 0xFD, 0x0D, 0x0D, 0x57, 0x82, 0x0D, 0x6E, 0x95, 0x7B, 0x00, 0xFC, 0xAD, 0x80, 0xBF, 0x2F, 0x36, 0x7C, 0x53, 0x51, 0x03, 0xC1, 0x0C, 0x42, 0xD3, 0xD3, 0x4C, 0x39, 0x4C, 0x00, 0x62, 0x58, 0x32, 0xBF, 0xF4, 0x9A, 0xE4, 0x5E, 0x13, 0x48, 0xA7, 0xFD, 0xB3, 0xD5, 0xDE, 0xBD, 0x0F, 0xFB, 0x35, 0x13, 0xDD, 0x3F, 0x12, 0x32, 0xD5, 0xC8, 0x32, 0x15, 0x7C, 0x0A, 0x69, 0x54, 0x05, 0x52, 0xAD, 0x4B, 0x0B, 0x4A, 0x8E, 0x5B, 0x39, 0x78, 0xCC, 0xE1, 0x76, 0xBA, 0xD8, 0xD9, 0x70, 0x74, 0x50, 0x65, 0x43, 0x30, 0x7C, 0xF7, 0x40, 0x35, 0x42, 0x7E, 0x36, 0xF8, 0x09, 0xE0, 0x0D, 0x23, 0xC7, 0x3A, 0x7C, 0x65, 0x98, 0x73, 0x7B, 0x85, 0x6A, 0xCB, 0xB1, 0x16, 0x5C, 0x02, 0x95, 0xDC, 0x52, 0x6B, 0x6A, 0x85, 0x9B, 0xF0, 0xC4, 0x3D, 0xAC, 0x13, 0x64, 0xCD, 0x0D, 0x2F, 0xDF, 0x61, 0xBB, 0x5E, 0x84, 0xF0, 0x83, 0x3F, 0x26, 0x88, 0x37, 0xCA, 0x8D, 0xC8, 0x3C, 0x05, 0x70, 0xA5, 0x4C, 0x17, 0xD5, 0x73, 0x4B, 0x0F, 0x6A, 0xE5, 0x89, 0x2D, 0x28, 0x1C, 0x72, 0x8B, 0x6B, 0xC3, 0xD0, 0xC5, 0x21, 0xB1, 0x51, 0xB7, 0x99, 0x15, 0x39, 0x99, 0x21, 0x5F, 0xF6, 0xBC, 0x72, 0x41, 0xC3, 0xAC, 0xC8, 0x9F, 0x38, 0x8D, 0x82, 0x42, 0x76, 0xD5, 0x28, 0xFA, 0x76, 0x86, 0xF6, 0x8B, 0x5B, 0xAC, 0x63, 0xBE, 0x4F, 0x77, 0x91, 0xA4, 0xE7, 0x48, 0xBC, 0x9B, 0xF6, 0x84, 0xEE, 0xFB, 0x6E, 0x63, 0x8E, 0x5A, 0xB8, 0xF7, 0xF7, 0x2C, 0x76, 0xBA, 0x1D, 0xB7, 0x8D, 0xCC, 0x55, 0x7F, 0x4D, 0x73, 0xB8, 0xBE, 0xC3, 0x13, 0xA6, 0x38, 0xB4, 0x7E, 0x1F, 0x48, 0x4A, 0xBD, 0xA8, 0x70, 0xF4, 0x8F, 0x00, 0x4A, 0x58, 0x18, 0x69, 0xE9};


PAYLOAD_CODE inline void pfs_gen_crypto_key(uint8_t* ekpfs, uint8_t seed[PFS_SEED_SIZE], unsigned int index, uint8_t key[PFS_FINAL_KEY_SIZE]) {

	struct thread* td = curthread();

	uint8_t d[4 + PFS_SEED_SIZE];

	real_memset(d, 0, sizeof(d));

	
	*(uint32_t*)d = (uint32_t)(index);
	real_memcpy(d + sizeof(uint32_t), seed, PFS_SEED_SIZE);

	real_fpu_kern_enter(td, fpu_ctx,0);
	{

		real_Sha256Hmac(key, d, sizeof(d), ekpfs, EKPFS_SIZE);

	}
	real_fpu_kern_leave(td, fpu_ctx);

}

 
PAYLOAD_CODE inline void pfs_generate_enc_key(uint8_t* ekpfs, uint8_t seed[PFS_SEED_SIZE], uint8_t key[PFS_FINAL_KEY_SIZE]) {

	pfs_gen_crypto_key(ekpfs, seed, 1, key);

}


PAYLOAD_CODE inline void pfs_generate_sign_key(uint8_t* ekpfs, uint8_t seed[PFS_SEED_SIZE], uint8_t key[PFS_FINAL_KEY_SIZE]) {

	pfs_gen_crypto_key(ekpfs, seed, 2, key);

}

PAYLOAD_CODE inline int my_sceSblPfsKeymgrGenEKpfsForGDGPAC_sceSblPfsKeymgrIoctl(struct pfs_key_blob* blob) {

	struct thread* td = curthread();

	struct rsa_buffer in_data;
	struct rsa_buffer out_data;
	struct rsa_key key;
	uint8_t dec_data[EEKPFS_SIZE];
	struct fake_key_desc* fake_key_slot;
	int ret;

	ret = real_sceSblPfsKeymgrGenEKpfsForGDGPAC(blob);


	if (ret) {

		if (!blob->finalized) {

			real_memset(&in_data, 0, sizeof(in_data));
			{


				in_data.ptr = blob->eekpfs;
				in_data.size = sizeof(blob->eekpfs);

			}

			real_memset(&out_data, 0, sizeof(out_data));
			{
				out_data.ptr = dec_data;
				out_data.size = sizeof(dec_data);

			}

			real_memset(&key, 0, sizeof(key));
			{

				key.p = (uint8_t*)s_ypkg_p;
				key.q = (uint8_t*)s_ypkg_q;
				key.dmp1 = (uint8_t*)s_ypkg_dmp1;
				key.dmq1 = (uint8_t*)s_ypkg_dmq1;
				key.iqmp = (uint8_t*)s_ypkg_iqmp;


			}

			real_fpu_kern_enter(td, fpu_ctx,0);
			{
				
				ret = real_RsaesPkcs1v15Dec2048CRT(&out_data, &in_data, &key);


			}
			real_fpu_kern_leave(td, fpu_ctx);

			if (ret == 0) { 
				real_memcpy(blob->ekpfs, dec_data, sizeof(blob->ekpfs));

				fake_key_slot = get_free_fake_key_slot();
				if (fake_key_slot)
					real_memcpy(fake_key_slot->key, blob->ekpfs, sizeof(fake_key_slot->key));
			}
		}
	}

	return ret;
}

PAYLOAD_CODE int my_sceSblPfsSetKey_pfs_sbl_init(unsigned int* ekh, unsigned int* skh, uint8_t* key, uint8_t* iv, int mode, int unused, uint8_t disc_flag) {
	struct sbl_key_rbtree_entry* key_entry;
	int is_fake_key;
	int ret;

	ret = real_sceSblPfsSetKey(ekh, skh, key, iv, mode, unused, disc_flag);

	is_fake_key = is_fake_pfs_key(key) != NULL;


	key_entry = sceSblKeymgrGetKey(*ekh); 
	if (key_entry) {

		if (is_fake_key) {

			 
			pfs_generate_enc_key(key, iv, key_entry->desc.pfs.key);
			real_memcpy(key_entry->desc.pfs.seed, s_fake_key_seed, sizeof(s_fake_key_seed));
		}
	}
	key_entry = sceSblKeymgrGetKey(*skh); 
	if (key_entry) {

		if (is_fake_key) {

			
			pfs_generate_sign_key(key, iv, key_entry->desc.pfs.key);
			real_memcpy(key_entry->desc.pfs.seed, s_fake_key_seed, sizeof(s_fake_key_seed));
		}
	}

	return ret;
}



PAYLOAD_CODE inline int npdrm_decrypt_debug_rif(unsigned int type, uint8_t* data) {


	static const uint8_t rif_debug_key[0x10] PAYLOAD_RDATA = { 0x96, 0xC2, 0x26, 0x8D, 0x69, 0x26, 0x1C, 0x8B, 0x1E, 0x3B, 0x6B, 0xFF, 0x2F, 0xE0, 0x4E, 0x12 };
	
	struct thread* td = curthread();

	int ret;

	


	real_fpu_kern_enter(td, fpu_ctx,0);
	{

		ret = real_AesCbcCfb128Decrypt(data + RIF_DIGEST_SIZE, data + RIF_DIGEST_SIZE, RIF_DATA_SIZE, rif_debug_key, sizeof(rif_debug_key) * 8, data);

		if (ret)
			ret = SCE_SBL_ERROR_NPDRM_ENOTSUP;
	}
	real_fpu_kern_leave(td, fpu_ctx);

	return ret;
}



#define RIF_KEY_TABLE_SIZE 0x230
#define SIZEOF_RIF 0x400

struct rif_key_blob {
	struct ekc ekc;
	uint8_t entitlement_key[0x10];
};

union keymgr_request {
	struct {
		uint32_t type;
		uint8_t key[RIF_MAX_KEY_SIZE];
		uint8_t data[RIF_DIGEST_SIZE + RIF_DATA_SIZE];
	} decrypt_rif;

	struct {
		struct rif rif;
		uint8_t key_table[RIF_KEY_TABLE_SIZE];
		uint64_t timestamp;
		int status;
	} decrypt_entire_rif;
};

union keymgr_response {
	struct {
		uint32_t type;
		uint8_t key[RIF_MAX_KEY_SIZE];
		uint8_t data[RIF_DIGEST_SIZE + RIF_DATA_SIZE];
	} decrypt_rif;

	struct {
		uint8_t raw[SIZEOF_RIF];
	} decrypt_entire_rif;
};



PAYLOAD_CODE int my_sceSblKeymgrSmCallfunc_npdrm_decrypt_rif_new(union keymgr_payload* payload) {
	uint64_t buf_gpu_va = (uint64_t)payload->mapped_buf;

	union keymgr_request* request = (union keymgr_request*)sceSblDriverGpuVaToCpuVa(buf_gpu_va, NULL);
	union keymgr_response* response = (union keymgr_response*)request;
	struct ekc* eekc;
	int orig_ret, ret;

	ret = orig_ret = real_sceSblKeymgrSmCallfunc(payload);

	if ((ret != 0 || payload->status != 0) && request) {

		if (request->decrypt_entire_rif.rif.format != 2) { 
			ret = orig_ret;
			goto err;
		}

		ret = npdrm_decrypt_debug_rif(request->decrypt_entire_rif.rif.format, request->decrypt_entire_rif.rif.digest);

		if (ret) {
			ret = orig_ret;
			goto err;
		}

		real_memcpy(response->decrypt_entire_rif.raw, request->decrypt_entire_rif.rif.digest, sizeof(request->decrypt_entire_rif.rif.digest) + sizeof(request->decrypt_entire_rif.rif.data));

		real_memset(response->decrypt_entire_rif.raw + 
				sizeof(request->decrypt_entire_rif.rif.digest) +
				sizeof(request->decrypt_entire_rif.rif.data), 
				0,
				sizeof(response->decrypt_entire_rif.raw) - 
				(sizeof(request->decrypt_entire_rif.rif.digest) + 
				sizeof(request->decrypt_entire_rif.rif.data)));

		payload->status = ret;
		ret = 0;
	}


err:
	return ret;
}

PAYLOAD_CODE int my_sceSblKeymgrSmCallfunc_npdrm_decrypt_isolated_rif(union keymgr_payload* payload) {

	
	union keymgr_request* request = (union keymgr_request*)sceSblDriverGpuVaToCpuVa(payload->mapped_buf, NULL);
	int ret;

	
	
	ret = real_sceSblKeymgrSmCallfunc(payload);


	
	if ((ret != 0 || payload->status != 0) && request) {

		if (request->decrypt_rif.type == 0x200) { 
			ret = npdrm_decrypt_debug_rif(request->decrypt_rif.type, request->decrypt_rif.data);
			payload->status = ret;
			ret = 0;
		}
	}

	return ret;
}



PAYLOAD_CODE int ccp_msg_populate_key(unsigned int key_handle, uint8_t* key, int reverse) {
	struct sbl_key_rbtree_entry* key_entry;
	uint8_t* in_key;
	int i;
	int status = 0;

	
	key_entry = sceSblKeymgrGetKey(key_handle);

	if (key_entry) {

		
		if (real_memcmp(key_entry->desc.pfs.seed, s_fake_key_seed, sizeof(key_entry->desc.pfs.seed)) == 0) {

			in_key = key_entry->desc.pfs.key;
			if (reverse) { 

				for (i = 0; i < 0x20; ++i)
					key[0x20 - i - 1] = in_key[i];
			} else {  

				real_memcpy(key, in_key, 0x20);
			}
			status = 1;
		}
	}

	return status;
}

PAYLOAD_CODE int ccp_msg_populate_key_if_needed(struct ccp_msg* msg) {

	unsigned int cmd = msg->op.common.cmd; 
	unsigned int type = CCP_OP(cmd);
	uint8_t* buf;
	int status = 0;

	if (!(cmd & CCP_USE_KEY_HANDLE))
		goto skip;

	buf = (uint8_t*)&msg->op;

	switch (type) {
		case CCP_OP_XTS:

			status = ccp_msg_populate_key(*(uint32_t*)(buf + 0x28), buf + 0x28, 1); 
			break;

		case CCP_OP_HMAC:

			status = ccp_msg_populate_key(*(uint32_t*)(buf + 0x40), buf + 0x40, 0); 
			break;

		default:

			goto skip;
	}

	if (status)
		msg->op.common.cmd &= ~CCP_USE_KEY_HANDLE;

skip:

	return status;
}

PAYLOAD_CODE int my_sceSblServiceCryptAsync_pfs_crypto(struct ccp_req* request) {
	struct ccp_msg* msg;
	int ret;


	TAILQ_FOREACH(msg, &request->msgs, next){
		
		ccp_msg_populate_key_if_needed(msg);

	}

	ret = real_sceSblServiceCryptAsync(request);

	return ret;
}

#include <assert.h>

#include "ps4.h"

const uint8_t payload_data_const[] =
{
#include "payload_data.inc"
};

uint64_t __readmsr(unsigned long __register)
{
  unsigned long __edx;
  unsigned long __eax;
  __asm__ ("rdmsr" : "=d"(__edx), "=a"(__eax) : "c"(__register));
  return (((uint64_t)__edx) << 32) | (uint64_t)__eax;
}

#define X86_CR0_WP (1 << 16)

static inline __attribute__((always_inline)) uint64_t readCr0(void)
{
  uint64_t cr0;
  __asm__ volatile ("movq %0, %%cr0" : "=r" (cr0) : : "memory");
  return cr0;
}

static inline __attribute__((always_inline)) void writeCr0(uint64_t cr0)
{
  __asm__ volatile("movq %%cr0, %0" : : "r" (cr0) : "memory");
}

struct auditinfo_addr {
    /*
    4    ai_auid;
    8    ai_mask;
    24    ai_termid;
    4    ai_asid;
    8    ai_flags;r
    */
    char useless[184];
};

struct ucred {
	uint32_t useless1;
	uint32_t cr_uid;     // effective user id
	uint32_t cr_ruid;    // real user id
 	uint32_t useless2;
    	uint32_t useless3;
    	uint32_t cr_rgid;    // real group id
    	uint32_t useless4;
    	void *useless5;
    	void *useless6;
    	void *cr_prison;     // jail(2)
    	void *useless7;
    	uint32_t useless8;
    	void *useless9[2];
    	void *useless10;
    	struct auditinfo_addr useless11;
    	uint32_t *cr_groups; // groups
    	uint32_t useless12;
};

struct filedesc {
	void *useless1[3];
    	void *fd_rdir;
    	void *fd_jdir;
};

struct proc {
    	char useless[64];
    	struct ucred *p_ucred;
    	struct filedesc *p_fd;
};

struct thread {
    	void *useless;
    	struct proc *td_proc;
};

struct payload_info
{
  uint8_t* buffer;
  size_t size;
};

struct syscall_install_payload_args
{
  void* syscall_handler;
  struct payload_info* payload_info;
};

struct real_info
{
  const size_t kernel_offset;
  const size_t payload_offset;
};

struct cave_info
{
  const size_t kernel_call_offset;
  const size_t kernel_ptr_offset;
  const size_t payload_offset;
};

struct disp_info
{
  const size_t call_offset;
  const size_t cave_offset;
};

struct payload_header
{
  uint64_t signature;
  size_t real_info_offset;
  size_t cave_info_offset;
  size_t disp_info_offset;
  size_t entrypoint_offset;
};

int find_process(const char* target)
{
  int pid;
  int mib[3] = {1, 14, 0};
  size_t size, count;
  char* data;
  char* proc;

  if (sysctl(mib, 3, NULL, &size, NULL, 0) < 0)
  {
	  
    return -1;
  }

  if (size == 0)
  {
    return -2;
  }

  data = (char*)malloc(size);
  if (data == NULL)
  {
    return -3;
  }

  if (sysctl(mib, 3, data, &size, NULL, 0) < 0)
  {
    free(data);
    return -4;
  }

  count = size / 0x448;
  proc = data;
  pid = -1;
  while (count != 0)
  {
    char* name = &proc[0x1BF];
	
    if (strncmp(name, target, strlen(target)) == 0)
    {
      pid = *(int*)(&proc[0x48]);
      break;
    }
    proc += 0x448;
    count--;
  }

  free(data);
  return pid;
}

int get_code_info(int pid, uint64_t* paddress, uint64_t* psize, uint64_t known_size)
{
  int mib[4] = {1, 14, 32, pid};
  size_t size, count;
  char* data;
  char* entry;

  if (sysctl(mib, 4, NULL, &size, NULL, 0) < 0)
  {
	  
    return -1;
  }

  if (size == 0)
  {
    return -2;
  }

  data = (char*)malloc(size);
  if (data == NULL)
  {
    return -3;
  }

  if (sysctl(mib, 4, data, &size, NULL, 0) < 0)
  {
    free(data);
    return -4;
  }

  int struct_size = *(int*)data;
  count = size / struct_size;
  entry = data;

  int found = 0;
  while (count != 0)
  {
    int type = *(int*)(&entry[0x4]);
    uint64_t start_addr = *(uint64_t*)(&entry[0x8]);
    uint64_t end_addr = *(uint64_t*)(&entry[0x10]);
    uint64_t code_size = end_addr - start_addr;
    uint32_t prot = *(uint32_t*)(&entry[0x38]);


    if (type == 255 && prot == 5 && code_size == known_size)
    {
      *paddress = start_addr;
      *psize = (end_addr - start_addr);
      found = 1;
      break;
    }

    entry += struct_size;
    count--;
  }

  free(data);
  return !found ? -5 : 0;
}

typedef struct _patch_info
{
  const char* name;
  uint32_t address;
  const char* data;
  uint32_t size;
}
patch_info;

int apply_patches(int pid, uint64_t known_size, patch_info* patches)
{
  uint64_t code_address, code_size;
  int result = get_code_info(pid, &code_address, &code_size, known_size);
  if (result < 0)
  {

    return -1;
  }

  char proc_path[64];
  sprintf(proc_path, "/mnt/proc/%d/mem", pid);

  int fd = open(proc_path, O_RDWR, 0);
  if (fd < 0)
  {

    return -2;
  }

  for (int i = 0; patches[i].name != NULL; i++)
  {
    lseek(fd, code_address + patches[i].address, SEEK_SET);
    result = write(fd, patches[i].data, patches[i].size);

  }

  close(fd);
  return 0;
}

patch_info shellcore_patches[32] =
{
  //{ "Enable Logging",                               0xF9664E, "\x00", 1 },
  //{ "Enable Logging",                               0xF9664E, "\x01", 1 },
/*
  { "Allow WebProcess LaunchApp #1",                0x28CE09, "\x90\xE9", 2 },
  { "Allow WebProcess LaunchApp #2",                0x28D02A, "\x90\xE9", 2 },
  { "Allow WebProcess LaunchApp #3",                0x28D0E0, "\xEB", 1 },

  { "Enable Development Mounts",                    0x276A83, "\xEB", 1 },
*/  
  { "debug pkg patch",                    0x11a0db, "\x31\xC0\x90\x90\x90", 5 },
  { "debug pkg patch",                    0x66ea3b, "\x31\xC0\x90\x90\x90", 5 },
  { "debug pkg patch",                    0x7f554b, "\x31\xC0\x90\x90\x90", 5 },
  { "debug pkg patch",                    0x11a107, "\x31\xC0\x90\x90\x90", 5 },
  { "debug pkg patch",                    0x66ea67, "\x31\xC0\x90\x90\x90", 5 },
  { "debug pkg patch",                    0x7f5577, "\x31\xC0\x90\x90\x90", 5 },
  { "debug pkg free string patch",        0xc980ee, "free\x00", 5 },

  { NULL, 0, NULL, 0 },
};

int mount_procfs()
{
  int result = mkdir("/mnt/proc", 0777);
  if (result < 0 && (*__error()) != 17)
  {

    return -1;
  }

  result = mount("procfs", "/mnt/proc", 0, NULL);
  if (result < 0)
  {

    return -2;
  }

  return 0;
}

void do_patch()
{
  int result;

  int shell_pid = find_process("SceShellCore");
  if (shell_pid < 0)
  {
    return;
  }
  

  result = mount_procfs();
  if (result)
  {
    return;
  }

  apply_patches(shell_pid, 0xF18000, shellcore_patches);
  
}

int syscall_install_payload(struct thread *td, struct syscall_install_payload_args* args)
{
  uint64_t cr0;
  typedef uint64_t vm_offset_t;
  typedef uint64_t vm_size_t;
  typedef void* vm_map_t;
  
  struct ucred* cred;
  struct filedesc* fd;

  fd = td->td_proc->p_fd;
  cred = td->td_proc->p_ucred;

  void* (*kernel_memcpy)(void* dst, const void* src, size_t len);
  void (*kernel_printf)(const char* fmt, ...);
  vm_offset_t (*kmem_alloc)(vm_map_t map, vm_size_t size);

  uint8_t* kernel_base = (uint8_t*)(__readmsr(0xC0000082) - 0x30EB30);
  uint8_t* kernel_ptr = (uint8_t*)kernel_base;
  void** got_prison0 =   (void**)&kernel_ptr[0xF26010];
  void** got_rootvnode = (void**)&kernel_ptr[0x206D250];

  *(void**)(&kernel_printf) = &kernel_base[0x347580];
  *(void**)(&kernel_memcpy) = &kernel_base[0x286CF0];
  *(void**)(&kmem_alloc) = &kernel_base[0x369500];
  vm_map_t kernel_map = *(void**)&kernel_base[0x1FE71B8];
  
	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;
  
	// uart enabler
	*(char *)(kernel_base + 0x186b0a0) = 0; // set the console disable console output bool

	// specters debug settings patchs

	*(char *)(kernel_base + 0x2001516) |= 0x14;
	*(char *)(kernel_base + 0x2001539) |= 1;
	*(char *)(kernel_base + 0x2001539) |= 2;
	*(char *)(kernel_base + 0x200153A) |= 1;
	*(char *)(kernel_base + 0x2001558) |= 1;	

	// Disable write protection

	cr0 = readCr0();
	writeCr0(cr0 & ~X86_CR0_WP);

	// debug menu full patches thanks to sealab

	*(uint32_t *)(kernel_base + 0x4CECB7) = 0;
	*(uint32_t *)(kernel_base + 0x4CFB9B) = 0;

	// Target ID Patches :)

	*(uint16_t *)(kernel_base + 0x1FE59E4) = 0x8101;
	*(uint16_t *)(kernel_base + 0X1FE5A2C) = 0x8101;
	*(uint16_t *)(kernel_base + 0x200151C) = 0x8101;


  if (!args->payload_info)
  {

    return -1;
  }

  uint8_t* payload_data = args->payload_info->buffer;
  size_t payload_size = args->payload_info->size;
  struct payload_header* payload_header = (struct payload_header*)payload_data;

  if (!payload_data ||
      payload_size < sizeof(payload_header) ||
      payload_header->signature != 0x5041594C4F414433ull)
  {

    return -2;
  }

  int desired_size = (payload_size + 0x3FFFull) & ~0x3FFFull; // align size

  // TODO(idc): clone kmem_alloc instead of patching directly
  cr0 = readCr0();
  writeCr0(cr0 & ~X86_CR0_WP);
  kernel_base[0x36958D] = 7;
  kernel_base[0x3695A5] = 7;
  writeCr0(cr0);

  uint8_t* payload_buffer = (uint8_t*)kmem_alloc(kernel_map, desired_size);
  if (!payload_buffer)
  {

    return -3;
  }

  // TODO(idc): clone kmem_alloc instead of patching directly
  cr0 = readCr0();
  writeCr0(cr0 & ~X86_CR0_WP);
  kernel_base[0x36958D] = 3;
  kernel_base[0x3695A5] = 3;
  writeCr0(cr0);

  

  kernel_memcpy((void*)payload_buffer, payload_data, payload_size);

  if (payload_header->real_info_offset != 0 &&
    payload_header->real_info_offset + sizeof(struct real_info) <= payload_size)
  {
    struct real_info* real_info =
      (struct real_info*)(&payload_data[payload_header->real_info_offset]);
    for (
      ; real_info->payload_offset != 0 && real_info->kernel_offset != 0
      ; ++real_info)
    {
      uint64_t* payload_target =
        (uint64_t*)(&payload_buffer[real_info->payload_offset]);
      void* kernel_target = &kernel_base[real_info->kernel_offset];
      *payload_target = (uint64_t)kernel_target;

       
    }
  }

  if (payload_header->cave_info_offset != 0 &&
    payload_header->cave_info_offset + sizeof(struct cave_info) <= payload_size)
  {
    struct cave_info* cave_info =
      (struct cave_info*)(&payload_data[payload_header->cave_info_offset]);
    for (
      ; cave_info->kernel_call_offset != 0 &&
        cave_info->kernel_ptr_offset != 0 &&
        cave_info->payload_offset != 0
      ; ++cave_info)
    {
      uint8_t* kernel_call_target = &kernel_base[cave_info->kernel_call_offset];
      uint8_t* kernel_ptr_target = &kernel_base[cave_info->kernel_ptr_offset];
      void* payload_target = &payload_buffer[cave_info->payload_offset];
      int32_t new_disp = (int32_t)(kernel_ptr_target - &kernel_call_target[6]);

      if (&kernel_call_target[6] == kernel_ptr_target)
      {

          

        if ((uint64_t)(kernel_ptr_target - &kernel_call_target[6]) != 0)
        {

        }
      }
      else
      {

       

        if ((uint64_t)(kernel_ptr_target - &kernel_call_target[6]) > UINT32_MAX)
        {

        }
      }

        

#pragma pack(push,1)
      struct
      {
        uint8_t op[2];
        int32_t disp;
      }
      jmp;
#pragma pack(pop)
      jmp.op[0] = 0xFF;
      jmp.op[1] = 0x25;
      jmp.disp = new_disp;
      cr0 = readCr0();
      writeCr0(cr0 & ~X86_CR0_WP);
      kernel_memcpy(kernel_call_target, &jmp, sizeof(jmp));
      kernel_memcpy(kernel_ptr_target, &payload_target, sizeof(void*));
      writeCr0(cr0);
    }
  }

  if (payload_header->disp_info_offset != 0 &&
    payload_header->disp_info_offset + sizeof(struct disp_info) <= payload_size)
  {
    struct disp_info* disp_info =
      (struct disp_info*)(&payload_data[payload_header->disp_info_offset]);
    for (
      ; disp_info->call_offset != 0 && disp_info->cave_offset != 0
      ; ++disp_info)
    {
      uint8_t* cave_target = &kernel_base[disp_info->cave_offset];
      uint8_t* call_target = &kernel_base[disp_info->call_offset];

      int32_t new_disp = (int32_t)(cave_target - &call_target[5]);

        

      cr0 = readCr0();
      writeCr0(cr0 & ~X86_CR0_WP);
      *((int32_t*)&call_target[1]) = new_disp;
      writeCr0(cr0);
    }
  }

  if (payload_header->entrypoint_offset != 0 &&
    payload_header->entrypoint_offset < payload_size)
  {

    void (*payload_entrypoint)();
    *((void**)&payload_entrypoint) =
      (void*)(&payload_buffer[payload_header->entrypoint_offset]);
    payload_entrypoint();
  }

  return 0;
}

void do_patch();

int _main(void)
{
  uint8_t* payload_data = (uint8_t*)(&payload_data_const[0]);
  size_t payload_size = sizeof(payload_data_const);
  
  

  initKernel();
  
  
  struct payload_info payload_info;
  payload_info.buffer = payload_data;
  payload_info.size = payload_size;
  errno = 0;
  int result = kexec(&syscall_install_payload, &payload_info);
  do_patch();
  return !result ? 0 : errno;
}

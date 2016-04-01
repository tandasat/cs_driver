#include <ntddk.h>
#include "../myinttypes.h"
#include <capstone.h>

// 'conversion' : from function pointer 'type1' to data pointer 'type2'
#pragma warning(disable : 4054)

EXTERN_C int cs_snprintf(char* buffer, size_t size, const char* fmt, ...);
EXTERN_C void cs_driver_regression_test();
static void cs_driver_tests();
static NTSTATUS cs_driver_hello();
static void cs_driver_vsnprintf_test();
int __cdecl printf(const char* format, ...);

// User-defined memory allocation functions
void __cdecl csdrv_free(void* ptr);
void* __cdecl csdrv_malloc(size_t size);
void* __cdecl csdrv_calloc(size_t n, size_t size);
void* __cdecl csdrv_realloc(void* ptr, size_t size);
int __cdecl csdrv_vsnprintf(char* buffer, size_t count, const char* format,
                            va_list argptr);

// Driver entry point
EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,
                              PUNICODE_STRING RegistryPath) {
  printf("Entering DriverEntry()\n");

  KdBreakPoint();
  cs_driver_tests();

  printf("Leaving DriverEntry()\n");
  return STATUS_CANCELLED;
}

// Exercises all tests
static void cs_driver_tests() {
  cs_driver_hello();
  cs_driver_vsnprintf_test();
  cs_driver_regression_test();
}

// Hello, Capstone!
static NTSTATUS cs_driver_hello() {
  csh handle;
  cs_insn* insn;
  size_t count;
  cs_opt_mem setup;
  KFLOATING_SAVE float_save;
  NTSTATUS status;

  // Any of Capstone APIs cannot be called at IRQL higher than DISPATCH_LEVEL
  // since our malloc implementation using ExAllocatePoolWithTag() is able to
  // allocate memory only up to the DISPATCH_LEVEL level.
  NT_ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);

  // On a 32bit driver, KeSaveFloatingPointState() is required before using any
  // Capstone function because they can access to the MMX/x87 registers and
  // 32bit Windows requires drivers to use KeSaveFloatingPointState() before and
  // KeRestoreFloatingPointState() after accesing to them. See "Using Floating
  // Point or MMX in a WDM Driver" on MSDN for more details.
  status = KeSaveFloatingPointState(&float_save);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  // Setup our own dynamic memory functions with cs_option().
  setup.malloc = csdrv_malloc;
  setup.calloc = csdrv_calloc;
  setup.realloc = csdrv_realloc;
  setup.free = csdrv_free;
  setup.vsnprintf = csdrv_vsnprintf;
  if (cs_option(0, CS_OPT_MEM, (size_t)&setup) != CS_ERR_OK) {
    // Failed to initialize our user-defined dynamic mem functions.
    // Quit is the only choice here :-(
    return STATUS_UNSUCCESSFUL;
  }

  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
    return STATUS_UNSUCCESSFUL;
  }

  count = cs_disasm(handle, (uint8_t*)&cs_driver_hello, 0x100,
                    (uint64_t)&cs_driver_hello, 0, &insn);
  if (count > 0) {
    printf("cs_driver!DriverEntry:\n");
    for (size_t j = 0; j < count; j++) {
      printf("0x%llx:\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
             insn[j].op_str);
    }
    cs_free(insn, count);
  }
  cs_close(&handle);

  // Restores the nonvolatile floating-point context.
  KeRestoreFloatingPointState(&float_save);
  return status;
}

// Functional test for cs_driver_vsnprintf()
static void cs_driver_vsnprintf_test() {
  char buf[10];
  NT_VERIFY(cs_snprintf(buf, sizeof(buf), "%s", "") == 0 &&
            strcmp(buf, "") == 0);
  NT_VERIFY(cs_snprintf(buf, sizeof(buf), "%s", "0") == 1 &&
            strcmp(buf, "0") == 0);
  NT_VERIFY(cs_snprintf(buf, sizeof(buf), "%s", "012345678") == 9 &&
            strcmp(buf, "012345678") == 0);
  NT_VERIFY(cs_snprintf(buf, sizeof(buf), "%s", "0123456789") == 10 &&
            strcmp(buf, "012345678") == 0);
  NT_VERIFY(cs_snprintf(buf, sizeof(buf), "%s", "01234567890") == 11 &&
            strcmp(buf, "012345678") == 0);
  NT_VERIFY(cs_snprintf(buf, sizeof(buf), "%s", "0123456789001234567890") ==
                22 &&
            strcmp(buf, "012345678") == 0);
  NT_VERIFY(cs_snprintf(buf, sizeof(buf), "%s", NULL) == 6 &&
            strcmp(buf, "(null)") == 0);
}

// printf() is required to exercise regression test etc. It can be omitted if
// those are not used in the project. This functions mimics printf() but does
// not return the same value as printf() would do.
int __cdecl printf(const char* format, ...) {
  NTSTATUS status;
  va_list args;

  va_start(args, format);
  status = vDbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, format, args);
  va_end(args);
  return NT_SUCCESS(status);
}

////////////////////////////////////////////////////////////////////////////////
//
// Defines required functions and internal stuff for them

// A pool tag for memory allocation
#ifndef CS_DRIVER_POOL_TAG
#define CS_DRIVER_POOL_TAG 'rdsC'
#endif

// A structure to implement realloc()
typedef struct _CS_DRIVER_MEMBLOCK {
  size_t size;   // A number of bytes allocated
  char data[1];  // An address returned to a caller
} CS_DRIVER_MEMBLOCK;
C_ASSERT(sizeof(CS_DRIVER_MEMBLOCK) == sizeof(void*) * 2);

// free()
void __cdecl csdrv_free(void* ptr) {
  if (ptr) {
    ExFreePoolWithTag(CONTAINING_RECORD(ptr, CS_DRIVER_MEMBLOCK, data),
                      CS_DRIVER_POOL_TAG);
  }
}

// malloc()
void* __cdecl csdrv_malloc(size_t size) {
  // Disallow zero length allocation because they waste pool header space and,
  // in many cases, indicate a potential validation issue in the calling code.
  NT_ASSERT(size);

  CS_DRIVER_MEMBLOCK* block = (CS_DRIVER_MEMBLOCK*)ExAllocatePoolWithTag(
      NonPagedPoolNx, size + sizeof(CS_DRIVER_MEMBLOCK), CS_DRIVER_POOL_TAG);
  if (!block) {
    return NULL;
  }
  block->size = size;
  return block->data;
}

// calloc()
void* __cdecl csdrv_calloc(size_t n, size_t size) {
  size_t total = n * size;

  void* new_ptr = csdrv_malloc(total);
  if (!new_ptr) {
    return NULL;
  }

  return memset(new_ptr, 0, total);
}

// realloc()
void* __cdecl csdrv_realloc(void* ptr, size_t size) {
  if (!ptr) {
    return csdrv_malloc(size);
  }

  void* new_ptr = csdrv_malloc(size);
  if (!new_ptr) {
    return NULL;
  }

  memcpy(new_ptr, ptr,
         min(CONTAINING_RECORD(ptr, CS_DRIVER_MEMBLOCK, data)->size, size));
  csdrv_free(ptr);
  return new_ptr;
}

// vsnprintf(). _vsnprintf() is avaialable for drivers, but it differs from
// vsnprintf() in a return value and when a null-terminater is set.
// csdrv_vsnprintf() takes care of those differences.
int __cdecl csdrv_vsnprintf(char* buffer, size_t count, const char* format,
                            va_list argptr) {
  int result = _vsnprintf(buffer, count, format, argptr);

  // _vsnprintf() returns -1 when a string is truncated, and returns "count"
  // when an entire string is stored but without '\0' at the end of "buffer".
  // In both cases, null-terminater needs to be added manually.
  if (result == -1 || (size_t)result == count) {
    buffer[count - 1] = '\0';
  }
  if (result == -1) {
    // In case when -1 is returned, the function has to get and return a number
    // of characters that would have been written. This attempts so by re-tring
    // the same conversion with temp buffer that is most likely big enough to
    // complete formatting and get a number of characters that would have been
    // written.
    char tmp[1024];
    result = _vsnprintf(tmp, RTL_NUMBER_OF(tmp), format, argptr);
    NT_ASSERT(result != -1);
  }

  return result;
}

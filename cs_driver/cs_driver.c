#include <ntddk.h>
#include "driver_mm.h"

// 'conversion' : from function pointer 'type1' to data pointer 'type2'
#pragma warning(disable : 4054)

EXTERN_C int cs_snprintf(char *buffer, size_t size, const char *fmt, ...);
EXTERN_C void cs_driver_regression_test();

DRIVER_INITIALIZE DriverEntry;
static void cs_driver_tests();
static NTSTATUS cs_driver_hello();
static void cs_driver_vsnprintf_test();


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
  cs_insn *insn;
  size_t count;
  KFLOATING_SAVE float_save;
  NTSTATUS status = STATUS_UNSUCCESSFUL;

  // Any of Capstone APIs cannot be called at IRQL higher than DISPATCH_LEVEL
  // since our malloc implementation using ExAllocatePoolWithTag() is able to
  // allocate memory only up to the DISPATCH_LEVEL level.
  NT_ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);

  // Setup our own dynamic memory functions with cs_driver_init().
  if (cs_driver_mm_init() != CS_ERR_OK) {
    // Failed to initialize our user-defined dynamic mem functions.
    // Quit is the only choice here :-(
    return STATUS_UNSUCCESSFUL;
  }

  // On a 32bit driver, KeSaveFloatingPointState() is required before using any
  // Capstone function because Capstone can access to the MMX/x87 registers and
  // 32bit Windows requires drivers to use KeSaveFloatingPointState() before and
  // KeRestoreFloatingPointState() after accesing to them. See "Using Floating
  // Point or MMX in a WDM Driver" on MSDN for more details.
  status = KeSaveFloatingPointState(&float_save);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  if (cs_open(CS_ARCH_X86, (sizeof(void *) == 4) ? CS_MODE_32 : CS_MODE_64,
              &handle) != CS_ERR_OK) {
    goto exit;
  }

  count = cs_disasm(handle, (uint8_t *)&cs_driver_hello, 0x100,
                    (uint64_t)&cs_driver_hello, 0, &insn);
  if (count > 0) {
    printf("cs_driver!cs_driver_hello:\n");
    for (size_t j = 0; j < count; j++) {
      printf("0x%p\t%s\t\t%s\n", (void *)(uintptr_t)insn[j].address,
             insn[j].mnemonic, insn[j].op_str);
    }
    cs_free(insn, count);
  }
  cs_close(&handle);

exit:;
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
_Use_decl_annotations_ int __cdecl printf(const char *_Format, ...) {
  NTSTATUS status;
  va_list args;

  va_start(args, _Format);
  status = vDbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, _Format, args);
  va_end(args);
  return NT_SUCCESS(status);
}

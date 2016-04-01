#include <ntddk.h>
#include "../myinttypes.h"
#include <capstone.h>

#pragma warning(push)
#pragma warning(disable : 4005)  // 'identifier' : macro redefinition
#pragma warning(disable : 4007)  // 'main': must be '__cdecl'

// "Import" existing tests into this file. All code is encaptured into unique
// namespace so that the same name does not conflict. Beware that those code
// is going to be compiled as C++ source file and not C files because this file
// is C++.

namespace unnamed {
#include "../tests/test.c"
}  // namespace unnamed

namespace arm {
#include "../tests/test_arm.c"
}  // namespace arm

namespace arm64 {
#include "../tests/test_arm64.c"
}  // namespace arm64

namespace detail {
#include "../tests/test_detail.c"
}  // namespace detail

namespace iter {
#include "../tests/test_iter.c"
}  // namespace iter

namespace mips {
#include "../tests/test_mips.c"
}  // namespace mips

namespace ppc {
#include "../tests/test_ppc.c"
}  // namespace ppc

namespace skipdata {
#include "../tests/test_skipdata.c"
}  // namespace skipdata

namespace sparc {
#include "../tests/test_sparc.c"
}  // namespace sparc

namespace systemz {
#include "../tests/test_systemz.c"
}  // namespace systemz

namespace x86 {
#include "../tests/test_x86.c"
}  // namespace x86

namespace xcore {
#include "../tests/test_xcore.c"
}  // namespace xcore

#pragma warning(pop)

// Exercises all existing regression tests
EXTERN_C void cs_driver_regression_test() {
  KFLOATING_SAVE float_save;
  NTSTATUS status = KeSaveFloatingPointState(&float_save);
  NT_VERIFY(NT_SUCCESS(status));

  unnamed::test();
  arm::test();
  arm64::test();
  detail::test();
  iter::test();
  mips::test();
  ppc::test();
  skipdata::test();    // FIXME: a bug check; likely to be buffer overflow
  sparc::test();
  systemz::test();
  x86::test();
  xcore::test();

  KeRestoreFloatingPointState(&float_save);
}

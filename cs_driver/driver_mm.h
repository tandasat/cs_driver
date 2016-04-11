#ifndef CAPSTONE_DRIVER_MM_H_
#define CAPSTONE_DRIVER_MM_H_

#include <capstone.h>

/*
 Initializes Capstone dynamic memory management for Windows drivers

 @return: CS_ERR_OK on success, or other value on failure.
 Refer to cs_err enum for detailed error.

 NOTE: cs_driver_init() can be called at IRQL <= DISPATCH_LEVEL.
*/
cs_err CAPSTONE_API cs_driver_mm_init();

#endif  // CAPSTONE_DRIVER_MM_H_

# cs_driver
cs_driver is a sample project for using Capstone in a driver with Visual Studio 
2015. This project aims to provide a minimal, clean procedure to compile and link
the Capstone disassembly framework in your Windows driver project. For more 
information about Capstone, see its project page.
- http://www.capstone-engine.org/


## Sample Output
![sample](/image/sample.png)


## Motivation
Capstone is a reliable, supported disassemler developed by an active community. 
It is designed for multi-platform support in first place, and supports usage by
OS kernel code. In fact, one of Capstone documents refers to a sample project
for learning how to embed Capstone into an Windows kernel driver.
- https://github.com/aquynh/KernelProject

However, this project lacks information about how to actually configure your 
driver project and compile Capstone. Also, it refers to a two-year-old branch 
and cannot be compiled with Visual Studio 2015 with described instructions. Not
only that, the repository consists of 50000+, 1.3GB of files in order to 
demonstrate make use of C++ Standard Template Library and Boost Libraries from 
drivers while those libraries are neither relevant to Capstone nor always 
demanded. For those reasons, the sample project is not overly helpful for those
who want to learn how to use Capstone in Windows drivers.

cs_driver, on the other hand, explains how to configure your and Capstone project
and includes only minimum amount of code with detailed comments for learning a 
procedure to apply Capstone to your project quickly. Also, cs_driver is able to
run all existing Capstone test code so that a developer can confirm that Capstone
on the kernel mode is properly functioning.


## How to use Capstone from your WDK project
In general, what you need to embed Capstone to a driver are: capstone.lib 
complied from the modified source code (contents of modification are explained 
later), ntstrsafe.lib to resolve __fltused, and cs_driver.h and some runtime 
initialization and safe guard code explained in cs_driver.c. In order to make 
use of Capstone from a new driver project, follow the below steps. 
 
1. Add a new project "Kernel Mode Driver, Empty (KMDF)" to the cs_driver solution
   ![new_project](/image/new_project.png)
  
2. Add a source file to the new project

   ![source_file](/image/source_file.png)

3. Open a project properties of the cs_driver project and set Configuration to
   "All Configurations" and Platform to "All Platforms"
    - C/C++ > General > Additional Include Directories
      - $(SolutionDir)capstone\include
    - Linker > Input > Additional Dependencies 
      - $(OutDir)..\$(ConfigurationName)_WDK\capstone.lib;ntstrsafe.lib
   ![properties](/image/properties.png)

4. Set dependency as below from [Project] > [Project Dependencies]
   ![dependency](/image/dependency.png)

5. Include cs_driver.h from the source file. It can be done by referencing existing
   one or creating a copy under the project

6. In source code, call KeSaveFloatingPointState() before using any of Capstone APIs
   on a 32bit system, and also call cs_driver_init() in order to setup dynamic 
   memory management of Capstone. For more details, refer to comments in cs_driver.c

After this, you are free to use Capstone API from a driver.

Those steps are just example and not a hard-rule. Developpers are also free to 
have separate solutions for Capstone and your driver as long as the driver can
link capstone.lib and run equivalent code to what cs_driver.h provides.

    
## How the cloned Capstone was modified for WDK projects
As of time cs_driver was created, source code of Capstone needs to be modified 
in order to compile, link and run all tests as part of a driver successfully.
This sections explains what changes were made and why as a reference. Beware 
that you not need apply those changes when Capstone in this repository is used. 

#### Added CAPSTONE_API to all Capstone APIs
- https://github.com/tandasat/capstone/commit/760940fdceb50a09f1a8ebee5dc807b6039f144e
- https://github.com/tandasat/capstone/commit/6dad56669b1e2fb2f09484adfb5c494285204d18

This change is to specifie calling convention for Calstone APIs. 

The default setting of calling convention is different between the capstone_static
project and a WDK project. capstone_static compiles code with __cdecl calling 
converntion, while a WDK project compiles code as __stdcall, leading to link or
runtime errors 

#### Replacesd snprintf() with cs_snprintf()
- https://github.com/tandasat/capstone/commit/aba6117c6c6723dc446797d2b889f4b989cd512a
- https://github.com/tandasat/capstone/commit/6bf747e5a59a0f785117198cc04c93391decae43
- https://github.com/tandasat/capstone/commit/760940fdceb50a09f1a8ebee5dc807b6039f144e

This change is to avoid making use of snprintf(), which is not available for 
drivers. 

**This change could lead to a runtime issue when user-defined vsnprintf() does
not return the same value as what genuine vsnprintf() does.** In order to 
assess this impact, a developer is able to use the cs_driver_vsnprintf_test() 
function to test if their vsnprintf() conforms behaviour of that of the C/C++ 
standard.

#### Avoided compile errors with regard to string literals
- https://github.com/tandasat/capstone/commit/6bf747e5a59a0f785117198cc04c93391decae43

This change is to avoid that strings comprise of PRI* macros is being threated
as string literals and cause compile errors when compiled as C++11 and later.
Details of this issue is explained under the "String literals followed by macros"
section in the "Breaking Changes in Visual C++ 2015" page on MSDN.
- https://msdn.microsoft.com/en-us/library/bb531344.aspx#BK_compiler

This change was made because cs_driver_test.cpp attemped to compile all test
code as C++ code for ease of excersising all regression test. 

#### Added and made use of CS_OPT_NONE and CS_OPT_OFF 
- https://github.com/tandasat/capstone/commit/6bf747e5a59a0f785117198cc04c93391decae43
- https://github.com/tandasat/capstone/commit/760940fdceb50a09f1a8ebee5dc807b6039f144e

This change is to avoid compile errors with regard to conversion errors from 
integer to enum (cs_opt_type and cs_opt_value) when test_skipdata.c is compiled
as C++ source as part of cs_driver_test.cpp.

#### Renamed a variable "i" to "ins" to avoid a warning
- https://github.com/tandasat/capstone/commit/6bf747e5a59a0f785117198cc04c93391decae43

This change is to avoid compiler warning C4456 with regard to shadowed variables
and required because warnings are treated as errors in a WDK project by default.

#### Added *_WDK configurations in the capstone_static project
- https://github.com/tandasat/capstone/commit/8ae679e0dee211a7ea0cbebb50a978e63414877a

This change is to add new build configurations for drivers. 

First of all, the project file was upgraded for Visual Studio 2015. Then, *_WDK 
configurations were made from existing configurations and following changes were
made to the *_WDK configurations:
 - C/C++ > General > Debug Information Format
   - OLD: Program Database for Edit And Continue (/ZI)
   - NEW: Program Database (/Zi)
 - C/C++ > Preprocessor > Preprocessor Definitions
   - NEW: Deleted CAPSTONE_USE_SYS_DYN_MEM
 - C/C++ > Code Generation > Basic Runtime Checks
   - OLD: Both (/RTC1, equiv. to /RTCsu) (/RTC1)
   - NEW: Default
 - C/C++ > Code Generation > Runtime Library
   - OLD: Multi-threaded Debug (/MTd)
   - NEW: (empty)
 - C/C++ > All Options > Additional Options
   - OLD: (empty)
   - NEW: /kernel

#### Replaced stdint.h with myinttypes.h
- https://github.com/tandasat/capstone/commit/f04254a87c5fed7abddc3aa607ec8bc7f67bfc6a

This change is to avoid compile errors due to make use of stdint.h, which is not 
available for drivers. 

#### Added _KERNEL_MODE support
- https://github.com/tandasat/capstone/commit/52959a1bb8eca4d9162396cb4ea3cdfbf31a2b98
- https://github.com/tandasat/capstone/commit/743bf536e0c14b4934c7d92cd5c749eef1baf258

This change is to let myinttype.h and platform.h use the non-stanadard headers 
(stdint.h and stdbool.h), which are not available for drivers.

Note that _KERNEL_MODE is defined when a program is compiled with the /kernel 
option as explained in the "/kernel (Create Kernel Mode Binary)" page on MSDN.
- https://msdn.microsoft.com/en-us/library/jj620896.aspx?f=255&MSPPError=-2147217396


## Supported Platforms
- x86 and x64 Windows 7, 8.1 and 10


## License
This software is released under the MIT License, see LICENSE.

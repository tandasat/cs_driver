cs_driver
==========

cs_driver is a sample project for using Capstone in a driver with Visual Studio 
2015. This project aims to provide a minimal, clean procedure to compile and link
the Capstone disassembly framework in your Windows driver project. For more 
information about Capstone, see its project page.
- http://www.capstone-engine.org/


Sample Output
---------------
![sample](/image/sample.png)


Motivation
-----------
Capstone is a reliable, supported disassemler developed by an active community. 
It is designed for multi-platform support for in first place, and supports 
usage by OS kernel code. In fact, one of Capstone documents refers to a sample
project for learning how to embed Capstone into an Windows kernel driver.
- https://github.com/aquynh/KernelProject

However, this project lacks information about how to actually configure your 
driver project and compile Capstone. Also, it refers to a two-year-old branch 
and cannot be compiled with Visual Studio 2015 with described instructions. Not
only that, the repository consists of 50000+, 1.3GB of files in order to 
demonstrate make use of C++ Standard Template Library and Boost Libraries from 
drivers while those libraries are neither relevant to Capstone nor always 
demanded. For those reasons, the sample project is not overly helpful for those
who want to learn how to use Capstone in Windows drivers.

cs_driver, on the other hand, explains how to configure yours and Capstone project
and includes only minimum amout of code with detailed comments for learning a 
procedure to apply Capstone to your project quickly. Also, cs_driver is able to
run all existing Capstone test code so that a developer can confirm that Capstone
in the kernel mode is properly functioning.


How to use Capstone from your WDK project
------------------------------------------
(TBD)

- Create a new project
- Delete all default .cpp and .h files
- Ceate capstore as a submodule under the cs_driver folder

    user@DESKTOP-LQSEFPE MINGW64 ~/Desktop/csd/cs_driver (master)
    $ git submodule add https://github.com/tandasat/capstone.git

- Add capstone_static.vcxproj located under the below folder to the solution 

    C:\Users\user\Desktop\csd\cs_driver\capstone\msvc\capstone_static


- Add cs_driver.c and cs_driver_test.cpp to the cs_driver project


    C:\Users\user\Desktop\csd\cs_driver\cs_driver

- Set dependency as below from [Project] > [Project Dependencies] 

- Open a project properties of the cs_driver project and set Configuration to All Configurations and Platform to All Platforms.

    C/C++ > General > Additional Include Directories
    $(SolutionDir)capstone\include;

    Linker > Input > Additional Dependencies 
    $(OutDir)capstone.lib;ntstrsafe.lib;
    
    Wpp Tracing > General > Run Wpp Tracing
    <inherit from parent or project defaults>
    


How the cloned Capstone was modified for WDK projects
------------------------------------------------------
(TBD)


Caution
--------
*Do not apply this procedure to your production project.* 

Currently, one of the skipdata tests called "Arm - Skip data with callback" 
causes a bug check on 32bit systems. While a reason is unknown and being 
investigated, it seems to be a buffer overflow issue. While I have not seen 
any problems by using x86_64 related features from a driver, the procedure 
explained in this page should not be applied to production code until a 
cause and a scope of this issue are identified. 


Supported Platforms
--------------------
- x86 and x64 Windows 7, 8.1 and 10


License
--------
This software is released under the MIT License, see LICENSE.

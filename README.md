cs_driver
==========

cs_driver is a sample project for using Capstone in a driver with Visual Studio 
2015. This project aims to provide minimal, clean procedure to compile and link
the Capstone disassembly framework in your Windows driver project. For more 
information of Capstone, see its project page.
- http://www.capstone-engine.org/


Sample Output
---------------
![sample](/imgage/sample.png)


Motivation
-----------
Capstone is a reliable, supported disassemler supported by an active development
community. It is designed for multi-platform support for the first place, and 
supports usage by OS kernel code. In fact, one of Capstone documents refers to a 
sample project for how to embed Capstone into Windows kernel driver.
- https://github.com/aquynh/KernelProject

However, this project cannot be compiled with Visual Studio 2015 with described 
instructions and lacks information about how to actually configure your driver
project and compile Capstone. Also, the project consists of files (MB) in order
to demonstrate make use of C++ Standard Template Library and Boost Libraries
from drivers while those libraries are unnecessary for using Capstone. For those
reasons, the sample project is not overly helpful, and a simpler project needs 
to be created.


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


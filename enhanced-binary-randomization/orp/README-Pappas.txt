         ----==== Orp: in-place binary code randomizer ====----

Orp is an in-place binary code randomizer for the x86 architecture. For more
information about it you can read the paper in 'doc/smashing.pdf' which was
published in the Proceedings of the 33rd IEEE Symposium on Security & Privacy
(2012). Here you will find information on how to install and use it.

If you have any questions or you want to report bugs or feature requests, please
sent us an email at vpappas@cs.columbia.edu


- Prerequisites
  
  1. Compiler
  Orp contains a modified version of the Libdasm library that you need to
  compile. Install the full .NET Framework 4 from:
  http://www.microsoft.com/en-us/download/details.aspx?id=17851
  and then install the Microsoft Windows SDK 7.1 from:
  http://www.microsoft.com/en-us/download/details.aspx?id=8279
  (make sure you choose the option "Visual C++ Compilers").

  2. Python
  Install the 32-bit version of Python 2.7 from:
  http://www.python.org/ftp/python/2.7.3/python-2.7.3.msi
  It is also possible to use the 64-bit version, but some steps bellow may be
  slightly different. If you already have Python installed from Cygwin, you may
  have some issues when running the examples later.

  3. Libdasm (modified)
  Start a Windows SDK command prompt and change directory to
  'orp-X/libdasm-1.5_orp/pydasm'. Then change the build environment to x86
  (skip if 64-bit Python is used):
   > SetEnv.cmd /x86
  Configure Python distutils to use Windows SDK instead of Visual Studio:
   > set DISTUTILS_USE_SDK=1
   > set MSSdk=1
  Compile and install the Python extension of libdasm:
   > python.exe setup.py build
   > python.exe setup.py install
  If python.exe is not found, either add it to PATH or use the absolute path.

  4. Install the Pygraph and PEfile Python libraries
  Download PEfile from:
  http://pefile.googlecode.com/files/pefile-1.2.10-114.zip
  Unzip, change directory to 'pefile-1.2.10-114' and install by executing:
   > python setup.py install
  Download Pygraph from:
  http://python-graph.googlecode.com/files/python-graph-1.8.1.zip
  Unzip, change directory to python-graph/core and install by executing:
   > python setup.py install
  Then, change directory to 'python-graph/dot' and install by executing:
   > python setup.py install


- Test suite

  You can verify the installation by running the test suite located in the orp-X
  directory:
   > python test.py
  If everything is in place, you should see no errors. Otherwise, check that all
  the prerequisites are properly installed and try again. 


- Example usage

  There are two DLLs in the test directory for which the control flow graph
  (CFG) is also included. So, you can use Orp with them even if you don't have
  IDA Pro. Orp has three modes of operation:

  1. Randomize a given binary
  Takes as input a binary (DLL or executable) and generates a randomized
  version. You can test that using the md5.dll:
   > python orp.py -r test\md5\md5.dll
  The randomized DLL will be located at test\md5\md5_patched-rand.dll and you
  can test it by running:
   > test\md5\main.exe test\md5\md5_patched-rand.dll

  2. Coverage evaluation
  Extracts all the gadgets (instruction sequences that end in an indirect
  branch; at most five instructions in length) and then applies all the
  different randomization techniques. Example:
   > python orp.py -c test\md5\md5.dll
  After it finishes, a detailed report is shown.

  3. Exploit evaluation
  Calculates the number of different randomized versions of the input DLL that
  break an exploit payload. The payload is given as a list of addresses in a
  Python file, having the same name as the input DLL with the addition of the
  '.payload.py' suffix. Currently, there is no exploit payloads for the included
  DLLs, so there is no easy way to test it if you don't have IDA Pro installed.
  

- With IDA Pro

  First, make sure that the IDA Pro directory where its main executables reside
  is included in PATH. Try to execute idaq.exe from a command prompt to test it.

  Also, in case IDA Pro uses a different python version than the one previously
  installed, you will need to install all the prerequisites for that version
  too. You choose which Python version to use from the command prompt using
  absolute paths.

  Orp can be used with IDA Pro in two ways:

  1. Analyze files other than the ones included in the test directory. To do so,
  you have to extract the control-flow graph:
   > python orp.py -d path/to/dll/or/exe
  This uses IDA Pro internally. The CFG will be dumped in a file with the same
  name as the input, plus the '.dmp.bz2' suffix. Then, you can run any of the
  above modes of execution: randomization, coverage, or exploit evaluation.

  2. Most of Orp's scripts can be used directly as standalone IDA Python scripts
  from the main window of IDA Pro. These are:

  gadget.py   Find gadgets between cursor position and end of function
  equiv.py    Find equivalent instructions between cursor and end of function
  preserv.py  Find preserved registers in the function under the cursor
  reorder.py  Reorder the instructions in the basic block under the cursor
  swap.py     Find swappable registers in the function under the cursor
  
  Some of them require the cursor to be on the beginning of a function. For more
  information check their main functions at the bottom of each script.

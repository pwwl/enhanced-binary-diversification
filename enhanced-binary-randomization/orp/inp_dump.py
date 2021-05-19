# Copyright (c) 2012, Vasilis Pappas <vpappas@cs.columbia.edu>
# This file is part of Orp http://nsl.cs.columbia.edu/projects/orp

# Additionally modified by Mahmood Sharif <mahmoods@alumni.cmu.edu>
# Alternate contact is Keane Lucas <keanelucas@cmu.edu>

import cPickle as pickle
import pefile  
import util

__all__ = ["load_data", "get_code_heads", "code_search",
"byte_at", "bytes_at", "seg_start", "seg_end", "get_func_of"]

# code heads will be initialized when load_data is called, hopefully before
# code_heads is accessed 
code_heads = set()

# the pe file instance
pe = None

# keep a reference to the loaded functions (needed for get_func_of)
functions = None

# keep the filename of the currently processed file (for patch)
filename = ""

def clear():
  """try to free memory when data no longer needed"""
  global code_heads, pe, functions, filename
  if pe is not None:
    pe.write()
    pe.close()
  pe = None
  code_heads = set()
  functions = None
  filename = ""

def get_functions(input_file):
  """Alias for load_data bellow."""

  return load_data(input_file)


def load_data(input_file):
  """Loads the data previously dumped using 'inp_ida.dump_data'."""

  global code_heads, pe, functions, filename

  dump_in = util.open_dump(input_file, "rb")
  functions = dict()

  code_heads = pickle.load(dump_in)

  while True:
    f = pickle.load(dump_in)

    if f == None:
      break

    functions[f.addr] = f

  dump_in.close()

  # open the original inpu file using pefile
  filename = input_file
  pe = pefile.PE(filename)

  return functions


def code_search(ea, val):
  offset = pe.get_offset_from_rva(ea-pe.OPTIONAL_HEADER.ImageBase)
  index = pe.__data__.find(chr(int(val, 16)), offset)

  if index != -1:
    return pe.get_rva_from_offset(index) + pe.OPTIONAL_HEADER.ImageBase
  else:
    return None


def byte_at(ea):
  """Returns the byte at the given address."""

  return ord(pe.get_data(ea-pe.OPTIONAL_HEADER.ImageBase, 1))


def bytes_at(ea, num):
  """Returns num of bytes at the given address."""

  return pe.get_data(ea-pe.OPTIONAL_HEADER.ImageBase, num)


def seg_start(ea):
  """Returns the start of the segment that ea belongs in."""

  section = pe.get_section_by_rva(ea-pe.OPTIONAL_HEADER.ImageBase)

  return section.VirtualAddress


def seg_end(ea):
  """Returns the end of the segment that ea belongs in."""

  section = pe.get_section_by_rva(ea-pe.OPTIONAL_HEADER.ImageBase)

  return section.VirtualAddress + section.Misc_VirtualSize


def get_func_of(ea):
  """Return the function that this address belongs to, if any."""

  for f in functions.itervalues():

    if f.level == -1: # imported ..
       continue

    for i in f.instrs:
      if i.addr <= ea < i.addr+len(i.bytes):
         return f.addr

  return None


def get_code_heads():
  """Returns the set with the code heads extracted from the dump file"""

  return code_heads


def get_input_file_path():
  """Return the name of the currently processed file."""

  return filename


def code_segments_iter():
  """Iterates over the possible code sections within an input binary."""

  base = pe.OPTIONAL_HEADER.ImageBase

  for sec in pe.sections:
    if sec.IMAGE_SCN_MEM_EXECUTE:
      start = base + sec.VirtualAddress
      end = start + sec.Misc_VirtualSize
      yield start, end, sec.Name

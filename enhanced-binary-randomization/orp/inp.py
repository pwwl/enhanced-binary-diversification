# Copyright (c) 2012, Vasilis Pappas <vpappas@cs.columbia.edu>
# This file is part of Orp http://nsl.cs.columbia.edu/projects/orp

# Additionally modified by Mahmood Sharif <mahmoods@alumni.cmu.edu>
# Alternate contact is Keane Lucas <keanelucas@cmu.edu>

import shutil
import os
import stat
import disp

try:
  import inp_ida
  for f in inp_ida.__dict__.iterkeys():
    globals()[f] = inp_ida.__dict__[f]
except ImportError, e:
  import inp_dump
  for f in inp_dump.__dict__.iterkeys():
    globals()[f] = inp_dump.__dict__[f]


def get_diff(instrs):
  """Returns a list of triplets of the form (ea, orig, new)."""

  diff = []

  for ins in instrs:
    for i, (orig, new) in enumerate(zip(ins.bytes, ins.cbytes)):
      if orig != chr(new):
        if not disp._is_displaced(ins):
          diff.append((ins.addr+i, orig, chr(new)))
        else:
          diff.append((ins.disp_addr+i, orig, chr(new)))

  return diff


def get_block_diff(block):
  """Returns a list of triplets of the form (ea, orig, new). Checks for diffs
  in block level using the instrs and rinstrs (=reordered) lists."""

  orig_bytes = ''.join([i.bytes for i in block.instrs])
  reor_bytes = ''.join([i.bytes for i in block.rinstrs])
  diff = []

  for i, (orig, new) in enumerate(zip(orig_bytes, reor_bytes)):
    if orig != new:
      diff.append((block.begin+i, orig, new))

  return diff


def patch(diff, suffix, debug=False):
  """Apply the diff to a copy of the currently processed file."""

  orig = get_input_file_path()

  if orig.endswith(".dll"):
    patched = orig.replace(".dll", "_patched-%s.dll"%suffix)
  elif orig.endswith(".exe"):
    patched = orig.replace(".exe", "_patched-%s.exe"%suffix)
  else:
    print "unknown suffix in:", orig
    return None

  pe_file = pefile.PE(orig)
  base = pe_file.OPTIONAL_HEADER.ImageBase

  for ea, orig, new in diff:

    # FIXME: temp hack for the relocation diffs ..
    if ea < base:
      if not pe_file.set_bytes_at_offset(ea, new):
        print "error setting bytes"
    else:
      # sanity check ..
      curr = pe_file.get_data(ea-base, 1)
      if curr != orig:
        print "error in patching", hex(ea), ":", ord(curr), "!=", ord(orig)

      if not pe_file.set_bytes_at_rva(ea-base, new):
        print "error setting bytes"

  pe_file.write(patched)
  pe_file.close()
  if not os.access(filename, os.X_OK):
    # add execute permission
    existing_permissions = stat.S_IMODE(os.stat(patched).st_mode)
    new_permissions = existing_permissions | stat.S_IXUSR
    os.chmod(patched, new_permissions)

  if debug:
    out = open(patched + ".diff", "w")
    out.write("#  ea     orig     new\n")
    for ea, orig, new in diff:
      out.write("0x%08x %02x %02x\n" % (ea, ord(orig), ord(new)))
    out.close()

  return patched


def patch2(diff, patched_path):
  """Apply the diff to a copy of the currently processed file.
  Edited by Mahmood"""

  orig = get_input_file_path()
  patched = patched_path

  pe_file = pefile.PE(orig)
  base = pe_file.OPTIONAL_HEADER.ImageBase

  for ea, orig, new in diff:

    # FIXME: temp hack for the relocation diffs ..
    if ea < base:
      if not pe_file.set_bytes_at_offset(ea, new):
        print "error setting bytes"
    else:
      # sanity check ..
      curr = pe_file.get_data(ea-base, 1)
      if curr != orig:
        print "error in patching", hex(ea), ":", ord(curr), "!=", ord(orig)

      if not pe_file.set_bytes_at_rva(ea-base, new):
        print "error setting bytes"

  pe_file.write(patched)
  pe_file.close()

  
def get_reloc_diff(rinstrs):
  """When reordering relocatable instructions, we also need to update
  the relocation info. This function returns a byte diff of the relocation
  section."""

  diff = []
  relocations = {}

  #TODO cache relocations
  pe = pefile.PE(get_input_file_path(), fast_load=True)
  pe.parse_data_directories(directories=[ 
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']])

  for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
    for reloc in filter(lambda x: x.type == 3, base_reloc.entries):  #HIGHLOW
      relocations[reloc.rva] = reloc.struct.get_file_offset()

  base = pe.OPTIONAL_HEADER.ImageBase

  #now check if we reordered any relocatable data
  for rins in filter(lambda x: x.inst_len >= 5, rinstrs):
    #print rins.disas, hex(rins.addr), hex(rins.raddr)
    # a relocatable ref can be found after the first byte (opcode) and is
    # 4 bytes long (no need to check the last three bytes of the instruction)
    for rva in xrange(rins.addr - base + 1, rins.addr - base + rins.inst_len - 3):
      if rva in relocations:
        foff = relocations[rva]
        new_rva = rva + rins.raddr - rins.addr
        new_rva_h = ((new_rva >> 8) & 0xf) | 3 << 4 # 3 is HIGHLOW
        #print "relocations: %x %x %x %x %x %x %x" % (rva, new_rva, rva & 0xff,
        #      new_rva & 0xff, (rva >> 8) & 0xff, (new_rva >> 8) & 0xff, new_rva_h)
        diff.append((foff+1, chr((rva >> 8) & 0xff), chr(new_rva_h)))
        diff.append((foff, chr(rva & 0xff), chr(new_rva & 0xff)))

  pe.write()
  pe.close()
  return diff

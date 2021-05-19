# Copyright (c) 2012, Vasilis Pappas <vpappas@cs.columbia.edu>
# This file is part of Orp http://nsl.cs.columbia.edu/projects/orp

# Additionally modified by Mahmood Sharif <mahmoods@alumni.cmu.edu>
# Alternate contact is Keane Lucas <keanelucas@cmu.edu>

import idautils
import idaapi
import idc

import func
import bbl
import insn
  
import pickle
import pefile
import util
import pydasm

__all__ = ["get_functions", "dump_data", "get_code_heads", "code_search",
"max_ea", "byte_at", "bytes_at", "seg_start", "seg_end", "get_func_of"]

code_heads = set()

def get_typed_imports():
  """Queries IDA for functions in the import table that do have a type.
  Returns a set of (func_ea, func_type) tuples."""

  imp_funcs = set()
  
  def imp_cb(ea, name, ordn):
    ftype = idc.GetType(ea)
    if ftype:
      imp_funcs.add((ea, ftype))
    return True

  for i in xrange(idaapi.get_import_module_qty()):
    idaapi.enum_import_names(i, imp_cb)

  return imp_funcs


def get_export_list():
  """Returns a set of the exported function addresses (using pefile)"""

  exports = set()

  for i, ordn, ea, name in idautils.Entries():
    exports.add(ea)

  return exports


def get_code_and_blocks(ea):
  """Extracts the control flow graph for the function at the given address.
  Returns a dictionary with the instructions (ea->insn.Instruction) and a list
  of the basic blocs (bbl.BasicBlock)."""

  code = {}
  blocks = {}
  ida_blocks = set(idaapi.FlowChart(idaapi.get_func(ea)))

  for bb in ida_blocks:
    
    # XXX: it seems that it's not a bug but inter-function jumps!
    if bb.startEA == bb.endEA: # skip that .. it's IDA's bug
      #print "skipping block %x : %x in func %x"%(bb.startEA, bb.endEA, ea)
      continue

    blocks[bb.startEA] = bbl.BasicBlock(bb.startEA, bb.endEA, {})
    
    for head in idautils.Heads(bb.startEA, bb.endEA):
      ibytes = idc.GetManyBytes(head, idc.ItemEnd(head) - head)
      spd = idc.GetSpd(head)
      code[head] = insn.Instruction(head, ibytes, spd)
      blocks[bb.startEA].instrs.append(code[head])
      next_head = idc.NextHead(head, bb.endEA)

      if idaapi.isFlow(idc.GetFlags(next_head)):
        code[head].succ.add(next_head)
    
    for suc_bb in (s for s in bb.succs() if s.startEA != s.endEA):
      #assume head is the last instruction of the block
      code[head].succ.add(suc_bb.startEA)
  
  for bb in (b for b in ida_blocks if b.startEA != b.endEA):
    for suc_bb in (s for s in bb.succs() if s.startEA != s.endEA):
      # a jump with zero offset (like, jz 0) gives two succs to the same bb
      if blocks[suc_bb.startEA] not in blocks[bb.startEA].successors:
        blocks[bb.startEA].successors.append(blocks[suc_bb.startEA])
    blocks[bb.startEA].successors.sort(key=lambda x: x.begin, reverse=True)

  #FIXME: find a better way ..
  for block in blocks.itervalues():
    if block.instrs[0].addr == ea:
      #print "found the entry!:", block.instrs
      block.instrs[0].f_entry = True
      block.type |= bbl.BasicBlock.ENTRY
      break
  else:
    print "BUG: could not find function entry in instrs!!"
  #print "blocks:", blocks

  return code, blocks.values()


#XXX: good test function in 0x070016E7 (BIB.dll)
def get_func_code_refs_from(func_ea, iaddrs):
  """Returns a set with the code references from this function"""

  code_refs = set()

  for addr in iaddrs:
    ref = idaapi.BADADDR

    for r in idautils.XrefsFrom(addr, idaapi.XREF_FAR):

      if r.iscode:
        to_func = idaapi.get_func(r.to)
        if not to_func or to_func.startEA != func_ea:
          ref = r.to
      else:
        ref = r.to

    if ref != idaapi.BADADDR and \
       (idaapi.is_call_insn(addr) or idaapi.is_indirect_jump_insn(addr)):
      #print hex(i.addr), i, hex(ref)
      code_refs.add(ref)

  return code_refs


def get_func_code_refs_to(func_ea):
  """Returns a set with the code references to this function"""

  code_refs = set()

  for ref in idautils.CodeRefsTo(func_ea, 0): #callers
    func_ida = idaapi.get_func(ref)

    if not func_ida:
      #print "BUG?: coderef came from no function! %X->%X"%(ref, addr) 
      continue

    #if func_ida.startEA not in functions:
    #  print "BUG?: function %X not in our set (r=%X)!"%(func_ida.startEA, ref) 
    #  continue

    code_refs.add((ref, func_ida.startEA))

  return code_refs


def get_functions(unused_arg=None): #same prototype as in inp_dump..
  """Extracts useful data from the file being processed.
  Returns a dictionary (ea->func.Function) containing all
  the functions that where disassembled by IDA."""

  functions = dict()

  for f in functions_iter():
    functions[f.addr] = f

  return functions


def functions_iter():

  functions = set()
  exports = get_export_list()

  for func_ea in idautils.Functions():

    if func_ea in functions:
      continue # functions with chunks appear once for each of them..

    functions.add(func_ea)

    code, blocks = get_code_and_blocks(func_ea)
    crefs_to = get_func_code_refs_to(func_ea)
    crefs_from = get_func_code_refs_from(func_ea, code.iterkeys())
    f = func.Function(func_ea, code, blocks, crefs_to, crefs_from)
    f.ftype = idc.GetType(func_ea)
    f.name = idc.GetFunctionName(func_ea)

    if func_ea in exports:
      f.exported = True

    # jumps can exit functions too
    if code:
      ins_addrs = set()
      for ins in f.instrs:
        ins_addrs.add(ins.addr)
      for block in f.blocks:
        for ins in block.instrs:
          if ins.mnem=='jmp':
            ins_asm = pydasm.get_instruction(ins.bytes, pydasm.MODE_32)
            if ins_asm.op1.type==pydasm.OPERAND_TYPE_IMMEDIATE:
              jmp_addr = int(ins.disas.split(' ')[1], 16)
              if not (jmp_addr in ins_addrs):
                ins.f_exit = True
                block.type = bbl.BasicBlock.EXIT

    # add/sub cannot be replaced if a subsequent instruction
    # reads the EF (eflags) register
    if f.code:
      for block in f.blocks:
        instrs = list(block.instrs)
        instrs.sort(key=lambda ins: ins.addr)
        for ins1 in instrs:
          ins1.irreplaceable = False
          if ins1.mnem=='add' or ins1.mnem=='sub':
            for ins2 in instrs:
              if ins2.addr>ins1.addr:
                if ins2.eflags_r \
                   or ins2.mnem=='adc' or ins2.mnem=='sbb':
                  # weirdly enough, eflags_r is 0 for adc and sbb
                  ins1.irreplaceable = True
                  break
                if ins2.eflags_w:
                  ins1.irreplaceable = False
                  break
    
    yield f

  typed_imports = get_typed_imports()

  for imp_ea, ftype in typed_imports:
    crefs_to = get_func_code_refs_to(imp_ea)
    f = func.Function(imp_ea, None, None, crefs_to, None)
    f.ftype = ftype
    f.level = -1 # special level for imported functions
    yield f
  
  #return functions

  
def dump_data():
  """Extracts and dumps useful data from the file being processed.
  The output is written using pickle and it consists of a set with all the
  code heads followed by func.Function objects (ended with a None)."""

  dump_out = util.open_dump(idaapi.get_input_file_path(), "wb")

  pickle.dump(get_code_heads(), dump_out)

  for f in functions_iter():
    pickle.dump(f, dump_out)

  pickle.dump(None, dump_out)

  dump_out.close()


def get_code_heads():
  """Returns a set with all the recognized code heads from all the
  code sections."""

  global code_heads

  if len(code_heads) == 0:
    for begin, end, name in code_segments_iter():
      code_heads |= set(filter(lambda x: idaapi.isCode(idc.GetFlags(x)),
                                         idautils.Heads(begin, end)))

  return code_heads



def code_segments_iter():
  """Iterates over the possible code sections within an input binary."""

  for i in range(idaapi.get_segm_qty()):
    seg = idaapi.getnseg(i)

    if not seg:
      continue

    seg_class = idaapi.get_segm_class(seg)

    if seg_class != "CODE":
      continue

    seg_name = idaapi.get_segm_name(seg.startEA)

    yield seg.startEA, seg.endEA, seg_name

#--------------------------------------------------------------------------------


def code_search(ea, val):
  """Search forward for the next occurance of val. Return None if no match."""

  res = idc.FindBinary(ea, idc.SEARCH_DOWN, val)

  if res == idaapi.BADADDR:
    return None
  else:
    return res


def byte_at(ea):
  """Returns the byte at the given address."""

  return idc.Byte(ea)


def max_ea(): # TODO: check!!
  """Returns the max effective address for this binary."""

  return idc.MaxEA()


def bytes_at(ea, num):
  """Returns num of bytes at the given address."""

  return idc.GetManyBytes(ea, num)


def seg_start(ea):
  """Returns the start of the segment that ea belongs in."""

  return idc.SegStart(ea)


def seg_end(ea):
  """Returns the end of the segment that ea belongs in."""

  return idc.SegEnd(ea)


def get_func_of(ea):
  """Return the function that this address belongs to, if any."""

  func = idaapi.get_func(ea)

  if func:
    return func.startEA
  else:
    return None


def get_input_file_path():
  """Return the name of the currently processed file."""

  return idaapi.get_input_file_path()



#--------------------------------------------------------------------------------


"""
def get_functions():
  return idautils.Functions()


def get_function_name(func_ea):
  return idc.GetFunctionName(func_ea)


def get_function_by_name(func_name):
  for func_ea in idautils.Functions():
    if func_name in idc.GetFunctionName(func_ea):
      break
  return func_ea


def get_input_file_path():
  return idaapi.get_input_file_path()


def get_fileregion_offset(ea):
  return idaapi.get_fileregion_offset(ea)


def get_code_heads(start, end):
  return filter(lambda x: idaapi.isCode(idc.GetFlags(x)), idautils.Heads(start, end))


def get_func_of(ea):
  func = idaapi.get_func(ea)
  if func:
    return func.startEA
  return None


def reanalyze():
  ea = next(idautils.Functions(), None)
  if ea != None:
    idc.AnalyzeArea(idc.SegStart(ea), idc.SegEnd(ea))


def get_func_type(func_ea):
  return idc.GetType(func_ea)




def find_and_dump_gadgets():
  import gadget
  dump_out = open("%s.gadgets" % get_input_file_path(), "wb")
  step = 512*1024
  for begin, end, name in code_segments_iter():
    while begin < end:
      gadgets = gadget.find_gadgets5(begin, min(begin+step, end))
      simple_gadgets = set((g.dump_simple(extra=True) for g in gadgets))
      pickle.dump(simple_gadgets, dump_out)
      begin += step
  pickle.dump(None, dump_out)
  dump_out.close()


def dump_exp_gadgets():
  import gadget
  exp_gadgets = gadget.find_exp_gadgets()
  with open("%s.payload.gadgets" % get_input_file_path(), "wb") as f:
    pickle.dump(exp_gadgets, f)
  return 


def load_exp_gadgets(dump_file):
  with open(dump_file, "rb") as f:
    exp_gadgets = pickle.load(f)
  return exp_gadgets


def disasm(ea):
  return idc.GetDisasm(ea)

"""

if __name__ == "__main__":
  import sys
  sys.setrecursionlimit(40000)
  idc.Wait()   # Wait for IDA to complete its auto analysis
  #reanalyze() # XXX already reanalyzed
  dump_data()
  #dump_exp_gadgets()
  #find_and_dump_gadgets()
  idc.Exit(0)

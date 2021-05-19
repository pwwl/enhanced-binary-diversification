# Copyright (c) 2021, Mahmood Sharif, Keane Lucas, Michael K. Reiter, Lujo Bauer, and Saurabh Shintre
# This file is code used in Malware Makeover

"""
A collection of tools that can be useful when
running randomization.
"""
import func

def reanalyze_functions(functions, levels):
  """
  Reanalyze the functions to re-run the randomization
  """
  # reset instruction and function's states
  for a, f in functions.iteritems():
    if f.level==-1:
      continue
    # re-init functions that were reordered
    if hasattr(f, 'code'):
      code = f.code
      was_reordered = [ins_a!=f.code[ins_a].addr for ins_a in f.code]
      if any(was_reordered):
        code2 = dict([(ins.addr, ins) for ins in code.itervalues()])
        f2 = func.Function(f.addr, code2, f.blocks, \
                           f.code_refs_to, f.code_refs_from)
        #assert(len(f2.blocks)==len(f.blocks))
        #assert(len(f2.instrs)==len(f.instrs))
        f2.name = f.name
        f2.exported = f.exported
        f2.ftype = f.ftype
        f2.level = f.level
        functions[a] = f2
    # update calls/rets/...
    for ref, func_ea in f.code_refs_to:
      try:
        # re-init the data structures
        f2 = functions[func_ea]
        f2.code[ref].USE = set()
        f2.code[ref].DEF = set()
        f2.code[ref].implicit = set()
        f2.code[ref].updated = False
      except KeyError, e:
        pass
    for ins in filter(lambda x: x.mnem == "call", f.instrs):
      ins.can_change = set()
      ins.USE = set()
      ins.DEF = set()
      ins.implicit = set()
    for ins in filter(lambda x: x.f_exit, f.instrs):
      ins.USE = set()
      ins.implicit = set()
    # reset data-structures (mainly of functions that weren't reordered)
    for ins in f.instrs:
      ins.reset_changed()
      ins.apply_changes()
      if ins.updated:
        ins.updated = False
    f.arg_regs = set()
    f.ret_regs = set()
    f.pre_regs = set()
    f.ret_regs = set()
    f.reg_pairs = []
  # run function-level analysis
  func.analyze_functions(functions, levels)

def patch(pe_file, disp_state, diffs):
  """
  patch the pe_file according to the provided diffs
  (i.e., apply the diffs). The code is based on inp.patch().
  """
  base = pe_file.OPTIONAL_HEADER.ImageBase
  for ea, orig, new in diffs:
    if (disp_state is None) or ea<disp_state.ropf_start: # non displaced instruction
      if ea < base:
        if not pe_file.set_bytes_at_offset(ea, new):
          print "error setting bytes"
      else:
        curr = pe_file.get_data(ea-base, 1)
        if orig!=None and curr != orig:
          print "error in patching", hex(ea), ":", ord(curr), "!=", ord(orig)
        if not pe_file.set_bytes_at_rva(ea-base, new):
          print "error setting bytes"

# Copyright (c) 2012, Vasilis Pappas <vpappas@cs.columbia.edu>
# This file is part of Orp http://nsl.cs.columbia.edu/projects/orp

# Additionally modified by Mahmood Sharif <mahmoods@alumni.cmu.edu>
# Alternate contact is Keane Lucas <keanelucas@cmu.edu>

import insn
import bbl

from pygraph.classes.digraph import digraph
from pygraph.classes.graph import graph
from pygraph.algorithms.searching import depth_first_search
from pygraph.algorithms.searching import breadth_first_search
from pygraph.algorithms.filters.null import null as null_filter


class _use_filter(null_filter):

  def __init__(self):
    self.use_regs = set()
    self.all_regs = set(insn.REGS[:8])
  
  def __call__(self, other, node):
    self.use_regs |= (self.all_regs & other.USE)
    self.all_regs -= other.DEF
    return True


class _def_filter(null_filter):

  def __init__(self, reg):
    self.reg = reg
    self.last_ins = None

  def __call__(self, other, node):
    self.last_ins = other
    # always check node, so we will not check the first pop
    if node and self.reg in other.DEF:
      return False
    return True


#TODO consider splitting the function class to a simpler one, more
#appropriate for dumping (like SimpleGadget in gadget.py)

class Function(object):

  def __init__(self, addr, code, blocks, crefs_to, crefs_from):
    #TODO: add name as an attribute
    self.addr = addr
    self.code = code
    self.blocks = blocks
    self.arg_regs = set() # register-arguments
    self.ret_regs = set() # register-return values
    self.pre_regs = set() # preserved registers
    self.touches = set()  # either USEd or DEFed but not preserved
    self.reg_pairs = []   # hold the pairs of push/pops for pre regs
    self.ftype = None 
    self.name = None
    self.exported = False
    self.level = -2 # legal levels are -1,0,1,2..
    self.code_refs_to = crefs_to # .. this func
    if code: # it could be an imported func
      self.instrs = self._reorder_instructions()
      self.igraph = self._get_instrs_graph()
      self.code_refs_from = crefs_from
      #self.ind_calls = [i for i in self.instrs if i.is_ind_call()]

  def __del__(self):
    if self.code:
      del self.igraph
      del self.instrs
      del self.code_refs_from
      del self.code
    del self.addr
    del self.blocks
    del self.code_refs_to
    del self.arg_regs
    del self.ret_regs
    del self.pre_regs
    del self.touches
    del self.reg_pairs
    del self.ftype
    del self.name

  def _reorder_instructions(self):
    cfg = digraph()
    cfg.add_nodes(self.blocks)

    for block in self.blocks:
      for other in block.successors:
        cfg.add_edge((block, other))

    root = next((b for b in self.blocks if b.type & bbl.BasicBlock.ENTRY), None)
    instrs = list()
    span_tree, pre, post = depth_first_search(cfg, root)

    for block in reversed(post):
      instrs.extend(block.instrs)
    instrs[0].f_entry = True # TODO: why do we need this? is there a bug  somewhere?
  
    for i, ins in enumerate(instrs):
      ins.pos = i
 
    del cfg
    return instrs

  def _get_instrs_graph(self):
    #initialize graph
    igraph = digraph()
    igraph.add_nodes(self.code.itervalues())
    for ins in self.code.itervalues():
      for suc in ins.succ:
        igraph.add_edge((ins, self.code[suc]))
    return igraph

  # can be called after analyze_registers and update the reg sets
  def parse_ftype(self, ftype):
    if not ftype.startswith("void"):
      self.ret_regs.add("eax")
    else:
      self.ret_regs.discard("eax")
    if "__cdecl" in ftype or "__stdcall" in ftype:
      self.touches.update(("eax", "ecx", "edx"))
    elif "__fastcall" in ftype:
      self.arg_regs.update(("ecx", "edx"))
      self.touches.update(("eax", "ecx", "edx"))
    elif "__thiscall" in ftype:
      self.arg_regs.add("ecx")
      self.touches.update(("eax", "ecx", "edx"))
    #XXX not sure!
    self.pre_regs.update(('esi', 'edi', 'ebx', 'ebp', 'esp'))
    self.touches -= self.pre_regs


  def check_SEH_preservs(self, functions):
    for ref in self.code_refs_from:
      if ref in functions:
        name = functions[ref].name
        if name and ("SEH_prolog" in name or "SEH_epilog" in name):
          self.pre_regs.update(('ebp', 'esi', 'edi', 'ebx'))
          return True
    return False


  def analyze_registers(self, functions):
    # quickly check if this func is SEH prolog or epilog and skip analysis
    if self.name and ("SEH_prolog" in self.name or "SEH_epilog" in self.name):
      return

    # normal analyze
    # find all the arguments and pushes
    use_f = _use_filter()
    if not self.instrs[0].f_entry: # debug!
      print "BUG: analyze_registers: instrs[0] is not f_entry!!!"
    st, order = breadth_first_search(self.igraph, self.instrs[0], use_f)

    # let's sort out the preserved registers first
    # XXX: check for the special case of SEH and skip the usual check!
    if not self.check_SEH_preservs(functions):
      #TODO: handle enter as push ebp!! (there is no enter in reader dlls..)
      pushes, pops = [], []
      for ins in self.instrs:
        if ins.mnem == "leave" or (ins.mnem == "pop" and
             ins.op1.type == insn.Operand.REGISTER):
          pops.append(ins)
        elif (ins.mnem == "push" and ins.op1.type == insn.Operand.REGISTER and
              len(ins.USE & use_f.use_regs) > 1): #esp is always in there..
          pushes.append(ins)
      for push in pushes:
        # is there any case to have 'push esp' !?
        if len(push.USE) != 2 or "esp" not in push.USE:
          print "WEIRD push instruction !?:", push
          continue
        reg = (push.USE-set(("esp",))).pop()
        # no need to put any extra check to the filter bellow for the leave case:
        # leave DEFs ebp and esp, and there is no way for reg=esp!
        reg_pops = filter(lambda x: reg in x.DEF, pops)
        if not reg_pops: # no pops, it's propably a push arg for a call
          continue
        true_reg_pops = []
        for pop in reg_pops:
          def_f = _def_filter(reg)
          st, order = breadth_first_search(self.igraph, pop, def_f)
          if def_f.last_ins.mnem not in ("ret", "retn", "jmp"): # nooo
            #print "break for", pop, "at", def_f.last_ins
            continue
          true_reg_pops.append(pop)
        if true_reg_pops:
          self.reg_pairs.append((reg, push, true_reg_pops))
          self.pre_regs.add(reg)

    # now we can safely tell which are the register-arguments
    self.arg_regs = use_f.use_regs - self.pre_regs

    # next, let's define the touched set
    #XXX not sure if we need to split this set to USE and DEF ones ..
    # should something that was only read in a function be considered as
    # a return value? .. maybe yes..
    for ins in self.instrs:
      self.touches |= (ins.DEF | ins.USE)
    self.touches -= self.pre_regs

    if not self.arg_regs <= self.touches:
      print "BUG: how can arg_regs not be subset of touched?", self

    # final set (and most difficult) the return-value registers
    for ref, func_ea in self.code_refs_to:
      try:
        func = functions[func_ea]
        use_f = _use_filter()
        #XXX: be careful!, a reg might be used after a call instrs .. we have
        # to check in that case if this is a return value of this function or
        # of the other (a third one)
        #TODO: we can add this as a generic test in the filters to check for 
        # CodeXfers to unanalyzed function
        st, order = breadth_first_search(func.igraph, func.code[ref], use_f)
        #self.ret_regs.append(use_f.use_regs & self.touches)
        self.ret_regs |= (use_f.use_regs & self.touches)
      except KeyError, e:
        pass

  def update_returns(self, set_default=False):
    for ins in filter(lambda x: x.f_exit, self.instrs):
      if set_default:
        # we can't be sure that ret_args was computed correctly, because this is
        # an unclassified function. use eax ..
        # Mahmood: Use edx too, to be conservative. In some conventions,
        # edx is also used to return values (e.g., see func #213 in less.exe
        # of Cygwin).
        ins.USE.update(set(('eax','edx')) | self.ret_regs | self.pre_regs)#REGS[:8])
        ins.implicit.update(set(('eax','edx')) | self.ret_regs | self.pre_regs)#REGS[:8])
      else:
        ins.USE.update(set(('eax',)) | self.ret_regs | self.pre_regs)
        ins.implicit.update(set(('eax',)) | self.ret_regs | self.pre_regs)

  # must be called after update_callers_info has been called for 
  # all analyzed functions
  def update_calls(self):
    # use the "super-set" of calling convention in cases we are not sure
    for ins in filter(lambda x: x.mnem == "call", self.instrs):
      if not ins.updated: #damn
        # the can_change registers can be changed up to the call instr
        ins.can_change.update(ins.USE - ins.implicit)
        ins.USE.update(("ecx", "edx"))
        ins.DEF.update(("eax", "ecx", "edx"))
        ins.implicit.update(("eax", "ecx", "edx"))

  def update_callers_info(self, functions):
    for ref, func_ea in self.code_refs_to:
      try:
        # update the USE and DEF sets of all the calls to this analyzed function
        func = functions[func_ea]
        func.code[ref].USE.update(self.arg_regs)
        func.code[ref].DEF.update(self.touches)
        func.code[ref].implicit.update(self.touches | self.arg_regs)
        func.code[ref].updated = True
      except KeyError, e:
        pass

  def get_basic_block(self, start_ea, end_ea):
    for bb in self.blocks:
      if bb.begin == start_ea and bb.end == end_ea:
        return bb
    return None

  def __str__(self):
    ret =  "0x%0X level-%d\n" % (self.addr, self.level)
    ret += "   arguments: %s\n" % self.arg_regs
    ret += "   touches  : %s\n" % self.touches
    ret += "   returns  : %s\n" % self.ret_regs
    ret += "   preserved: %s\n" % self.pre_regs
    return ret


#TODO: need to go through this again ..
def classify_functions(functions):
  """Classifies the functions based on their call relationship. This classification
  can be done in the beginning as it only requires the code_refs_to and code_refs_from
  sets. The 'level' values of each function will be updated from -2 (unclassified) to
  a value >=0. Imported functions already have a 'level' value of -1."""

  # do a bottom-up classification of the functions
  # start with functions that have no call instructions, then
  # processes functions that only call the previous ones, and so on
  level = 0
  processed, curr_processed = set(), set()
  while len(processed) < len(functions):
    curr_processed.clear()
    for func in filter(lambda x: x.level == -2, functions.itervalues()):
      if func.code_refs_from <= processed:
        func.level = level
        curr_processed.add(func.addr)
    if curr_processed <= processed: # subset of processed
      #print "no more to analyze .. let's search for typed"
      curr_processed.clear() # we already had them .. 
      for func in filter(lambda x: x.level == -2, functions.itervalues()):
        if func.ftype:
          func.level = level
          curr_processed.add(func.addr)
      #print "found %d typed and not analyzed functions" % len(curr_processed)
      if not curr_processed:
        break
    #print "\tfound %d level-%d functions"%(len(curr_processed-processed), level)
    processed.update(curr_processed)
    level += 1
  
  #print "\tclassified", len(processed), "out of", len(functions), "functions"
  return level


#TODO: need to go through this again ..
def analyze_functions(functions, levels):
  """Analyzes the functions by calling f.analyze_registers and also updates
  the USE-DEF sets of the appropriate call/ret functions."""

  #(imported) update info on callers of imported functions
  for func in filter(lambda x: x.level == -1, functions.itervalues()):
    func.parse_ftype(func.ftype)
    func.update_callers_info(functions)

  #(classified) process each level of functions in order
  for l in range(levels):
    #print "\tanalyzing level-%d functions" % l
    for func in filter(lambda x: x.level == l, functions.itervalues()):
      func.analyze_registers(functions)
      # special case for typed functions
      if func.ftype: # typed functions that call unclassified ones
        func.parse_ftype(func.ftype) # safe to call after analyze_regs
      func.update_callers_info(functions)
      func.update_returns()
      func.update_calls()

  # (unclassified) this one will set default USE and DEF values to any not
  # updated calls and all the retns. such calls should only exist in
  # unclassified functions
  #print "\tanalyzing unclassified functions"
  for func in filter(lambda x: x.level == -2, functions.itervalues()):
    func.update_calls()

  # now that all calls/retns are set, let's analyze the unclassified methods too
  # mostly for the preserved registers
  for func in filter(lambda x: x.level == -2, functions.itervalues()):
    func.analyze_registers(functions)
    func.update_returns(set_default=True)

  for func in filter(lambda x: x.level == -2, functions.itervalues()):
    func.update_callers_info(functions) #XXX XXX

  #print "counting the number of updated call instructions:"
  calls = updated = 0
  for func in filter(lambda x: hasattr(x, "instrs"), functions.itervalues()):
    for ins in filter(lambda x: x.mnem == "call", func.instrs):
      calls += 1
      if ins.updated:
        updated += 1

  #print "\ttotal %d, updated %d" % (calls, updated)

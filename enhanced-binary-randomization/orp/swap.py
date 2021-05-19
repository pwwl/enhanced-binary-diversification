# Copyright (c) 2012, Vasilis Pappas <vpappas@cs.columbia.edu>
# This file is part of Orp http://nsl.cs.columbia.edu/projects/orp

# Additionally modified by Mahmood Sharif <mahmoods@alumni.cmu.edu>
# Alternate contact is Keane Lucas <keanelucas@cmu.edu>

import itertools
import inp
from collections import deque
import random
import randtoolkit

from pygraph.algorithms.filters.null import null as null_filter
from pygraph.algorithms.searching import breadth_first_search

class Lifetime:
  """Represents the lifetime of a register as a set of "Subsets"."""

  def __init__(self, name, max_span_size):
    self.regions  = []
    self.subsets  = []
    self.name     = name
    self.span     = [None]*max_span_size # optimize region lookups 
    self.max_size = max_span_size

  def get_reg_name_in(self, begin, end):
    names = set(self.cname[begin:end+1])-set([None])
    if len(names) == 0: #dead
      return self.name
    elif len(names) == 1:
      return names.pop()
    else: # more than one names !?
      # be conservative here and filter the combination ..
      return None #self.name #names.pop()

  def update_reg_name_in(self, begin, end, name):
    self.cname[begin:end+1] = [name]*(end-begin+1)

  def reset_name(self):
    self.cname = [None]*self.max_size
    for r in self.regions:
      self.cname[r.begin:r.end+1] = [self.name]*(r.end-r.begin+1)

  def dont_touch(self):
    return len(self.subsets) == 0 or (len(self.subsets) == 1 and 
                           self.subsets[0].size == self.max_size)

  def add_subset(self, instrs):
    # subsets of the same register may overlap overlap, mostly due to 
    # one instruction live regions
    new_subset = Subset(instrs, self.name)
    for subset in self.subsets[:]: #copy because it changes
      if subset.intersects(new_subset):
        new_subset.merge(subset)
        self.subsets.remove(subset)
    self.subsets.append(new_subset)

  def get_swap_subset(self, subset, other):
    #get a copy of subset!
    subset = subset.copy()
    #print "will check", self.name, other.name, "in", subset

    for lifetime in itertools.cycle((self, other)):
      old_size = subset.size
      for sg in lifetime.subsets:
        if sg.intersects(subset):
          #print "\t", sg, "intersects", subset
          if sg.no_swap:
            #print "\tsg is no swap .. bail out"
            return None
          #print "\tmerging them!"
          subset.merge(sg)
      if subset.size == old_size:
        #print "\tsize did not change, done!"
        break

    return subset

  def __str__(self):
    return "%s (dont_touch=%-5s): %s" % (self.name, self.dont_touch(), 
                            ", ".join(map(str, self.subsets)))

  def __repr__(self):
    return self.name


class Subset:
  """Represents a subset of the CFG (instructions only, sufficient
  and much faster)"""
  
  def __init__(self, instrs, register):
    # check whether region is unswappable and make the graph
    self.instr_set = set()
    self.no_swap = False
    for ins in instrs:
          # check if register is implicitly used
      if not self.no_swap and ((register in ins.implicit) or
          # check if reg was alive before the function was called
          (ins.f_entry and register in ins.IN) or
          # for now, we assume that every register that is alive at exit
          # may be used by the caller (return value(s))
          (ins.f_exit and register in ins.USE)):
        self.no_swap = True
      self.instr_set.add(ins)
    self.size = len(self.instr_set)
 
  def merge(self, other):
    self.instr_set.update(other.instr_set)
    self.size = len(self.instr_set)
    self.no_swap = self.no_swap or other.no_swap

  def intersects(self, other):
    # fast, no copies
    return len(self.instr_set & other.instr_set) > 0 #any((n in self.instr_set for n in other.instr_set))

  def copy(self):
    copy_subset = Subset([], '')
    copy_subset.instr_set = self.instr_set.copy()
    copy_subset.size = self.size
    copy_subset.no_swap = self.no_swap
    return copy_subset
 
  # mostly for debug
  def to_graph(self, code):
    graph = digraph()
    graph.add_nodes(self.instr_set)
    for ins in self.instr_set:
      for suc in ins.succ:
        if graph.has_node(code[suc]):
          graph.add_edge((ins, code[suc]))
    return graph
 
  def __str__(self):
    return "%s no_swap=%s" % ([min((i.pos for i in self.instr_set)), 
           max((i.pos for i in self.instr_set))], self.no_swap)


class Swap:
  """Simple class to hold swaps."""
  def __init__(self, reg1, reg2, subset):
    self.reg1 = reg1 if reg1 > reg2 else reg2
    self.reg2 = reg2 if reg1 > reg2 else reg1
    #self.reg1 = reg1 if reg1.name > reg2.name else reg2
    #self.reg2 = reg2 if reg1.name > reg2.name else reg1
    self.regs = set((self.reg1, self.reg2))
    self.size = subset.size
    self.addrs = tuple(sorted(i.addr for i in subset.instr_set))
    self.subset = subset
    self._id = "%s-%s-%x" % (self.reg1.name, self.reg2.name,
               sorted(self.subset.instr_set, key=lambda x: x.addr)[0].addr)

  def get_instrs(self):
    return self.subset.instr_set

  def overlap(self, other):
    return self.subset.instr_set & other.subset.instr_set

  def __eq__(self, other):
    return (isinstance(other, Swap) and self._id == other._id)

  def __hash__(self):
    return hash(self._id)
 
  def __repr__(self):
    return "%s <-> %s (%d) in: %s " % (self.reg1.name, self.reg2.name,
           len(self.subset.instr_set), [min((i.pos for i in self.subset.instr_set)), 
           max((i.pos for i in self.subset.instr_set))])
  
  def bounds(self):
    """
    Returns the min position and max position of the instructions
    covered by the swap.
    """
    return [min((i.pos for i in self.subset.instr_set)), \
            max((i.pos for i in self.subset.instr_set))]

def liveness_analysis(code):
  """Performs instruction-level liveness analysis and fills in the 
  IN and OUT sets of each instruction."""

  convergence = False
  i = 0

  for ins in code.itervalues():
    ins.IN = set()
    ins.OUT = set()
  
  while not convergence:
    i += 1
    for ins in code.itervalues():
      ins.IN_old = ins.IN.copy()
      ins.OUT_old = ins.OUT.copy()
      # out[n] = U_{s is successor of n} in[n]
      ins.OUT = reduce(lambda x, y: x | y, [code[s].IN for s in ins.succ], set())
      # ins[n] = use[n] U (out[n] - def[n])
      if ins.mnem=='call':
        # Be careful not to swap registers that are implicitly
        # used by call (e.g., if eax is used for sending arguments,
        # we should be careful not to swap it)
        ins.IN = ins.USE | ins.implicit | (ins.OUT - ins.DEF)
      else:
        # normal case
        ins.IN = ins.USE | (ins.OUT - ins.DEF)

    # repeat until in'[n] == in[n] and out'[n] == out[n] for all n
    for ins in code.itervalues():
      if (ins.IN_old != ins.IN) or (ins.OUT_old != ins.OUT):
        break
    else:
      # for loop fell through without finding any IN/OUT difference
      convergence = True

def get_reg_live_subsets(instrs, code, igraph):
  """Computes the subsets of the instructions where each register is live.
  Retunrs a dictionary keyed with the register name."""

  # compute the live subsets
  live_regs = dict()
  for reg in ('eax', 'ebx', 'ecx', 'edx', 'edi', 'esi', 'ebp', 'esp'): #TODO: insn.REGS[:8]
    live_regs[reg] = Lifetime(reg, len(instrs))
  
  class live_filter(null_filter):
    def __call__(self, other, node):
      # always check 'other' which is the candidate. (includes root)
      # but also check if node is set which takes care of root
      if node and self.cur_reg not in other.IN:
        #print "forward filtered %s from %s (reg=%s)" % ( 
        #    str(other), str(node), self.cur_reg)
        return False
      return True

  # compute live regions for register values "born" withing this function
  live_f = live_filter()
  for ins in instrs:
    diff = ins.OUT - ins.IN
    if len(diff) > 1 and ins.mnem not in ("call", "cpuid", "rdtsc"):
      print "WARNING: more than one regs defined at", ins, ins.OUT, ins.IN
    for reg in diff:
      live_f.cur_reg = reg
      st, order = breadth_first_search(igraph, ins, live_f)
      live_regs[live_f.cur_reg].add_subset(order)

  # if a DEFed register is not in OUT it's an one-instr live region.
  # if that register is also in the implicit set of the instruction,
  # it will be marked as unswappable
  for ins in instrs:
    for reg in ins.DEF:
      if reg not in ins.OUT:
        #print "one-instr live region, register", reg, " in ", ins
        live_regs[reg].add_subset([ins])

  # add live regions for registers that where alive before this function
  # was called.
  if not instrs[0].f_entry: # debug!
    print "BUG: compute_live: instrs[0] is not f_entry!!!"

  #print "compute_live_regions: checking", instrs[0]
  for reg in instrs[0].IN:
    #print "compute_live_regions: checking", reg, "in", instrs[0]
    live_f.cur_reg = reg
    st, order = breadth_first_search(igraph, instrs[0], live_f)
    #print reg, "live region", [i.pos for i in order]
    # let's handle the special case of region splitting for indirect calls
    live_regs[live_f.cur_reg].add_subset(order)

  return live_regs


#TODO: splitting is not 100% .. first, we stop after we find just one split
# per subset (there could be cases that we would be able to prune more) and
# second, we should recursively check all the possible subsubsets .. not just
# simple spits
def split_reg_live_subsets(live_regs, code):
  """Checks whether the computed live subsets can be split. A live subset can be
  split when it contains an isntruction that USEs and DEFs the same register, thus
  ending and beginning new subsets."""

  def _split_subset_at(instr_set, at, code):
    #print "lets do", instr_set, at, code
    # find the subset after the indirect call
    after = set()
    queue = set((code[s] for s in at.succ if code[s] in instr_set))
    while len(queue) > 0:
      ins = queue.pop()
      after.add(ins)
      queue.update((code[s] for s in ins.succ if code[s] in instr_set and code[s] not in after))
    #print "after", after
    #XXX sneaky: check for rhombus weird stuff!
    succs = set()
    for ins in instr_set - after - set((at,)):
      succs.update((code[s] for s in ins.succ if code[s] in instr_set))
    #print "succs", succs
    if succs & after:
      #print "WARNING: rhombus in split!", at
      return None, None
    if at in after:
      print "WARNING: cycle!", at
      return None, None
    before = instr_set - after - set((at,))
    return before, after
  
  def _unswappable_subsets_iter():
    for reg in live_regs.itervalues():
      for subset in (s for s in reg.subsets if s.no_swap):
        yield reg, subset
    return

  def recursive_split(reg, subset, code, changes):
    for ins in subset.instr_set:
      # check if we have a indirect call and split the region in two!
      if reg.name in ins.implicit and reg.name in ins.can_change:
        before_call, after_call = _split_subset_at(subset.instr_set, ins, code) 
        if before_call == after_call == None:
          continue
        # we check whether the region ending before the call would be swappable
        # if so, we split it!
        if Subset(before_call, reg.name).no_swap == False:
          #print "yeii we're splitting!!"
          sub1 = Subset(before_call | set((ins,)), reg.name)
          sub1.no_swap = False #we have to manually change it here ..
          if len(after_call) > 0: #no need if last ins is our call
            sub2 = Subset(after_call, reg.name)
            sub2.no_swap = True #we have to manually change it here ..
            changes.append((reg, subset, (sub1, sub2)))
            recursive_split(reg, sub2, code, changes)
          else:
            changes.append((reg, subset, (sub1,)))
          break
      # check if we have mov or lea instructions that have the same src, dst
      # XXX: this is a quick and dirty implementation: we only search for 
      # unswappable regions that contain these kind of instructions and then,
      # if spliting these regions would produce a swappable part, we split it
      elif ins.mnem in ("movzx", "movsx", "mov", "lea") and set((reg.name,)) == (ins.DEF & ins.USE):
        before, after = _split_subset_at(subset.instr_set, ins, code)
        #print ins, before, after
        if before == after == None:
          continue
        if Subset(before | set((ins,)), reg.name).no_swap == False:
          sub1 = Subset(before | set((ins,)), reg.name)
          sub2 = Subset(after, reg.name)
          changes.append((reg, subset, (sub1, sub2)))
          ins.cregs[reg.name].remove((ins.modrm_off, 3))
          recursive_split(reg, sub2, code, changes)
          break
        elif Subset(set((ins,)) | after, reg.name).no_swap == False:
          sub1 = Subset(before, reg.name)
          sub2 = Subset(set((ins,)) | after, reg.name)
          changes.append((reg, subset, (sub1, sub2)))
          #print ins.regs, '->',
          ins.cregs[reg.name] = [(ins.modrm_off, 3)]
          #print ins.regs
          recursive_split(reg, sub1, code, changes)
          break
    return

  changes = []
  for reg, subset in _unswappable_subsets_iter():
    recursive_split(reg, subset, code, changes)
  for reg, subset, subs in changes:
    reg.subsets.remove(subset)
    reg.subsets.extend(subs)
  return


def get_reg_swaps(live_regs):
  """Given all the registers' live subsets, check which of them can
  be swapped. Returns a list with Swap objects."""

  swaps = [] # <- MOVE BACK TO SET
  # filter out any registers that are not used
  reg_vals = filter(lambda x: not x.dont_touch(), live_regs.values())
  for reg, other in itertools.permutations(reg_vals, 2):
    for subset in reg.subsets:
      if subset.no_swap:
        continue
      # print "ASDASD", reg, subset
      swap_subset = other.get_swap_subset(subset, reg)
      if swap_subset != None and swap_subset.size == 0:
        print "BUG: empty subset in get_swap_subset"
        continue
      if swap_subset != None:
        swaps.append(Swap(reg, other, swap_subset)) # <-BACK TO SET!

  return list(swaps)


def apply_swap_comb(swap_comb):
  """Applies each swap in the combination by updating ins.cregs and ins.cbytes.
  Returns a boolean indicating whether this swap combination can be applied and
  the set of changed instructions."""

  changed = set()
  failed = False
  
  #apply swaps
  for swap in swap_comb:
    for ins in swap.get_instrs():
      # r1, r2 have original register names, as Instruction.regs does
      if swap.reg1.name in ins.regs or swap.reg2.name in ins.regs:
        changed.add(ins)
        if not ins.swap_registers(swap.reg1.name, swap.reg2.name):
          failed = True
          break

  return not failed, changed

def bound_comparison(swap1, swap2):
  """
  Compare the bounds of two swaps; returns 0 for no
  overlap, 1 for overlap, and -1 for partial overlap.
  Assumes that the range of swap1 is larger than swap2's.
  """
  instrs1 = swap1.subset.instr_set
  instrs2 = swap2.subset.instr_set
  if instrs2.issubset(instrs1):
    return 1
  if len(instrs1 & instrs2)>0:
    return -1
  return 0
  # bounds1 = swap1.bounds()
  # bounds2 = swap2.bounds()
  # if bounds2[1]<bounds1[0] or bounds1[1]<bounds2[0]:
  #   return 0
  # if bounds1[0]<=bounds2[0] and bounds2[1]<=bounds1[1]:
  #   return 1
  # return -1

def reg_overlap(swap1, swap2):
  """
  returns True if swap1 and swap2 have any register in common
  """
  if swap1.reg1.name==swap2.reg1.name or \
     swap1.reg1.name==swap2.reg2.name or \
     swap1.reg2.name==swap2.reg1.name or \
     swap1.reg2.name==swap2.reg2.name:
    return True
  return False

def swap_to_key(swap):
  regs = ['eax', 'ebx', 'ecx', 'edx', 'edi', 'esi', 'ebp', 'esp']
  reg_to_idx = dict(zip(regs,list(range(len(regs)))))
  bounds = swap.bounds()
  key = (bounds[1]-bounds[0])*1000000
  key += bounds[0]*100
  key += max([reg_to_idx[swap.reg1.name], reg_to_idx[swap.reg2.name]])*10
  key += min([reg_to_idx[swap.reg1.name], reg_to_idx[swap.reg2.name]])
  return key

def can_swap(f):
  """
  checks if there are any pairs of registers in f
  that can be swapped.
  """
  liveness_analysis(f.code)
  live_regs = get_reg_live_subsets(f.instrs, f.code, f.igraph)
  swaps = get_reg_swaps(live_regs)
  if len(swaps)>0:
    return True
  return False

def do_multiple_swaps(f, swaps, p=0.5):
  """
  Do (randomly selected) multiple swaps at once. Applies the 
  changes to instructions directly, and returns a list of changes 
  to bytes (as well as sets of bytes and instructions changed).
  """
  
  # if no swaps, do nothing
  if not swaps:
    return [], set(), set()
  
  # order swap by # instructions covered (descending)
  ord_swaps = deque(sorted(swaps, key=lambda x: x.size, reverse=True))
  
  # find groups of overlapping swaps (code from
  # swap.gen_swap_combinations)
  swap_groups = []
  group_i = 0
  if len(swaps) > 0:
    swap_groups.append([ord_swaps.popleft()])
  while len(ord_swaps) > 0:
    old_len = len(swap_groups[group_i])
    for i in range(len(ord_swaps)):
      swap = ord_swaps.popleft()
      if any([swap.overlap(o) for o in swap_groups[group_i]]):
        swap_groups[group_i].append(swap)
      else:
        ord_swaps.append(swap)
    if len(swap_groups[group_i]) == old_len:
      group_i += 1
      swap_groups.append([ord_swaps.popleft()])
  for swap_group in swap_groups:
    swap_group.sort(key=lambda swap: swap_to_key(swap), reverse=True)
    
  # for each group of overlapping swaps, pick
  # a random subset of swaps to perform
  diffs = []
  changed_bytes = set()
  changed_instrs = set()
  for i_g, group in enumerate(swap_groups):
    group = deque(group)
    while(len(group)>0):
      swap = group.popleft()
      if random.random()<1-p:
        continue
      success, changed = apply_swap_comb([swap])
      if success:
        # compute diff, update changed addresses+instrs, and apply changes
        diff = inp.get_diff(changed)
        diffs.extend(diff)
        changed_bytes.update((ea for ea, orig, curr in diff))
        changed_instrs.update(changed)
        for ins in changed:
          ins.apply_changes()
        # update the next swaps (renaming registers where needed)
        group_prev = group
        group = deque([])
        for swap2 in group_prev:
          bound_res = bound_comparison(swap, swap2)
          reg_res = reg_overlap(swap, swap2)
          if bound_res==0 or not reg_res:
            group.append(swap2)
          elif bound_res==1:
            if swap2.reg1.name==swap.reg1.name:
              swap2.reg1 = swap.reg2
            elif swap2.reg1.name==swap.reg2.name:
              swap2.reg1 = swap.reg1
            if swap2.reg2.name==swap.reg1.name:
              swap2.reg2 = swap.reg2
            elif swap2.reg2.name==swap.reg2.name:
              swap2.reg2 = swap.reg1
            group.append(swap2)
      else:
        # failure
        for ins in f.instrs:
          ins.reset_changed()
  
  # reset instruction changes
  for ins in f.instrs:
    ins.reset_changed()
  
  # done
  return diffs, changed_bytes, changed_instrs

def do_swap_canonicalization(f, swaps, pe_file):
  """
  Canonicalize instructions to the representation with the minimal 
  alphabetical order.
  """
  # if no swaps, do nothing
  if not swaps:
    return [], set(), set()
  
  # order swap by # instructions covered (descending)
  ord_swaps = deque(sorted(swaps, key=lambda x: x.size, reverse=True))
  
  # find groups of overlapping swaps (code from
  # swap.gen_swap_combinations)
  swap_groups = []
  group_i = 0
  if len(swaps) > 0:
    swap_groups.append([ord_swaps.popleft()])
  while len(ord_swaps) > 0:
    old_len = len(swap_groups[group_i])
    for i in range(len(ord_swaps)):
      swap = ord_swaps.popleft()
      if any([swap.overlap(o) for o in swap_groups[group_i]]):
        swap_groups[group_i].append(swap)
      else:
        ord_swaps.append(swap)
    if len(swap_groups[group_i]) == old_len:
      group_i += 1
      swap_groups.append([ord_swaps.popleft()])
  for swap_group in swap_groups:
    swap_group.sort(key=lambda swap: swap_to_key(swap), reverse=True)

  # for each group of overlapping swaps, pick the
  # swaps that would decrease the alphabetical order
  diffs = []
  changed_bytes = set()
  changed_instrs = set()
  for i_g, group in enumerate(swap_groups):
    group = deque(group)
    while(len(group)>0):
      swap = group.popleft()
      success, changed = apply_swap_comb([swap])
      if success:
        # compute diff
        diff = inp.get_diff(changed)
        # check if the diff decreases the alphabetical order
        earliest = min(diff, key=lambda x: x[0])
        if earliest[2]>earliest[1]:
          # the diff isn't good
          for ins in f.instrs:
            ins.reset_changed()
          continue
        # diff is good (decreases the order)
        diffs.extend(diff)
        changed_bytes.update((ea for ea, orig, curr in diff))
        changed_instrs.update(changed)
        for ins in changed:
          ins.apply_changes()
        # update the next swaps (renaming registers where needed)
        group_prev = group
        group = deque([])
        for swap2 in group_prev:
          bound_res = bound_comparison(swap, swap2)
          reg_res = reg_overlap(swap, swap2)
          if bound_res==0 or not reg_res:
            group.append(swap2)
          elif bound_res==1:
            if swap2.reg1.name==swap.reg1.name:
              swap2.reg1 = swap.reg2
            elif swap2.reg1.name==swap.reg2.name:
              swap2.reg1 = swap.reg1
            if swap2.reg2.name==swap.reg1.name:
              swap2.reg2 = swap.reg2
            elif swap2.reg2.name==swap.reg2.name:
              swap2.reg2 = swap.reg1
            group.append(swap2)
      else:
        # failure
        for ins in f.instrs:
          ins.reset_changed()
  
  # reset instruction changes
  for ins in f.instrs:
    ins.reset_changed()

  # apply diffs
  randtoolkit.patch(pe_file, None, diffs)
  
  # done
  return diffs, changed_bytes, changed_instrs

def do_single_swaps(swaps, gen_patched, all_diffs=None):
  """Applies one swap at a time and optionally generates the patched .dll.
  Returns a set of the linear addresses of the changed bytes."""

  changed_bytes = set()
  
  for i, swap in enumerate(swaps):
    success, changed = apply_swap_comb([swap])

    if success:
      diff = inp.get_diff(changed)
      if gen_patched:
        inp.patch(diff, "swap-%06d"%i)
      if all_diffs != None:
        all_diffs.append(diff)
      changed_bytes.update((ea for ea, orig, curr in diff))

    for ins in changed:
      ins.reset_changed()

  return changed_bytes


def gen_swap_combinations(swaps):
  """Generates all the possible swap combinations (entropy)."""

  # check 0x4A8297A0, icu
  from collections import deque

  ord_swaps = deque(sorted(swaps, key=lambda x: x.size, reverse=True))

  # categorize swaps in groups of overlapping ones
  swap_groups = []
  group_i = 0

  if len(swaps) > 0:
    swap_groups.append([ord_swaps.popleft()])

  while len(ord_swaps) > 0:

    old_len = len(swap_groups[group_i])

    for i in range(len(ord_swaps)):

      swap = ord_swaps.popleft()

      if any([swap.overlap(o) for o in swap_groups[group_i]]):
        swap_groups[group_i].append(swap)
      else:
        ord_swaps.append(swap)

    if len(swap_groups[group_i]) == old_len:
      group_i += 1
      swap_groups.append([ord_swaps.popleft()])

  comb_groups = []

  for group in swap_groups:
    #print(len(group), group)
    combs = [itertools.combinations(group, i) for i in xrange(len(group)+1)]
    #print(len(combs), combs)
    comb_groups.append(itertools.chain(*combs))
    #print(type((*comb_groups[0])[1]))

  for comb in itertools.product(*comb_groups):
    comb = filter(lambda x: x, itertools.chain(*comb))
    if len(comb) > 0:
      yield comb


# executes as an IDA python script
if __name__ == "__main__":
  import inp_ida
  import func

  # Find swappable registers in the function under the cursor
  ida_func = idaapi.get_func(ScreenEA())
  if not ida_func:
    print "error: cursor is not under a function.."
  else:
    func_ea = ida_func.startEA
    print "\nAnalyzing function starting at %X" % func_ea
    code, blocks = inp_ida.get_code_and_blocks(func_ea)
    f = func.Function(func_ea, code, blocks, set(), set())
    # treat as unclassified 
    f.update_calls()
    f.analyze_registers({})
    f.update_returns(set_default=True)

    print f

    for ins in f.instrs:
      print "%-40s R: %-12s W: %-12s I: %s" % (str(ins), 
            ','.join(ins.USE), ','.join(ins.DEF), ','.join(ins.implicit))

    print "\nRunning liveness analysis"
    liveness_analysis(f.code)

    for ins in f.instrs:
      print "%-40s IN: %-20s OUT: %-20s" % (str(ins), 
            ','.join(ins.IN), ','.join(ins.OUT))

    print "\nComputing the live instruction subsets of the registers"
    live_regs = get_reg_live_subsets(f.instrs, f.code, f.igraph)

    for reg in live_regs.itervalues():
      print reg

    print "\nTrying to split some of the subsets"
    split_reg_live_subsets(live_regs, code)

    for reg in live_regs.itervalues():
      print reg 

    print "\nComputing the possible register swaps"
    swaps = get_reg_swaps(live_regs)
    for i, swap in enumerate(swaps):
      print i, swap 

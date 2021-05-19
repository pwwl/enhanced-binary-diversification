#!/usr/bin/env python

# Copyright (c) 2012, Vasilis Pappas <vpappas@cs.columbia.edu>
# This file is part of Orp http://nsl.cs.columbia.edu/projects/orp

# Additionally modified by Mahmood Sharif <mahmoods@alumni.cmu.edu>
# Alternate contact is Keane Lucas <keanelucas@cmu.edu>

import itertools
import pydasm
import insn
import inp
import disp
import pefile
from bbl import BasicBlock
import randtoolkit

from pygraph.classes.digraph import digraph

from collections import deque

import random

def BuildBBDependenceDAG(bb):
  """Computes the dependence graph of a basic block."""

  # See Section 9.2 (algorithm in Figure 9.6) of Muchnick's
  # Advanced Compiler Design and Implementation

  dependence_graph = digraph()

  # Maintain reachability information to avoid costly graph traversals
  reachable_fwd = {}
  reachable_bkwd = {}

  for j in bb.instrs:
    #print "\n",j, j.op2.type
    dependence_graph.add_node(j)
    conflict = set()

    # Find which of the instructions already in the DAG conflict with j.
    # Check instructions in reverse order to eliminate redundand dependencies
    for k in reversed(bb.instrs[:bb.instrs.index(j)]):
      dependency = Conflict(k, j)
      #print "dependency", k, '->', j, ':', dependency
      if not dependency:
        continue
      # If there is a path from k to one of the instructions already in
      # dependence with j in the current DAG, then k -> j is redundant
      if reachable_fwd.get(k, set()).intersection(conflict):
        continue
      conflict.add(k)

      dependence_graph.add_edge((k, j))   # Add an edge for this conflict

      # Update reachability information
      reachable_fwd.setdefault(k, set()).add(j)
      reachable_bkwd.setdefault(j, set()).add(k)
      # j is also reachable from all the ancestors of k
      for v in reachable_bkwd.get(k, []):
        reachable_fwd[v].add(j)
      # j can also reach backwards all the ancestors of k
      reachable_bkwd.setdefault(j, set()).update(reachable_bkwd.get(k, []))

  return dependence_graph


UNMOVABLE = [
  # branches
  pydasm.INSTRUCTION_TYPE_JMPC,
  pydasm.INSTRUCTION_TYPE_JECXZ,
  pydasm.INSTRUCTION_TYPE_JMP,
  pydasm.INSTRUCTION_TYPE_LOOP,
  pydasm.INSTRUCTION_TYPE_CALL,
  pydasm.INSTRUCTION_TYPE_RET,
  # other
  pydasm.INSTRUCTION_TYPE_OTHER, # TODO overly restrictive, could relax it
  # TODO think about what else should go in here
]

# Avoid moving FPU instructions, as their effects aren't properly checked
UNMOVABLE += list(range(pydasm.INSTRUCTION_TYPE_FCMOVC, pydasm.INSTRUCTION_TYPE_FPU+1)) 

def Conflict(i1, i2):
  """Returns True if i1 must precede i2 for correct execution."""

  # If we cannot figure out any dependency, assume that there is a conflict
  res = 'DEFAULT_CONFLICT'
  found_RAW = True
  found_WAR = True
  found_WAW = True
  
  if i1.type in UNMOVABLE or i2.type in UNMOVABLE:
    return res

  # displaced instructions cannot be moved
  if disp._is_displaced(i1) or disp._is_displaced(i2):
    return True

  # We assume all memory operands reference unique addresses
  # (be very conservative for now - TODO: could relax this)

  # RAW: i1 writes a register/address/flag used by i2
  if not i1.DEF.isdisjoint(i2.USE):
    # i1 writes a register read by i2
    return ('RAW', i1.DEF.intersection(i2.USE).pop()) # TODO assert only one reg
  if ((i1.op1.type == insn.Operand.MEMORY or
       i1.type == pydasm.INSTRUCTION_TYPE_PUSH or
       i1.type == pydasm.INSTRUCTION_TYPE_STOS) and
      (i2.op2.type == insn.Operand.MEMORY or
       i2.type == pydasm.INSTRUCTION_TYPE_POP) and
      i2.type != pydasm.INSTRUCTION_TYPE_LEA): # not an actual memory access
    # i1 writes an address read by i2
    return ('RAW', 'MEM')
  if i1.eflags_w & i2.eflags_r:
    # i1 writes at least one flag read by i2
    return ('RAW', 'EFLAGS')
  found_RAW = False

  # WAR: i1 reads a register/address/flag overwritten by i2
  if not i1.USE.isdisjoint(i2.DEF):
    # i1 reads a register written by i2
    return ('WAR', i1.USE.intersection(i2.DEF).pop())
  if ((i1.op2.type == insn.Operand.MEMORY or
       i1.type == pydasm.INSTRUCTION_TYPE_POP) and
      i1.type != pydasm.INSTRUCTION_TYPE_LEA and # not an actual memory access
      (i2.op1.type == insn.Operand.MEMORY or
       i2.type == pydasm.INSTRUCTION_TYPE_PUSH or
       i2.type == pydasm.INSTRUCTION_TYPE_STOS)):
    # i1 reads an address written by i2
    return ('WAR', 'MEM')
  if i1.eflags_r & i2.eflags_w:
    # i1 reads at least one flag written by i2
    return ('WAR', 'EFLAGS')
  found_WAR = False

  # WAW: i1 and i2 both write the same register/address/flag
  if not i1.DEF.isdisjoint(i2.DEF):
    # i1 and i2 both write the same register
    return ('WAW', i1.DEF.intersection(i2.DEF).pop())
  if ((i1.op1.type == insn.Operand.MEMORY or
       i1.type == pydasm.INSTRUCTION_TYPE_PUSH or
       i1.type == pydasm.INSTRUCTION_TYPE_STOS) and
      (i2.op1.type == insn.Operand.MEMORY or
       i2.type == pydasm.INSTRUCTION_TYPE_PUSH or
       i2.type == pydasm.INSTRUCTION_TYPE_STOS)):
    # i1 and i2 both write the same address
    return ('WAW', 'MEM')
  if i1.eflags_w & i2.eflags_w:
    # i1 and i2 both write the same flag(s)
    return ('WAW', 'EFLAGS')
  found_WAW = False

  if not found_RAW and not found_WAR and not found_WAW:
    return None   # No dependency found

  return res


def ReorderGraph(dag):
  """Computes a topological sorting of the input graph. The resulting ordering
  has the highest hamming distance possible copmared to the original ordering.
  CAUTION: destroys the input DAG."""
  # based on http://en.wikipedia.org/wiki/Topological_ordering#Algorithms

  if not dag.edges():
    return []

  ordering = []
  edge_srcs, edge_dsts = zip(*dag.edges())    # unzip list of edge tuples
  roots = set(edge_srcs) - set(edge_dsts)
  # Include any unconnected vertices
  roots.update(set(dag.nodes()) - set(itertools.chain(*dag.edges())))

  while roots:
    # If possible, pick an instruction that will increase the hamming distance
    # of the resulting ordering compared to the original instruction sequence
    n = max(roots, key=lambda i: i.pos) # the farthest instr - greedy choice
    roots.remove(n)
    ordering.append(n)
    for m in dag.node_neighbors[n][:]:  # copy list (modified in the loop)
      dag.del_edge((n, m))
      if not dag.node_incidence[m]:
        roots.add(m)

  assert dag.edges() == []
  return ordering

def ReorderGraphRandomly(dag):
  """
  Randomly reorder the instructions in the graph. Works iteratively:
  in each iteration we have a set of nodes that do not depend on others
  (i.e., without incoming edges); we remove a random node, and if any
  nodes it connected to become independent (i.e., they don't have any
  incoming edges), we add them to the set.
  """

  if not dag.edges():
    nodes = list(dag.nodes())
    random.shuffle(nodes)
    return nodes

  ordering = []
  edge_srcs, edge_dsts = zip(*dag.edges())    # unzip list of edge tuples
  roots = set(edge_srcs) - set(edge_dsts)
  roots.update(set(dag.nodes()) - set(itertools.chain(*dag.edges()))) # Include any unconnected vertices
  #roots = [n for n in dag.nodes() if not n in edge_dsts]

  # randomize order
  roots = deque(roots)
  random.shuffle(roots)

  while roots:
    # extract a random node from roots
    n = roots.popleft()
    ordering.append(n)
    for m in dag.node_neighbors[n][:]:  # copy list (modified in the loop)
      dag.del_edge((n, m))
      if not dag.node_incidence[m]:
        roots.append(m)
    random.shuffle(roots) # randomize order again

  assert dag.edges() == []
  return ordering

def ReorderGraphMinOrder(dag):
  """
  Reorder the graph such that we end up with the one with the
  minimal alphabetical order, while respecting the dependencies
  """

  if not dag.edges():
    nodes = list(dag.nodes())
    nodes.sort(key=lambda ins: ins.bytes)
    return nodes
  
  ordering = []
  edge_srcs, edge_dsts = zip(*dag.edges())    # unzip list of edge tuples
  roots = set(edge_srcs) - set(edge_dsts)
  roots.update(set(dag.nodes()) - set(itertools.chain(*dag.edges()))) # Include any unconnected vertices
  
  # sort to minimize alph. rep
  roots = list(roots)
  roots.sort(key=lambda ins: ins.bytes) 

  while roots:
    # extract a random node from roots
    n = roots[0]
    roots = roots[1:]
    ordering.append(n)
    for m in dag.node_neighbors[n][:]:  # copy list (modified in the loop)
      dag.del_edge((n, m))
      if not dag.node_incidence[m]:
        roots.append(m)
    roots.sort(key=lambda ins: ins.bytes) # sort to minimize alph. order again

  assert dag.edges() == []
  return ordering

def causes_reloc_diff(rinstrs, pe, relocations):
  """
  Checks if relocating the instruction leads to a change in
  the reloc section. These cannot be handled well by this tool,
  it seems. Based on 'inp.get_reloc_diff()'.
  """
  base = pe.OPTIONAL_HEADER.ImageBase
  # now check if we reordered any relocatable data
  for rins in filter(lambda x: x.inst_len >= 5, rinstrs):
    for rva in xrange(rins.addr - base + 1, rins.addr - base + rins.inst_len - 3):
      if rva in relocations:
        return True
  return False

#_xxxprev = None
_xxxrelocations = None
_xxxlastfile = 0
def get_relocations(pe, use_caching=True):
  # relocations have always been constant for >30 execution iterations
  # on a file
  
  global _xxxrelocations
  global _xxxlastfile
  if use_caching and _xxxlastfile == id(pe):
    relocations = _xxxrelocations
  else:

    pe.parse_data_directories(directories=[ 
              pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']])
    relocations = {}
    if pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size > 0 and \
      hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
      for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
        for reloc in filter(lambda x: x.type == 3, base_reloc.entries):  #HIGHLOW
          relocations[reloc.rva] = reloc.struct.get_file_offset()
    _xxxrelocations = relocations
    _xxxlastfile = id(pe)
    #nreloc = len(relocations)
    #print "relocations: %d" % (nreloc)
    #global _xxxprev
    #if (_xxxprev is not None and _xxxprev != relocations):
    #  print "different"
    #else:
    #  print "same"
    #_xxxprev = relocations
  return relocations

def can_reorder(f):
  """
  checks whether there are instructions in f that can
  be reordered
  """
  for block in f.blocks:
    dag = BuildBBDependenceDAG(block)
    
    if not dag.edges() and len(list(dag.nodes()))>0:
      return True

    edge_srcs, edge_dsts = zip(*dag.edges())
    roots = set(edge_srcs) - set(edge_dsts)
    roots.update(set(dag.nodes()) - set(itertools.chain(*dag.edges()))) 
    roots = deque(roots)

    while roots:
      if len(roots)>1:
        return True
      n = roots.popleft()
      for m in dag.node_neighbors[n][:]:  # copy list (modified in the loop)
        dag.del_edge((n, m))
        if not dag.node_incidence[m]:
          roots.append(m)
  
  del dag
  return False

# _xxxrelocations = None
# _xxxlastfile = 0
def do_random_reordering(f, pe_file):
  """
  Reorder function f's instructions randomly, in a way that maintains
  the dependencies in the cfg. Returns the byte diffs and the set of 
  changed bytes, and applies the reordering to the internal representation 
  of the binary.
  """
  diffs = []
  reordered = []

  # global _xxxrelocations
  # global _xxxlastfile
  # if _xxxlastfile != id(pe_file):
  #   _xxxlastfile = id(pe_file)
  #   _xxxrelocations = get_relocations(pe_file)
  # relocations = _xxxrelocations
  relocations = get_relocations(pe_file)

  for i_b, block in enumerate(f.blocks):

    # build dag and reorder instructions
    dag = BuildBBDependenceDAG(block)
    block.rinstrs = ReorderGraphRandomly(dag)
    del dag
    min_pos = block.instrs[0].pos
    #min_pos = min(block.instrs, lambda x: x.pos)

    # update the address of reordered instrs
    order_changed = False
    reloc_diff = False
    for i, rins in enumerate(block.rinstrs):    
      if i == 0:
        rins.raddr = block.begin
      else:
        rins.raddr = block.rinstrs[i-1].raddr + len(block.rinstrs[i-1].bytes)
      
      if rins.raddr != rins.addr:
        order_changed = True
        if rins.inst_len>4 and causes_reloc_diff([rins], pe_file, relocations):
          reloc_diff = True

    if order_changed and not reloc_diff:
      # update byte diffs
      diff = inp.get_block_diff(block)
      diffs.extend(diff)
      # update Entry/Exist fields
      if block.type & BasicBlock.ENTRY:
        block.rinstrs[0].f_entry = True
      if block.type & BasicBlock.EXIT:
        block.rinstrs[-1].f_exit = True
      for rins in block.rinstrs[1:-1]:
        rins.f_entry = False
        rins.f_exit = False
      # update instrs
      block.instrs = block.rinstrs
      for i, ins in enumerate(block.instrs):
        # update addr & pos
        ins.addr = ins.raddr
        if min_pos!=-1:
          ins.pos = i+min_pos
        # update succ
        if ins.succ:
          if i!=len(block.instrs)-1:
            # not the last intruction in the block
            ins.succ = set([ins.addr+len(ins.bytes)])
          else:
            # last instruction in the block
            ins.succ = set()
            for other in block.successors:
              ins.succ.add(other.begin)
    elif reloc_diff:
      block.rinstrs = block.instrs
      for ins in block.instrs:
        ins.raddr = ins.addr

  changed_bytes = set([ea for ea, orig, curr in diffs])

  # done
  return diffs, changed_bytes

def do_reorder_canonicalization(f, pe_file):
  """
  Canonicalize instructions to the representation with the minimal 
  alphabetical order.
  """
  diffs = []
  reordered = []

  # global _xxxrelocations
  # global _xxxlastfile
  # if _xxxlastfile != id(pe_file):
  #   _xxxlastfile = id(pe_file)
  #   _xxxrelocations = get_relocations(pe_file)
  # relocations = _xxxrelocations
  relocations = get_relocations(pe_file)

  for i_b, block in enumerate(f.blocks):
    
    # build dag and reorder instructions
    dag = BuildBBDependenceDAG(block)
    block.rinstrs = ReorderGraphMinOrder(dag)
    del dag
    min_pos = block.instrs[0].pos
    #min_pos = min(block.instrs, lambda x: x.pos)

    # update the address of reordered instrs
    order_changed = False
    reloc_diff = False
    for i, rins in enumerate(block.rinstrs):    
      if i == 0:
        rins.raddr = block.begin
      else:
        rins.raddr = block.rinstrs[i-1].raddr + len(block.rinstrs[i-1].bytes)
      
      if rins.raddr != rins.addr:
        order_changed = True
        if rins.inst_len>4 and causes_reloc_diff([rins], pe_file, relocations):
          reloc_diff = True

    if order_changed and not reloc_diff:
      # update byte diffs and patch the pe
      diff = inp.get_block_diff(block)
      randtoolkit.patch(pe_file, None, diff)
      diffs.extend(diff)
      # update Entry/Exist fields
      if block.type & BasicBlock.ENTRY:
        block.rinstrs[0].f_entry = True
      if block.type & BasicBlock.EXIT:
        block.rinstrs[-1].f_exit = True
      for rins in block.rinstrs[1:-1]:
        rins.f_entry = False
        rins.f_exit = False
      # update instrs
      block.instrs = block.rinstrs
      for i, ins in enumerate(block.instrs):
        # update addr & pos
        ins.addr = ins.raddr
        if min_pos!=-1:
          ins.pos = i+min_pos
        # update succ
        if ins.succ:
          if i!=len(block.instrs)-1:
            # not the last intruction in the block
            ins.succ = set([ins.addr+len(ins.bytes)])
          else:
            # last instruction in the block
            ins.succ = set()
            for other in block.successors:
              ins.succ.add(other.begin)
    elif reloc_diff:
      block.rinstrs = block.instrs
      for ins in block.instrs:
        ins.raddr = ins.addr

  changed_bytes = set([ea for ea, orig, curr in diffs])

  # done
  return diffs, changed_bytes

def do_reordering(blocks, gen_patched, all_diffs=None):
  """Reorders the instructions within the given blocks and optionally generates
  instances of the input file with these instructions reordered. Returns the
  changed bytes set (coverage evaluation)."""

  reordered = []
  changed_bytes = set()
  diff = []
  
  for block in blocks:

    dag = BuildBBDependenceDAG(block)
    block.rinstrs = ReorderGraph(dag)
    del dag

    # update the address of reordered instrs
    for i, rins in enumerate(block.rinstrs):

      if i == 0:
        rins.raddr = block.begin
      else:
        rins.raddr = block.rinstrs[i-1].raddr + len(block.rinstrs[i-1].bytes)

      if rins.raddr != rins.addr and rins.inst_len > 4:
        reordered.append(rins)

    diff.extend(inp.get_block_diff(block))
  
  reloc_diff = inp.get_reloc_diff(reordered)
  
  if gen_patched:
    inp.patch(diff+reloc_diff, "reorder")

  if all_diffs != None and len(reloc_diff) == 0:
    all_diffs.append(diff+reloc_diff)

  changed_bytes.update((ea for ea, orig, curr in diff))

  return changed_bytes


def gen_topological_sortings(block):
  """Tries to generate all the possible reorderings. Kills the loop after it
  reaches a threshold.. (entropy evaluation)."""

  # Varol and Rotem's algorithm from '79 
  # http://comjnl.oxfordjournals.org/content/24/1/83.full.pdf+html

  dag = BuildBBDependenceDAG(block)

  #util.draw_graph(dag, "reorder-dag.eps")

  R = set(dag.edges())
  P = ReorderGraph(dag)
  del dag
  N = len(P)
  LOC = range(N)

  yield P
  i = 0

  # huge or infinite loop detection
  loop_cnt = topsort_cnt = 0

  while i < N:

    K = LOC[i]

    if K+1 < N and (P[K], P[K+1]) not in R:
      P[K], P[K+1] = P[K+1], P[K]
      LOC[i] = LOC[i] + 1
      i = 0
      yield P[:]
      topsort_cnt += 1
    else:
      P.insert(i, P.pop(LOC[i]))
      LOC[i] = i
      i = i + 1

    loop_cnt += 1

    if loop_cnt > 1000:
      #print "killing topol. sort after 1000 loops (%d topsorts)" % topsort_cnt
      break


# executes as an IDA python script
if __name__ == "__main__":
  import inp_ida
  import func
  import util 

  # Reorder the instructions in the basic block under the cursor
  ida_func = idaapi.get_func(ScreenEA())
  if not ida_func:
    print "error: cursor is not under a function.."
  else:
    func_ea = ida_func.startEA
    code, blocks = inp_ida.get_code_and_blocks(func_ea)
    f = func.Function(func_ea, code, blocks, set(), set())
    for bb in f.blocks:
      if bb.begin <= ScreenEA() < bb.end:
        print "\nBuilding the DAG for the basic block %X:%X"%(bb.begin, bb.end)
        dag = BuildBBDependenceDAG(bb)
        # uncomment to draw the DAG (needs dot from graphviz)
        #util.draw_graph(dag, "dag.eps")
        for ins in ReorderGraph(dag):
          print ins
        break
        del dag
    else:
      print "could not find the basic block .."

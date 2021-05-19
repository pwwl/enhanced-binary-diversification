#!/usr/bin/env python

# Copyright (c) 2012, Vasilis Pappas <vpappas@cs.columbia.edu>
# This file is part of Orp http://nsl.cs.columbia.edu/projects/orp

# Additionally modified by Mahmood Sharif <mahmoods@alumni.cmu.edu>
# Alternate contact is Keane Lucas <keanelucas@cmu.edu>

import time
import pickle
import optparse
import itertools
import sys

import inp
import func
import gadget

import swap
import preserv
import equiv
import reorder

import numpy as np


def _dump(filename, data):
  print "+ dumping", filename
  with open(filename, "wb") as f:
    pickle.dump(data, f)


def get_changed_bytes(functions):
  """Applies all the randomizations on each function and returns the
  superset of the changed bytes for each technique (coverage)."""

  swap_b, preserv_b, equiv_b, reorder_b = set(), set(), set(), set()

  for f in filter(lambda x: x.level != -1, functions.itervalues()):

    # swap
    swap.liveness_analysis(f.code)
    live_regs = swap.get_reg_live_subsets(f.instrs, f.code, f.igraph)
    swap.split_reg_live_subsets(live_regs, f.code)
    swaps = swap.get_reg_swaps(live_regs)
    swap_b |= swap.do_single_swaps(swaps, gen_patched=False)

    # preserv
    preservs, avail_regs = preserv.get_reg_preservations(f)
    preserv_b |= preserv.do_reg_preservs(f.instrs, f.blocks, preservs,
                                         avail_regs, gen_patched=False)

    # equiv
    equiv_b |= equiv.do_equiv_instrs(f.instrs, gen_patched=False)

    # reorder
    reorder_b |= reorder.do_reordering(f.blocks, gen_patched=False)

  return swap_b, preserv_b, equiv_b, reorder_b


def eval_coverage(input_file, dump_eval_data=False):
  """Evaluates the effectiveness of the randomization techniques in
  breaking/eliminating gadgets (coverage)."""

  def _check_gadget(g, changed, ins_hit):
    """Checks if the given gadget was broken by these changed bytes. In addition,
    it keeps track of which of the gadget instructions where changed. Returns
    True, if the gadget was broken, False otherwise."""

    broke = False

    for i_start, i_end in zip(g.addrs, g.addrs[1:]+[g.end]):
      if any(b in changed for b in xrange(i_start, i_end)):
        ins_hit.add(i_start)
        broke = True

    return broke

  start_time = time.time()

  # get the changed byte sets
  functions = inp.get_functions(input_file)
  levels = func.classify_functions(functions)
  func.analyze_functions(functions, levels)
  swap_b, preserv_b, equiv_b, reorder_b = get_changed_bytes(functions)

  # get the gadgets
  gadgets = gadget.get_simple_gadgets(input_file)

  # initialize output vars
  unchanged = set()
  eliminated = set()
  swapped = set()
  preserved = set()
  equived = set()
  reordered = set()
  ins_hit = set()
  ins_hit_data = {2: [0]*3, 3: [0]*4, 4: [0]*5, 5: [0]*6}

  # check each gadget one by one to see which were broken/eliminated etc
  for g in gadgets:

    ins_hit.clear()
    broke_this_g = False

    # check if the gadget is broken
    if _check_gadget(g, swap_b, ins_hit):
      swapped.add(g)
      broke_this_g = True
    if _check_gadget(g, preserv_b, ins_hit):
      preserved.add(g)
      broke_this_g = True
    if g.overlap and _check_gadget(g, equiv_b, ins_hit):
      equived.add(g)
      broke_this_g = True
    if g.overlap and _check_gadget(g, reorder_b, ins_hit):
      reordered.add(g)
      broke_this_g = True
    elif not g.overlap and g.func_ea and g.func_ea in functions:
      # XXX: it's extremely difficult to find cases where gadgets will be broke
      # this way because the gadget extraction algorithm usualy stops on jumps,
      # which are the baseic block boarders. So, most non-overlapping gadgets
      # are whole BBs.
      f = functions[g.func_ea]
      for ins in (f.code[a] for a in xrange(g.start, g.end) if a in f.code):
        if ins.addr != ins.raddr and ins.raddr < g.start or ins.raddr > g.end:
          reordered.add(g)
          broke_this_g = True
          break

    # one of the few :)
    if not broke_this_g:
      unchanged.add(g)

    # if any of the gadget's instruction was changed
    if len(ins_hit) > 0:
      # update the gadget isntruction hit histogram
      for i in ins_hit:
        ins_hit_data[len(g.addrs)][g.addrs.index(i)] += 1
      ins_hit_data[len(g.addrs)][-1] += 1
      # check if the gadget was elliminated!
      if g.addrs[-1] in ins_hit and ((g.addrs[-1] in swap_b or
          g.addrs[-1] in preserv_b) or (g.overlap and (
          g.addrs[-1] in equiv_b or g.addrs[-1] in reorder_b))):
        eliminated.add(g)

  # output the evaluation data..
  print "--------------------------- done -------------------------------"

  c_len = float(len(swap_b|preserv_b|equiv_b|reorder_b))
  print "total changed bytes: %d" % c_len
  print "  swap: %d (%.1f%%)" % (len(swap_b), 100*len(swap_b)/c_len)
  print "  preserv: %d (%.1f%%)" % (len(preserv_b), 100*len(preserv_b)/c_len)
  print "  equiv: %d (%.1f%%)" % (len(equiv_b), 100*len(equiv_b)/c_len)
  print "  reorder: %d (%.1f%%)" % (len(reorder_b), 100*len(reorder_b)/c_len)
  
  print "total gadgets: %d" % len(gadgets)

  if len(gadgets) > 0:

    print "  instructions hit within gadgets (last column is the total):"
    for k, v in ins_hit_data.iteritems():
      print "    glen%d:" % k, ' '.join([str(c) for c in v])

    reds = set((g for g in gadgets if g.red))

    r_len = len(reds)
    g_len = float(len(gadgets))
    print "  red: %d (%.1f%%)" % (r_len, 100*r_len/g_len)

    gr_len = float(len(gadgets - reds))
    u_len = len(unchanged)
    ur_len = float(len(unchanged - reds))
    print "  unchanged: %d (%.1f%%) - no red: %d (%.1f%%)" % (
          u_len, 100*u_len/g_len, ur_len, 100*ur_len/gr_len)

    e_len = len(eliminated)
    print "  eliminated: %d (%.1f%%) - no red: %.1f%%" % (
          e_len, 100*e_len/g_len, 100*e_len/gr_len)

    b_len = len(gadgets - unchanged)
    print "  broken: %d (%.1f%%) - no red: %.1f%%" % (
          b_len, 100*b_len/g_len, 100*b_len/gr_len)

    s_len = len(swapped)
    print "    swap: %d (%.1f%%) - no red: %.1f%%" % (
          s_len, 100*s_len/g_len, 100*s_len/gr_len)

    p_len = len(preserved)
    print "    preserv: %d (%.1f%%) - no red: %.1f%%" % (
          p_len, 100*p_len/g_len, 100*p_len/gr_len)

    q_len = len(equived)
    print "    equiv: %d (%.1f%%) - no red: %.1f%%" % (
          q_len, 100*q_len/g_len, 100*q_len/gr_len)

    o_len = len(reordered)
    print "    reorder: %d (%.1f%%) - no red: %.1f%%" % (
          o_len, 100*o_len/g_len, 100*o_len/gr_len)

    avg_g_blen = sum((g.end-g.start for g in gadgets)) / g_len
    avg_ur_blen = sum((g.end-g.start for g in unchanged-reds)) / ur_len
    print "  avg size (bytes): %.2f - unchanged (no red): %.2f" % (
          avg_g_blen, avg_ur_blen)

    avg_g_ilen = sum((g.ins_num for g in gadgets)) / g_len
    avg_ur_ilen = sum((g.ins_num for g in unchanged-reds)) / ur_len
    print "  avg size (insns): %.2f - unchanged (no red): %.2f" % (
          avg_g_ilen, avg_ur_ilen)

  print "evaluation took", int(time.time()-start_time), "seconds"

  if dump_eval_data:
    _dump(input_file + ".changed_bytes_swap", swap_b)
    _dump(input_file + ".changed_bytes_preserv", preserv_b)
    _dump(input_file + ".changed_bytes_equiv", equiv_b)
    _dump(input_file + ".changed_bytes_reorder", reorder_b)

    _dump(input_file + ".gadgets_unchanged", unchanged)
    _dump(input_file + ".gadgets_swapped", swapped)
    _dump(input_file + ".gadgets_preserved", preserved)
    _dump(input_file + ".gadgets_equived", equived)
    _dump(input_file + ".gadgets_reordered", reordered)

  #sanity checks
  if swapped|preserved|equived|reordered != gadgets-unchanged:
    print "BUG: gadget sets check failed!!"


def get_func_entropy(f, live_regs, swaps, preservs, avail_regs):
  """Given a function, return the number of ways that it can be rewritten."""
  
  entropy = 0
  
  # 1. swaps
  swap_diffs = set()
  # XXX use only at most 10 swaps here .. otherwise it takes forever
  for i, swap_comb in enumerate(swap.gen_swap_combinations(swaps[:10])):
    success, changed = swap.apply_swap_comb(swap_comb)
    if not success:
      continue
    diff = inp.get_diff(changed)
    for ins in changed:
      ins.reset_changed()
    if i > 1000:
      #print "killing after 1000 swap combinations"
      break

  entropy += np.log(len(swap_diffs) + 1)/np.log(2)

  #print "\tswaps:", len(swap_diffs) 

  # 2. preservs
  preserv_diffs = set()

  # 2.1 global substitution
  implicit = reduce(lambda x, y: x | y, [i.implicit for i in f.instrs if not i.f_exit], set())
  preserv_regs = [reg for reg, pushes, pops in preservs if reg not in implicit]
  preserv_combs = []

  if len(preserv_regs) >= 2:
    preserv_combs.extend(itertools.combinations(preserv_regs, 2))

  preserv_combs.extend(itertools.product(preserv_regs, avail_regs))

  for r1, r2 in preserv_combs:
    for ins in f.instrs:
      if not ins.swap_registers(r1, r2):
        break
    else:
      diff = inp.get_diff(f.instrs)
      preserv_diffs.add(tuple(d for d in diff))
    for ins in f.instrs:
      ins.reset_changed()

  # 2.2 reorder pushes/pops
  # XXX: a preserved register is used only after it's pushed!
  #      and only before it's poped!
  # augment each ins in the preservs with blocks and find first/last
  preserv_blocks = set()

  for reg, pushes, pops in preservs:
    for ins in itertools.chain(pushes, pops):
      ins.block = next((b for b in f.blocks if ins in b.instrs), None)
      if not hasattr(ins.block, 'first'):
        ins.block.first = ins.block.instrs.index(ins)
        ins.block.last = ins.block.instrs.index(ins)
      else:
        ins.block.first = min(ins.block.first, ins.block.instrs.index(ins))
        ins.block.last = max(ins.block.last, ins.block.instrs.index(ins))
      preserv_blocks.add(ins.block)

  # group preservs in the same block and reorder them
  preservs_groups = []

  for reg, pushes, pops in preservs:
    if len(preservs_groups) == 0:
      preservs_groups.append([(reg, pushes, pops)])
      continue
    for group in preservs_groups:
      if (all(p1.block == p2.block for p1, p2 in zip(group[0][1], pushes)) and
          all(p1.block == p2.block for p1, p2 in zip(group[0][2], pops))):
        group.append((reg, pushes, pops))
        break
      else:
        preservs_groups.append([(reg, pushes, pops)])

  # do reorder of pushes/pops
  for group in (g for g in preservs_groups if len(g) > 1):
    for group_perm in itertools.permutations(group):
      for block in preserv_blocks:
        block.rinstrs = block.instrs[:]
        block.curr_first = block.first
        block.curr_last = block.last
      for reg, pushes, pops in group:
        for push in pushes:
          push.block.rinstrs.remove(push)
          push.block.rinstrs.insert(push.block.curr_first, push)
          push.block.curr_first += 1
        for pop in reversed(pops):
          pop.block.rinstrs.remove(pop)
          pop.block.rinstrs.insert(pop.block.curr_last-1, pop)
          pop.block.curr_last -= 1
      diff = set()
      for block in preserv_blocks:
        diff.update(inp.get_block_diff(block))
      preserv_diffs.add(tuple(d for d in diff))

  entropy += np.log(len(preserv_diffs) + 1)/np.log(2)

  #print "\tpreservs:", len(preserv_diffs) 
  
  # 3. equiv
  equiv_instrs = []

  for ins in f.instrs:
    try:
      has_equiv = (not ins.irreplaceable) and equiv.check_equiv(ins)
    except:
      has_equiv = False
    if has_equiv:
      diff = inp.get_diff([ins])
      equiv_instrs.append(ins)
      ins.reset_changed()

  #sr_equiv = [i for i in equiv_instrs if i.bytes[i.opc_off] in objs.same_regs]
  #entropy *= 2**(len(equiv_instrs)-len(sr_equiv))
  #entropy *= 5**len(sr_equiv)
  entropy += len(equiv_instrs)

  #print "\tequiv (instrs):", len(equiv_instrs), "(%d sr_equiv)" % len(sr_equiv)

  # 4. reorder
  reorder_diffs = set()

  # find the block(s) of the gadget
  for block in f.blocks:
    for order in reorder.gen_topological_sortings(block):
      block.rinstrs = order
      diff = inp.get_block_diff(block)
      reorder_diffs.add(tuple(d for d in diff))
  
  entropy += np.log(len(reorder_diffs) + 1)/np.log(2)
  
  #print "\treorder:", len(reorder_diffs)

  # done
  #print "\tentropy:", entropy

  return entropy



def eval_exploit(input_file, dump_eval_data=False):
  """Evaluates a single exploit and checks whether it is prevented. If so,
  it also calulated the number of different permutations that break it
  (entropy)."""

  start_time = time.time()

  # load and analyze the input file
  functions = inp.get_functions(input_file)
  levels = func.classify_functions(functions)
  func.analyze_functions(functions, levels)

  # get the gadgets
  try:
    gadgets = gadget.get_payload_gadgets(input_file)
  except Exception, e:
    print "ERROR: Could not open payload file"
    print e
    sys.exit(1)

  # initialize output vars
  gadgets_hit = set()
  func_gads = {}
  expl_entropy = 1
  elim_gadgets = brk_gadgets = 0
  color = {True : "red", False : "blue"}
  overlap = {True : ",overlap", False : ""}

  # group the gadgets based on the function they belong
  for g in gadgets:
    if g.func_ea not in func_gads:
      func_gads[g.func_ea] = []
    func_gads[g.func_ea].append(g)

  for func_ea, gadgets in func_gads.iteritems():
    #there is nothing we can do ..
    if func_ea == None:
      continue

    f = functions[func_ea]

    # do analysis!
    swap.liveness_analysis(f.code)
    live_regs = swap.get_reg_live_subsets(f.instrs, f.code, f.igraph)
    swap.split_reg_live_subsets(live_regs, f.code)
    swaps = swap.get_reg_swaps(live_regs)
    preservs, avail_regs = preserv.get_reg_preservations(f)

    for g in gadgets:

      print "0x%08x (%s%s) # %s" % (g.start,
            color[g.red], overlap[g.overlap], g.string)

      if g.red:
        continue

      if g.func_ea != g.end_func_ea:
        print "gadget spans in two or more functions!"

      entropy, eliminated = get_entropy(f, g, live_regs, swaps, preservs, avail_regs)

      expl_entropy *= entropy

      if entropy > 1:
        brk_gadgets += 1
        gadgets_hit.add(g)

      if eliminated:
        elim_gadgets += 1

  print "all:", len(gadgets), "eliminated:", elim_gadgets, "broken:", brk_gadgets
  print "payload entropy:", expl_entropy

  print "evaluation took", int(time.time()-start_time), "seconds"

  if dump_eval_data:
    _dump(input_file + ".gadgets_hit", gadgets_hit)


if __name__ == "__main__":

  parser = optparse.OptionParser("usage: %prog -ec input_file")
  
  parser.add_option("-c", "--coverage", dest="coverage",
                    action="store_true", default=False,
                    help="evaluate the coverage")
  
  parser.add_option("-e", "--exploit", dest="exploit",
                    action="store_true", default=False,
                    help="evaluate the exploit")

  (options, args) = parser.parse_args()
  
  if len(args) == 0:
    parser.error("no input file")
  elif len(args) > 1:
    parser.error("more than one input files")

  if options.coverage:
    #import cProfile
    #cProfile.run('eval_coverage(args[0])', 'evalprof')
    eval_coverage(args[0])
  elif options.exploit:
    eval_exploit(args[0])
  else:
    parser.error("must specify -e or -c")

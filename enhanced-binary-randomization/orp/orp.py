#!/usr/bin/env python

# Copyright (c) 2012, Vasilis Pappas <vpappas@cs.columbia.edu>
# This file is part of Orp http://nsl.cs.columbia.edu/projects/orp

# Additionally modified by Mahmood Sharif <mahmoods@alumni.cmu.edu>
# Alternate contact is Keane Lucas <keanelucas@cmu.edu>

import optparse
import itertools
import random
import subprocess
import os
import sys
import pefile
import copy

import func
import eval
import inp

import swap
import reorder
import equiv
import preserv

VER="0.3"

# check for the prerequisites
try:
  import pydasm
except ImportError, e:
  print "pydasm is not installed"
  sys.exit(1)

#TODO: check that pydasm is patched!

try:
  import pygraph
except ImportError, e:
  print "pygraph is not installed"
  sys.exit(1)

def patch(pe_file, diffs):
  """
  patch the pe_file according to the provided diffs
  (i.e., apply the diffs). The code is based on inp.patch().
  """
  base = pe_file.OPTIONAL_HEADER.ImageBase
  for ea, orig, new in diffs:
    if ea < base:
      if not pe_file.set_bytes_at_offset(ea, new):
        print "error setting bytes"
    else:
      curr = pe_file.get_data(ea-base, 1)
      if curr != orig:
        print "error in patching", hex(ea), ":", ord(curr), "!=", ord(orig)
      if not pe_file.set_bytes_at_rva(ea-base, new):
        print "error setting bytes"

def randomize(input_file, n_randomize=10):

  pe_file = pefile.PE(input_file)
  
  # get the changed byte sets
  functions = inp.get_functions(input_file)
  levels = func.classify_functions(functions)
  func.analyze_functions(functions, levels)

  # see what happens when randomizing again and again and again...
  for i_r in range(n_randomize):
    # copy pe_file and functions
    #pe_file = copy.deepcopy(pe_file)
    functions = copy.deepcopy(functions)
  
    global_diffs = []
    changed_bytes = set()
    changed_insts = set()

    for f in filter(lambda x: x.level != -1, functions.itervalues()):

      # skip the SEH prolog and epilog functions .. they cause trouble
      if "_SEH_" in f.name:  
        continue

      # equiv
      diffs, c_b, c_i = equiv.do_equiv_instrs(f)
      if diffs:
        changed_bytes.update(c_b)
        changed_insts.update(c_i)
        global_diffs.extend(diffs)
        patch(pe_file, diffs)
    
      # swap
      swap.liveness_analysis(f.code)
      live_regs = swap.get_reg_live_subsets(f.instrs, f.code, f.igraph)
      swaps = swap.get_reg_swaps(live_regs)
      # count = 0
      # for comb in swap.gen_swap_combinations(swaps):
      #   # if len(comb)>1:
      #   #   print(comb)
      #   #   exit(0)
      #   count += 1
      # # print('Count=%d'%(count,))
      diffs, c_b, c_i = swap.do_multiple_swaps(f, swaps)
      if diffs:
        changed_bytes.update(c_b)
        changed_insts.update(c_i)
        global_diffs.extend(diffs)
        patch(pe_file, diffs)

      # preserv
      preservs, avail_regs = preserv.get_reg_preservations(f)
      # print('f.reg_pairs: %s'%(f.reg_pairs,))
      # print('preservs: %s'%(preservs,))
      # print('avail_regs: %s'%(avail_regs,))
      diffs, c_b, c_i = preserv.do_reg_preservs(f, preservs, avail_regs)
      if diffs:
        changed_bytes.update(c_b)
        changed_insts.update(c_i)
        global_diffs.extend(diffs)
        patch(pe_file, diffs)
        
      # reorder
      diffs, c_b = reorder.do_random_reordering(f, pe_file)
      if diffs:
        changed_bytes.update(c_b)
        global_diffs.extend(diffs)
        patch(pe_file, diffs)
        
    # update
    print "done with randomization iter #%d: changed %d bytes (and %d instructions)"%(i_r,len(changed_bytes),len(changed_insts))

    # reanalyze functions (if not the last iteration)
    if i_r<n_randomize-1:
      for f in functions.itervalues():
        f.arg_regs = set()
        f.ret_regs = set()
        f.pre_regs = set()
        f.ret_regs = set()
        f.reg_pairs = []
      func.analyze_functions(functions, levels)

  # write output
  output_file = input_file.replace(".exe", "_patched-w-compositions.exe")
  pe_file.write(output_file)
  pe_file.close()


def call_ida(input_file):
  script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "inp_ida.py")
  if not os.path.exists(script):
    print "error: could not find inp_ida.py (%s)" % script
    sys.exit(1)
  command = 'idaq -A -S"\\"' + script + '\\"" ' + input_file
  print "executing:", command
  exit_code = subprocess.call(command)
  print "exit code:", exit_code


if __name__=="__main__":

  parser = optparse.OptionParser("usage: %prog [options] input_file")

  parser.add_option("-p", "--profile", dest="profile",
                    action="store_true", default=False,
                    help="profile the execution")

  parser.add_option("-c", "--eval-coverage", dest="coverage",
                    action="store_true", default=False,
                    help="evaluate the randomization coverage")

  parser.add_option("-e", "--eval-payload", dest="payload",
                    action="store_true", default=False,
                    help="check if the payload of the exploit can be broken")

  parser.add_option("-d", "--dump-cfg", dest="dump_cfg",
                    action="store_true", default=False,
                    help="dump the CFG of the input file (using IDA)")

  parser.add_option("-r", "--randomize", dest="randomize",
                    action="store_true", default=True,
                    help="produce a randomized instance of input (default)")

  (options, args) = parser.parse_args()

  print "Orp v%s" % VER

  # check if an input file is given
  if len(args) == 0:
    parser.error("no input file")
  elif len(args) > 1:
    parser.error("more than one input files")

  # check if the input file exists
  if not os.path.exists(args[0]):
    parser.error("cannot access input file '%s'" % args[0])

  # check for incompatible options
  if options.profile and options.dump_cfg:
    parser.error("cannot profile the CFG extraction from IDA")

  # check if we're asked to profile execution
  if options.profile:
    import cProfile
    _run = cProfile.run
  else:
    _run = __builtins__.eval

  if options.coverage:
    _run('eval.eval_coverage(args[0])')
  elif options.payload:
    _run('eval.eval_exploit(args[0])')
  elif options.dump_cfg:
    call_ida(args[0])
  elif options.randomize:
    _run('randomize(args[0])')
  else:
    parser.error("how did you do that?")

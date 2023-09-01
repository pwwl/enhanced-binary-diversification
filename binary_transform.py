# Copyright (c) 2021, Keane Lucas, Mahmood Sharif, Michael K. Reiter, Lujo Bauer, and Saurabh Shintre
# This file is code used in Malware Makeover

"""
Randomize multiple binaries
"""

import random
import time
import hashlib
random.seed(time.time())
import sys
sys.path.append('enhanced-binary-randomization/')
sys.path.append('enhanced-binary-randomization/orp')

import peLib
import copy

import func
import inp
import swap
import reorder
import equiv
import preserv
import disp
import semnops
from randtoolkit import reanalyze_functions, patch

import argparse

ALLOWED_TRANSFORMS = ['equiv', 'swap', 'preserv', \
                      'reorder', 'disp', 'semnops'] # IPR + Disp
# ALLOWED_TRANSFORMS = ['disp', 'semnops'] # Disp
# ALLOWED_TRANSFORMS = ['equiv', 'swap', 'preserv', 'reorder'] # IPR

# ensure that the allowed transforms either have both disp and semnops or neither
assert ('disp' in ALLOWED_TRANSFORMS and 'semnops' in ALLOWED_TRANSFORMS) or \
       ('disp' not in ALLOWED_TRANSFORMS and 'semnops' not in ALLOWED_TRANSFORMS)

print('******* Allowed transformations: %s *******'%ALLOWED_TRANSFORMS)

def find_duplicate_bytes(functions):
    """
    Find duplicate bytes in functions
    """
    insn_set = set()
    dup_bytes = set()
    # find duplicate bytes in functions
    for f_key in functions.keys():
        f = functions[f_key]
        # skip the SEH prolog and epilog functions .. they cause trouble
        if f.level == -1 or "_SEH_" in f.name:
            continue
        for i in f.instrs:
            if i.addr in insn_set:
                for j in range(len(i.bytes)):
                    dup_bytes.add(i.addr + j)
            else:
                insn_set.add(i.addr)
    return dup_bytes

def randomize(input_file, n_randomize=10):
  pe_file, epilog = peLib.read_pe(input_file)

  # init DispState
  if 'disp' in ALLOWED_TRANSFORMS:
    disp_state = disp.DispState(pe_file)
  else:
    disp_state = None
  
  # get the changed byte sets
  functions = inp.get_functions(input_file)
  levels = func.classify_functions(functions)
  func.analyze_functions(functions, levels)

  # find duplicate bytes in functions
  dup_bytes = find_duplicate_bytes(functions)

  # see what happens when randomizing again and again and again...
  for i_r in range(n_randomize):
  
    global_diffs = []
    changed_bytes = set()
    changed_insts = set()

    # transform counts
    transform_counts = [0]*len(ALLOWED_TRANSFORMS)

    for f in filter(lambda x: x.level != -1, functions.itervalues()):
      
      # skip the SEH prolog and epilog functions .. they cause trouble
      if "_SEH_" in f.name:  
        continue
      
      # check for duplicate ref bytes in this function, skip if found
      dup_bytes_in_f = False
      for i in f.instrs:
        if i.addr in dup_bytes:
          dup_bytes_in_f = True
          break
      if dup_bytes_in_f:
        continue
      
      selected_transform = random.choice(ALLOWED_TRANSFORMS)
      transform_counts[ALLOWED_TRANSFORMS.index(selected_transform)] += 1
      
      if selected_transform=='equiv': # equivs
        diffs, c_b, c_i = equiv.do_equiv_instrs(f, p=0.5)
        if diffs:
          changed_bytes.update(c_b)
          changed_insts.update(c_i)
          global_diffs.extend(diffs)
          patch(pe_file, disp_state, diffs)
      elif selected_transform=='swap': # swaps
        swap.liveness_analysis(f.code)
        live_regs = swap.get_reg_live_subsets(f.instrs, f.code, f.igraph)
        swaps = swap.get_reg_swaps(live_regs)
        diffs, c_b, c_i = swap.do_multiple_swaps(f, swaps, p=0.5)
        if diffs:
          changed_bytes.update(c_b)
          changed_insts.update(c_i)
          global_diffs.extend(diffs)
          patch(pe_file, disp_state, diffs)
      elif selected_transform=='preserv': # preservs
        preservs, avail_regs = preserv.get_reg_preservations(f)
        diffs, c_b, c_i = preserv.do_reg_preservs(f, preservs, avail_regs, p=0.5)
        if diffs:
          changed_bytes.update(c_b)
          changed_insts.update(c_i)
          global_diffs.extend(diffs)
          patch(pe_file, disp_state, diffs)
      elif selected_transform=='reorder': # reorders
        diffs, c_b = reorder.do_random_reordering(f, pe_file)
        if diffs:
          changed_bytes.update(c_b)
          global_diffs.extend(diffs)
          patch(pe_file, disp_state, diffs)
      elif selected_transform=='disp': # displacements
        diffs, c_b, c_i = disp.displace_block(f, disp_state)
        if diffs:
          changed_bytes.update(c_b)
          changed_insts.update(c_i)
          global_diffs.extend(diffs)
          patch(pe_file, disp_state, diffs)
      elif selected_transform=='semnops': # semantic nops
        diffs, c_b = semnops.do_semnops(f)
        if diffs:
          changed_bytes.update(c_b)
          global_diffs.extend(diffs)
          patch(pe_file, disp_state, diffs)
      else:
        raise ValueError('Unknown transform type: %s'%selected_transform)

    # update
    print('[iter %d]'%i_r)
    print('changed %d bytes (and %d instructions)'\
      %(len(changed_bytes),len(changed_insts)))
    print('transformation counts: %s'%transform_counts)
    
    # reanalyze functions (if not the last iteration)
    if i_r<n_randomize-1:
      reanalyze_functions(functions, levels)

  if disp_state is not None:
    # add displacements to the pe
    adj_pe = peLib.AdjustPE(pe_file)
    adj_pe.update_displacement(disp_state)

  # write output
  output_file = input_file.replace(".exe", "") + "_patched-w-compositions.exe"
  print('Transformed binary can be found at "%s"'%(output_file,))
  peLib.write_pe(output_file, pe_file, epilog)
  pe_file.close()

  # if need to merge with /tmp/reloc.data
  if disp_state is not None and disp_state.peinfo.getRelocationSize()>0:
    disp._merge_file(output_file)

  # print hash before and after randomization
  hash_before = hashlib.sha256()
  hash_before.update( open(input_file, 'rb').read() )
  print('sha256 before transformation: "%s"'%(hash_before.hexdigest(),))
  hash_after = hashlib.sha256()
  hash_after.update( open(output_file, 'rb').read() )
  print('sha256 after transformation:  "%s"'%(hash_after.hexdigest(),))


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pe', action='append', help="PE filenames to attack. This argument " + \
                                                      "can be used multiple times.")
    parser.add_argument('--disp_budget', type=float, \
                        help='file size increase due to displacement (ratio)')
    parser.add_argument('--pad_val', type=str, default=256, \
                        help='padding value (default: 256)')
    parser.add_argument('--iters', type=int, default=1, \
                        help='number of randomizing iterations')
    return parser.parse_args()

# parse input arguments

if __name__=="__main__":
  args = parse_arguments()
  binary_paths = args.pe
  for bin_path in binary_paths:
    print('====================')
    print('Randomizing "%s"...'%(bin_path))
    randomize(bin_path, n_randomize=args.iters)

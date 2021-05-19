# Copyright (c) 2021, Mahmood Sharif, Keane Lucas, Michael K. Reiter, Lujo Bauer, and Saurabh Shintre
# This file is code used in Malware Makeover

"""
Randomize PerformanceTest's (a stress testing software) EXEs and 
DLLs to test the correctness of randomization.
"""

import random
import time
random.seed(time.time())

import sys
sys.path.append('orp')

import pefile
import copy

import func
import inp
import swap
import reorder
import equiv
import preserv
from randtoolkit import reanalyze_functions, patch

VER="0.3"

ALLOWED_TRANSFORMS = ['equiv', 'swap', 'preserv', 'reorder']
print('******* Allowed transformations: %s *******'%ALLOWED_TRANSFORMS)

def randomize(input_file, n_randomize=1):
  pe_file = pefile.PE(input_file)
  
  # get the changed byte sets
  functions = inp.get_functions(input_file)
  levels = func.classify_functions(functions)
  func.analyze_functions(functions, levels)

  # see what happens when randomizing again and again and again...
  i_f = -1
  for i_r in range(n_randomize):
  
    global_diffs = []
    changed_bytes = set()
    changed_insts = set()

    for f in filter(lambda x: x.level != -1, functions.itervalues()):
      
      # skip the SEH prolog and epilog functions .. they cause trouble
      if "_SEH_" in f.name:  
        continue
      
      selected_transform = random.choice(ALLOWED_TRANSFORMS)
      
      if selected_transform=='equiv': # equivs
        diffs, c_b, c_i = equiv.do_equiv_instrs(f, p=0.5)
        if diffs:
          changed_bytes.update(c_b)
          changed_insts.update(c_i)
          global_diffs.extend(diffs)
          patch(pe_file, diffs)
      elif selected_transform=='swap': # swaps
        swap.liveness_analysis(f.code)
        live_regs = swap.get_reg_live_subsets(f.instrs, f.code, f.igraph)
        swaps = swap.get_reg_swaps(live_regs)
        diffs, c_b, c_i = swap.do_multiple_swaps(f, swaps, p=0.5)
        if diffs:
          changed_bytes.update(c_b)
          changed_insts.update(c_i)
          global_diffs.extend(diffs)
          patch(pe_file, diffs)
      elif selected_transform=='preserv': # preservs
        preservs, avail_regs = preserv.get_reg_preservations(f)
        diffs, c_b, c_i = preserv.do_reg_preservs(f, preservs, avail_regs, p=0.5)
        if diffs:
          changed_bytes.update(c_b)
          changed_insts.update(c_i)
          global_diffs.extend(diffs)
          patch(pe_file, diffs)
      elif selected_transform=='reorder': # reorders
        diffs, c_b = reorder.do_random_reordering(f, pe_file)
        if diffs:
          changed_bytes.update(c_b)
          global_diffs.extend(diffs)
          patch(pe_file, diffs)
      else:
        raise ValueError('Unknown transform type: %s'%transform)

    # update
    print "done with randomization iter #%d: changed %d bytes (and %d instructions)"%(i_r,len(changed_bytes),len(changed_insts))
    
    # reanalyze functions (if not the last iteration)
    if i_r<n_randomize-1:
      reanalyze_functions(functions, levels)

  # write output
  if input_file.endswith('.exe'):
    output_file = input_file.replace(".exe", "_patched-w-compositions.exe")
  elif input_file.endswith('.dll'):
    output_file = input_file.replace(".dll", "_patched-w-compositions.dll")
  else:
    output_file = input_file + "_patched-w-compositions"
  pe_file.write(output_file)
  pe_file.close()
     
if __name__=="__main__":
  binary_paths = [\
                  'test/PerformanceTest-PEs/d3dx10_43.dll', \
                  'test/PerformanceTest-PEs/d3dx11_43.dll', \
                  'test/PerformanceTest-PEs/freeglut.dll', \
                  'test/PerformanceTest-PEs/glew32.dll', \
                  'test/PerformanceTest-PEs/glut32.dll', \
                  'test/PerformanceTest-PEs/Mandel.exe', \
                  'test/PerformanceTest-PEs/oclParticles.exe', \
                  'test/PerformanceTest-PEs/PT-CPUTest32.exe', \
                  'test/PerformanceTest-PEs/D3DCompiler_43.dll', \
                  'test/PerformanceTest-PEs/PerformanceTest_Help.exe'
  ]                  
  for bin_path in binary_paths:
    print('====================')
    print('Randomizing "%s"...'%(bin_path))
    randomize(bin_path, n_randomize=1)

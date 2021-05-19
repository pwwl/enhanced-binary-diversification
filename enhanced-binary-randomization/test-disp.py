# Copyright (c) 2021, Mahmood Sharif, Keane Lucas, Michael K. Reiter, Lujo Bauer, and Saurabh Shintre
# This file is code used in Malware Makeover

"""
Code to develop/test code-displacement transformations.
"""

import random
import time
random.seed(time.time())

import sys
sys.path.append('orp')

import peLib
import copy

import func
import inp
import disp
import semnops
from randtoolkit import reanalyze_functions, patch

VER="0.3"

def displace(input_file, n_randomize=1):
  pe, epilog = peLib.read_pe(input_file)

  # init DispState
  disp_state = disp.DispState(pe)

  # get the changed byte sets
  functions = inp.get_functions(input_file)
  levels = func.classify_functions(functions)
  func.analyze_functions(functions, levels)

  # run several rounds of displacement
  for i_r in range(n_randomize):
  
      # all diffs for patching
      all_diffs = []

      # run displacement for each function
      for f in filter(lambda x: x.level != -1, functions.itervalues()):

        # skip the SEH prolog and epilog functions .. they cause trouble
        if "_SEH_" in f.name:  
          continue

        # test displacement
        diffs, _, _ = disp.displace_block(f, disp_state)

        # # debug - are we attempting to displace the
        # # same bytes several times?
        # if hasattr(f, 'displaced_bytes'):
        #   for i_a in range(len(f.displaced_bytes)-1):
        #     addresses = f.displaced_bytes[i_a]
        #     for ea, orig, new in diffs:
        #       assert(ea<addresses[0] or ea>addresses[1]), \
        #         'attempting to displace twice (addr: 0x%08X) :-/'%ea

        # update diffs
        if len(diffs)>0:
          all_diffs.extend(diffs)

      # progress
      print('[iter %d] number of changed bytes: %d'%(i_r, len(all_diffs)))
      
      # patch the binary
      if all_diffs:
        patch(pe, disp_state, all_diffs)

      # re analyze
      if i_r<n_randomize-1:
        reanalyze_functions(functions, levels)

  # results update
  print('# displaced bytes: %d'%disp_state.dbytes)
  print('# diffs: %d'%len(all_diffs))
  print('# bytes in .ropf section: 0x%X'%len(disp_state.get_dbin()))

  # # debug - what's at the end of the PE?
  # print('what\'s at the end of the PE?')
  # for i in range(len(pe.__data__)-0x27, len(pe.__data__), 16):
  #   bytes = pe.__data__[i:i+16]
  #   print(' '.join(['%02x'%(ord(bytes[i]),) for i in range(len(bytes)) ]))
  
  # add displacements
  adj_pe = peLib.AdjustPE(pe)
  adj_pe.update_displacement(disp_state)

  # # debug
  # print('--> .ropf bytes:')
  # for i in range(0, len(disp_state.dbin), 16):
  #   bytes = disp_state.dbin[i:i+16]
  #   print(' '.join(['%02x'%(ord(bytes[i]),) for i in range(len(bytes)) ]))

  # write out
  output_fname = input_file.replace('.exe', '') + '.disp.exe'
  peLib.write_pe(output_fname, pe, epilog)

  # if need to merge with /tmp/reloc.data
  if disp_state.peinfo.getRelocationSize()>0:
    disp._merge_file(output_fname)

def test_displace_w_budget(input_file, budget=1000):
  pe, epilog = peLib.read_pe(input_file)

  # init DispState
  disp_state = disp.DispState(pe)

  # get the changed byte sets
  functions = inp.get_functions(input_file)
  levels = func.classify_functions(functions)
  func.analyze_functions(functions, levels)

  # test displacement with budget
  diffs = disp.displace_w_budget(functions, disp_state, budget)

  # patch the binary
  if diffs:
    patch(pe, disp_state, diffs)
  
  # randomize semnops
  diffs = []
  for f in filter(lambda x: x.level != -1, functions.itervalues()):
    # skip the SEH prolog and epilog functions .. they cause trouble
    if "_SEH_" in f.name:  
      continue
    diff, _ = semnops.do_semnops(f)
    if diff:
      diffs.extend(diff)
    
  # patch the binary
  if diffs:
    patch(pe, disp_state, diffs)

  # results update
  print('# displaced bytes: %d'%disp_state.dbytes)
  print('# diffs: %d'%len(diffs))
  print('# bytes in .ropf section: 0x%X'%len(disp_state.get_dbin()))

  # add displacements
  adj_pe = peLib.AdjustPE(pe)
  adj_pe.update_displacement(disp_state)

  # write out
  output_fname = input_file.replace('.exe', '') + '.disp_w_budget.exe'
  peLib.write_pe(output_fname, pe, epilog)

  # if need to merge with /tmp/reloc.data
  if disp_state.peinfo.getRelocationSize()>0:
    disp._merge_file(output_fname)
     
if __name__=="__main__":
  binary_paths = [\
                  'test/caffeine/caffeine.exe', \
                  'test/checksum-cygwin/cksum.exe', \
                  # 'test/diff-cygwin/diff.exe', \
                  # 'test/find-cygwin/find.exe', \
                  # 'test/grep-cygwin/grep.exe', \
                  # 'test/info-cygwin/info.exe', \
                  # 'test/less-cygwin/less.exe', \
                  # 'test/mv-cygwin/mv.exe', \
                  'test/python/python.exe', \
                  'test/pip/pip.exe'
  ]
  for bin_path in binary_paths:
    print('====================')
    print('Testing with "%s"...'%(bin_path))
    # displace(bin_path, n_randomize=5)
    test_displace_w_budget(bin_path)

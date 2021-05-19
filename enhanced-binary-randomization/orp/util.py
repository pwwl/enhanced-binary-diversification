# Copyright (c) 2012, Vasilis Pappas <vpappas@cs.columbia.edu>
# This file is part of Orp http://nsl.cs.columbia.edu/projects/orp

# Additionally modified by Mahmood Sharif <mahmoods@alumni.cmu.edu>
# Alternate contact is Keane Lucas <keanelucas@cmu.edu>

import time
import os
from bz2 import BZ2File
from subprocess import Popen, PIPE

DUMP_EXT=".dmp"
GADGET_EXT=".gad"
ZIP_EXT=".bz2"
PAYLOAD_EXT=".payload.py"
PAY_GAD_EXT=".pay_gad"

def open_dump(filename, mode):
  """Return a file object to store or load the data from the ida dump."""

  return BZ2File(filename + DUMP_EXT + ZIP_EXT, mode)


def open_gadgets(filename, mode):
  """Return a file object to store or load the gadgets from the input file
  (simple form)."""

  return BZ2File(filename + GADGET_EXT + ZIP_EXT, mode)


def open_payload_gadgets(filename, mode):
  """Return a file object to store or load the gadgets corresponding to the
  payload (simple form)."""

  return open(filename + PAY_GAD_EXT, mode)


def get_payload(filename):
  """Returns the contents of the explit payload file. These files contain
  python lists of addresses."""

  return eval(open(filename + PAYLOAD_EXT).read())


def run(cmd, timeout):
  """Executes the given command and polls for its completion.
  If the command takes more than the timeout value, it is killed.
  Returns the output of the command or None."""

  proc = Popen(cmd, stdout=PIPE, universal_newlines=True)

  while proc.poll() == None:

    timeout -= 0.2
    time.sleep(0.2)

    if timeout <= 0:
      proc.terminate()

  output = ''.join(proc.communicate()[0].split('\n'))

  return output

def get_addr_range(addrs, addr):
    """
    Return the range of either functions/blocks/codes with a binary search, O(log N)
    :param addrs: the list containing a start/end address pair
    :param addr: the target address range one looks for
    :return: (start, end) if any (0,0) otherwise
    """
    starts = [start for (start, end) in addrs]
    ends = [end for (start, end) in addrs]

    first = 0
    last = len(starts) - 1
    while first <= last:
        mid = (first+last)//2
        if starts[mid] <= addr < ends[mid]:
            return starts[mid], ends[mid]
        else:
            if starts[mid] < addr:
                first = mid + 1
            else:
                last = mid - 1

    # When no range has been found
    return 0,0

def draw_graph(g, filename="cfg.eps"):
  """Draws the given graph (which should be a pygrah instance. dot must
  be installed for this to work.."""

  from pygraph.readwrite.dot import write as write_graph

  input_lines = write_graph(g).split('\n')
  input_lines.insert(1, 'node [shape=box, style=rounded, fontname=Courier]')
  input = '\n'.join(input_lines)

  f = open(filename, 'w')
  proc = Popen(['dot', '-q', '-Teps'], stdin=PIPE, stdout=f, stderr=PIPE)
  stderr = proc.communicate(input)

  if stderr[1]:
    print "dot failed:", stderr[1]

  f.close()

  return


def draw_CFG(func, live_subsets):
  """Generate a fancy CFG annotated with the live regions of each register.
  Graphviz's 'dot' should exist in $PATH. The graph is saved as an .eps in the
  same dir where the processed .dll/.idb exists."""

  BOX_NONE   = 0
  BOX_LIVE   = 1  # colors for USEd regs!
  BOX_DEF    = 2  # draw a bolder box for DEFined regs
  BOX_ENTRY  = 3  # white entry live regions
  BOX_EXIT   = 4  # light grey exit live regions

  # Find all live registers at each position
  live_regs_in_pos = {}
  for reg, lifetime in live_subsets.iteritems():
    for subset in lifetime.subsets:
      for instr in subset.instr_set:
        box_type = BOX_LIVE
#        # Draw entry/exit live regions in a different way
#        if region.rtype == Region.ENTRY:
#          box_type = BOX_ENTRY
#        elif region.rtype == Region.EXIT:
#          box_type = BOX_EXIT
        # Highlight instructions that define a register 
        if reg in instr.OUT and reg not in instr.IN:
          box_type = BOX_DEF
        live_regs_in_pos.setdefault(instr.pos, dict()).update({reg: box_type})

  def get_liveregs_str(pos):
    """Returns the HTML string for the live registers in position 'pos'"""

    reg_colors = {
      "eax": "dodgerblue", "ebx": "green1", "ecx": "orchid", "edx": "orange",
      "esi": "yellow",     "edi": "red",    "esp": "pink",   "ebp": "cyan2"}

    boxes = {
      BOX_NONE:  'BORDER="0"><FONT COLOR="white" POINT-SIZE="10">%s',
      BOX_LIVE:  'BGCOLOR="%s"><FONT POINT-SIZE="10">%s',
      BOX_DEF:   'BORDER="3" BGCOLOR="%s"><FONT POINT-SIZE="10">%s',
      BOX_ENTRY: 'BORDERCOLOR="%s"><FONT POINT-SIZE="10">%s',
      BOX_EXIT:  'NOTUSED="%s" BGCOLOR="#EEEEEE"><FONT POINT-SIZE="10">%s'}

    ret_str = ''
    live_reg_types = live_regs_in_pos.get(pos, dict())
    # Draw registers in this particular order, ignore esp for now
    for reg in ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp']:
      ret_str += '<TD '
      if reg in live_reg_types.keys():
        ret_str += boxes[live_reg_types[reg]] % (reg_colors[reg], reg)
      else:
        ret_str += boxes[BOX_NONE] % (reg)
      ret_str += '</FONT></TD>'
    return ret_str

  # Generate graph input file for dot
  node_str = '%d [label=<<TABLE><TR><TD BORDER="0">%-24s</TD>%s</TR></TABLE>>];'
  dotfile_lines = [
    'digraph foo {',
    '  graph [size="7,11", labeljust=l, ranksep=0.5]',
    '  node  [shape=plaintext, fontname=Courier]']

  # Draw nodes
  for ins in func.instrs:
    dotfile_lines.append(node_str % (ins.pos, ins, get_liveregs_str(ins.pos)))

  # Draw edges
  for ins in func.instrs:
    for suc in ins.succ:
      dotfile_lines.append(str(ins.pos)+' -> '+str(func.code[suc].pos)+';')

  dotfile_lines.append('}')
  input = '\n'.join(dotfile_lines)

  # Generate graph
  f = open('cfg.eps', 'w')
  proc = subprocess.Popen(['dot', '-q', '-Teps'], stdin=subprocess.PIPE,
                          stdout=f, stderr=subprocess.PIPE)
  stderr = proc.communicate(input)

  if stderr[1]:
    print "dot failed:", stderr[1]

  f.close()

  return

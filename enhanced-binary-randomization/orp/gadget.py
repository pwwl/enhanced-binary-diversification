#!/usr/bin/env python

# Copyright (c) 2012, Vasilis Pappas <vpappas@cs.columbia.edu>
# This file is part of Orp http://nsl.cs.columbia.edu/projects/orp

# Additionally modified by Mahmood Sharif <mahmoods@alumni.cmu.edu>
# Alternate contact is Keane Lucas <keanelucas@cmu.edu>

import pydasm
import pickle
import inp
import util


class SimpleGadget(object):
  
  def __init__(self, start, end, overlap, red, ins_num, func_ea):
    self.start   = start
    self.end     = end     # real end!
    self.overlap = overlap
    self.red     = red
    self.ins_num = ins_num
    self.func_ea = func_ea
  
  def set_extra(self, addrs, string, end_func_ea):
    self.addrs  = addrs
    self.string = string
    self.end_func_ea = end_func_ea


class Gadget():
  
  def __init__(self, start_ea, end_ea, instrs):
    self._start_ea = start_ea
    self._end_ea = end_ea # addr of the first byte of the final instruction
    self._instrs = instrs
    self.overlap = not all((a in inp.get_code_heads() for a, i in instrs))

  def get_start_ea(self):
    return self._start_ea

  def get_end_ea(self):
    return self._end_ea

  def get_real_end_ea(self):
    return self._end_ea + self._instrs[-1][1].length

  def dump_simple(self, extra=False):
    func_ea = inp.get_func_of(self._start_ea)
    red = (not func_ea and not inp.get_func_of(self.get_real_end_ea()-1))
    sg = SimpleGadget(self._start_ea, self.get_real_end_ea(), self.overlap,
                      red, len(self._instrs), func_ea)
    if extra:
      sg.set_extra([a for a, i in self._instrs], '; '.join([
                   pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, 0)
                   for a, i in self._instrs]), inp.get_func_of(self.get_real_end_ea()-1))
    return sg

  def __str__(self):
    output_header = "gadget @ %.08X:%.08X %s\n" % (
        self.get_start_ea(), self.get_end_ea(),
        "(overlapping)" if self.overlap else "")
    output_lines = []
    for ea, instr in self._instrs:
      instr_str = pydasm.get_instruction_string(instr, pydasm.FORMAT_INTEL, 0)
      output_lines.append("%.08X %.2X %s" % (ea, instr.opcode, instr_str))
    return (output_header + '\n'.join(output_lines))

  def __eq__(self, other):
    return ((self.get_start_ea() == other.get_start_ea()) and
            (self.get_end_ea() == other.get_end_ea()))

  def __ne__(self, other):
    return not self.__eq__(other)

  def __hash__(self):
    return hash("%x-%x"%(self.get_start_ea(), self.get_end_ea()))

  def __cmp__(self, other):
    if self.get_end_ea() == other.get_end_ea():
      return self.get_start_ea() - other.get_start_ea()
    else:
      return self.get_end_ea() - other.get_end_ea()


gadget_ends = [
  'C3',  # ret
# 'CB',  # ret far - ignore for now
  'C2',  # ret imm16
# 'CA',  # ret imm16 far - ignore for now
  'FF',  # indirect jmp/call - not always (!) ..could be inc/dec r/m16/32
]

# based on  http://hexblog.com/2009/09/assembling_and_finding_instruc.html

def find_gadget_ends(start_ea, end_ea):
  gadget_end_addresses = []
  for opcode_byte in gadget_ends:
    ea = start_ea
    while True:
      ea = inp.code_search(ea, opcode_byte)
      if ea > end_ea or ea == None:
        break
      if inp.byte_at(ea) != 0xFF:
        gadget_end_addresses.append(ea)
      else:
        # An opcode starting with 0xFF is not necessarily an indirect jmp/call
        bytes_ahead = 10  # TODO should be smaller, probably 3, should check
        headroom = inp.seg_end(ea) - ea
        if 0 < headroom < 10:
          bytes_ahead = headroom
        ibuf = inp.bytes_at(ea, bytes_ahead)
        if not ibuf:
          print "WARNING: GetManyBytes(%.08X, %d) failed " % (ea, bytes_ahead)
        instr = pydasm.get_instruction(ibuf, pydasm.MODE_32)
        if (instr and
            pydasm.get_mnemonic_string(instr, pydasm.FORMAT_INTEL) in ("call", "jmp") and
            (instr.op1.reg != 8 or instr.op1.basereg != 8 or instr.op1.indexreg != 8)):
          gadget_end_addresses.append(ea)
      ea += 1
  return gadget_end_addresses


def extract_gadget(end_ea, depth_bytes=64):
  """Extract all gadgets that end at the instruction starting at ea
  end_ea: the first byte of the final instruction of the gadgets
  depth_bytes: look back for gadget instructions at most 'depth_bytes'
  from the address of its last instruction"""

  bytes_ahead = 6  # TODO should be smaller, probably 3, should check
  bytes_back = depth_bytes
  # Confine search within end_ea's segment
  headroom = inp.seg_end(end_ea) - end_ea
  if 0 < headroom < bytes_ahead:
    bytes_ahead = headroom
  headroom = end_ea - inp.seg_start(end_ea)
  if 0 < headroom < bytes_back:
    bytes_back = headroom

  ibuf_start = max(end_ea-bytes_back, inp.seg_start(end_ea))
  ibuf_len = bytes_back+bytes_ahead

  ibuf = inp.bytes_at(ibuf_start, ibuf_len)
  if not ibuf:
    print "WARNING: GetManyBytes(%.08X, %d) failed " % (ibuf_start, ibuf_len)

  # ibuf:
  #
  #   end_ea-bytes_back                end_ea    end_ea+bytes_ahead
  #     |                                 |                 |
  #     +---------------------------------+-----------------+
  #      <-----------bytes_back----------> <--bytes_ahead-->

  # Always corresponds to end_ea and is our basic reference in the ibuf
  idx_end_instr = bytes_back

  # This is the final instruction of the gadget (ret/jmp/call)
  instr = pydasm.get_instruction(ibuf[idx_end_instr:], pydasm.MODE_32)

  # Holds the disassembled instruction at each position in the ibuf
  all_instrs = [None]*(idx_end_instr + 1)   # +1 for the final instruction
  all_instrs[idx_end_instr] = instr

  # Going backwards from its final instruction, a gadget cannot include
  # any instruction of the following types
  bad_instrs = [
    pydasm.INSTRUCTION_TYPE_JMP,
    pydasm.INSTRUCTION_TYPE_JMPC,
    pydasm.INSTRUCTION_TYPE_LOOP,
    pydasm.INSTRUCTION_TYPE_CALL,
    pydasm.INSTRUCTION_TYPE_RET,
    pydasm.INSTRUCTION_TYPE_PRIV]

  gadgets = [[idx_end_instr]]

  # Find all gadgets starting from each and every position in the buffer
  for pos in range(idx_end_instr):

    # If we have already visited this instruction as part of a previous
    # instruction sequence, we can skip exploring the same sub-sequence
    if all_instrs[pos]:
      continue

    tmp_gadget = []
    has_bad = False

    # Linear disassembly until we reach the end of the gadget
    while pos < idx_end_instr:
      instr = all_instrs[pos]  # Acts as a cache of decoded instructions
      if not instr:
        # First time we visit this instruction: disassemble 
        instr = pydasm.get_instruction(ibuf[pos:], pydasm.MODE_32)
        # Stop exploring this path if we hit an illegal or "bad" instruction
        if not instr or instr.type in bad_instrs:
          has_bad = True
          break
        # Save the decoded instruction to avoid disassembling it again
        all_instrs[pos] = instr
      # Non-bad instruction: append it to the current gadget
      tmp_gadget.append(pos)
      # Move to the next instruction
      pos += instr.length

    # If we "touched" the gadget's final instruction, this is a valid gadget
    if not has_bad and pos == idx_end_instr:
      # For completeness, also include the final instruction
      tmp_gadget.append(idx_end_instr)
      gadgets.append(tmp_gadget)

  gadgets_ret = []
  for gdgt in gadgets:
    idx_first_instr = gdgt[0]
    start_ea = end_ea - (idx_end_instr - idx_first_instr)
    instrs = [all_instrs[p] for p in gdgt]
    addrs = map(lambda idx: (end_ea - (idx_end_instr - idx)), gdgt)
    gadgets_ret.append(Gadget(start_ea, end_ea, zip(addrs, instrs)))

  return gadgets_ret


def find_gadgets(ea_start, ea_end):
  """Finds and returns a set of gadgets that are at most 64 bytes long."""

  gadgets = set()
  gadget_end_addresses = find_gadget_ends(ea_start, ea_end)

  for g_ea in sorted(gadget_end_addresses):
    g = extract_gadget(g_ea)
    if g != None:
      gadgets.update(g)

  return gadgets


def find_gadgets5(ea_start, ea_end):
  """Finds and returns a set of gadgets that are at most 5 instructions long."""

  gadgets5 = set()

  for g in find_gadgets(ea_start, ea_end):
    for i in range(min(5, len(g._instrs)), 1, -1):
      instrs = g._instrs[-i:]
      gadgets5.add(Gadget(instrs[0][0], instrs[-1][0], instrs))

  return gadgets5


def find_payload_gadgets():
  """Finds and returns a set of gadgets that is used by the given exploit."""
  
  # load the exploits gadgets
  payload = util.get_payload(inp.get_input_file_path())
  exp_gadgets = set()

  for addr in payload:
    gadgets = find_gadgets(addr, addr+64)
    for gad in gadgets:
      for iaddr, ins in gad._instrs:
        if iaddr == addr:
          i = gad._instrs.index((iaddr, ins))
          exp_gadgets.add(Gadget(addr, gad._instrs[-1][0], gad._instrs[i:]))

  print "found", len(exp_gadgets), "gadgets for", len(payload), "addresses"

  if len(exp_gadgets) != len(payload):
    print "missing:", list(set(payload)-set(g.get_start_ea() for g in exp_gadgets))

  return set((g.dump_simple(extra=True) for g in exp_gadgets))


def get_all_gadgets():
  """Returns a set of all the gadges found in all the code segments of
  the file that is currently processed. (It uses find_gadgets5 which limits
  the length of each gadget to 5 instructions)."""

  all_gadgets = set()

  for begin, end, name in inp.code_segments_iter():
    all_gadgets |= find_gadgets5(begin, end)

  return all_gadgets


def get_simple_gadgets(input_file):
  """Checks if a dump of the gadgets already exists and loads them. Otherwise,
  it finds all the gadgets in the current input file, dumps them and also
  returns them (simple form)."""

  try:
    gad_in = util.open_gadgets(input_file, "rb")
    simple_gadgets = pickle.load(gad_in)
  except IOError, e:
    all_gadgets = get_all_gadgets()
    simple_gadgets = set((g.dump_simple(extra=True) for g in all_gadgets))
    gad_out = util.open_gadgets(input_file, "wb")
    pickle.dump(simple_gadgets, gad_out)
    gad_out.close()

  return simple_gadgets


def get_payload_gadgets(input_file):
  """Checks if a dump of the payload gadgets already exists and loads them.
  Otherwise, it finds all the gadgets corresponding to the addresses in the
  payload, dumps them and also returns them (simple form)."""

  try:
    pay_gad_in = util.open_payload_gadgets(input_file, "rb")
    payload_gadgets = pickle.load(pay_gad_in)
  except IOError, e:
    payload_gadgets = find_payload_gadgets() # already simple
    pay_gad_out = util.open_payload_gadgets(input_file, "wb")
    pickle.dump(payload_gadgets, pay_gad_out)
    pay_gad_out.close()

  return payload_gadgets

# executes as an IDA python script
if __name__ == "__main__":
  # Find gadgets between cursor position and end of function
  start_ea = ScreenEA()
  end_ea = idc.FindFuncEnd(start_ea)
  print "\nSearching for gadgets in %.8X:%.8X" % (start_ea, end_ea)
  gadgets = find_gadgets(start_ea, end_ea)
  print "Found %d gadgets:" % len(gadgets)
  for g in sorted(gadgets):
    print g
  gadgets5 = find_gadgets5(start_ea, idc.FindFuncEnd(start_ea))
  print "Found %d (sub)sequences 2-5 instructions long" % len(gadgets5)
  for g in sorted(gadgets5):
    print g

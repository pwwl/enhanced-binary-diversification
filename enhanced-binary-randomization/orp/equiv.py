# Copyright (c) 2012, Vasilis Pappas <vpappas@cs.columbia.edu>
# This file is part of Orp http://nsl.cs.columbia.edu/projects/orp

# Additionally modified by Mahmood Sharif <mahmoods@alumni.cmu.edu>
# Alternate contact is Keane Lucas <keanelucas@cmu.edu>

import struct
import insn
import inp
import random
import randtoolkit

# equivalent instructions stuff.. ugly (check x86.py)
both_regs = (0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19, 0x20,
             0x21, 0x28, 0x29, 0x30, 0x31, 0x38, 0x39, 0x88, 0x89)
same_regs = {0x84: (0x08, 0x0A, 0x20, 0x22),
             0x08: (0x84, 0x0A, 0x20, 0x22),
             0x0A: (0x84, 0x08, 0x20, 0x22),
             0x20: (0x84, 0x08, 0x0A, 0x22),
             0x22: (0x84, 0x08, 0x0A, 0x20),
             0x85: (0x09, 0x0B, 0x21, 0x23),
             0x09: (0x85, 0x0B, 0x21, 0x23),
             0x0B: (0x85, 0x09, 0x21, 0x23),
             0x21: (0x85, 0x09, 0x0B, 0x23),
             0x23: (0x85, 0x09, 0x0B, 0x21)}
same_reg_modrms = (0xC0, 0xC9, 0xD2, 0xDB, 0xE4, 0xED, 0xF6, 0xFF)
equiv_addsub8 = {0x04: 0x2C, 0x2C: 0x04}
equiv_addsub32 = {0x05: 0x2D, 0x2D: 0x05}
equiv_xorsub = {0x30: 0x28, 0x31: 0x29, 0x32: 0x2A, 0x33: 0x2B}
equiv_xchg = (0x86, 0x87)

def check_equiv(ins):
    """Checks whether this instruction can be changed with an equivalent one.
    'cbytes' is changed if an equivalent instrucion does exist."""

    opcode = ord(ins.bytes[ins.opc_off])
    modrm = ord(ins.bytes[ins.modrm_off])

    # check for equivalent instructions when both operands are registers
    if ins.op1.type == ins.op2.type == insn.Operand.REGISTER:
      dir_bit = 0b00000010
      # check if there is an equivalent when both regs are the same
      if opcode in same_regs and modrm in same_reg_modrms:
        ins.cbytes[ins.opc_off] = same_regs[opcode][0]
        modrm_offset = ins.modrm_mod << 6 | ins.modrm_rm << 3 | ins.modrm_reg
        ins.cbytes[ins.modrm_off] = modrm_offset
      # turn off the dir bit and check again
      elif opcode ^ (opcode & dir_bit) in both_regs:
        ins.cbytes[ins.opc_off] ^= dir_bit
        modrm_offset = ins.modrm_mod << 6 | ins.modrm_rm << 3 | ins.modrm_reg
        ins.cbytes[ins.modrm_off] = modrm_offset
      elif opcode in equiv_xchg and ins.modrm_off > 0:
        modrm_offset = ins.modrm_mod << 6 | ins.modrm_rm << 3 | ins.modrm_reg
        ins.cbytes[ins.modrm_off] = modrm_offset
      #XXX shadowed by first case!
      elif opcode in equiv_xorsub and modrm in same_reg_modrms:
        ins.cbytes[ins.opc_off] = equiv_xorsub[opcode]
    # check for equiv when second openrand is imm (eg, add -> sub)
    elif ins.op2.type == insn.Operand.IMMEDIATE:
      ext_mask = 0b00101000  # modrm = mod 2b | reg 3b | rm 3b
      # 8 bit immediates, extended opcodes
      if opcode in (0x80, 0x83) and ins.modrm_reg in (0b000, 0b101):
        if ins.op2.immediate_value != -0x80:  # -2**7
          ins.cbytes[ins.modrm_off] ^= ext_mask
          tmp = struct.unpack('b',  chr(ins.cbytes[-1]))[0]
          ins.cbytes[-1] = struct.pack('b', -tmp)
      # 32 bit immediate, extended opcode
      elif opcode == 0x81 and ins.modrm_reg in (0b000, 0b101):
        if ins.op2.immediate_value != -0x80000000: # -2**31
          ins.cbytes[ins.modrm_off] ^= ext_mask
          tmp = struct.unpack('i',  str(ins.cbytes[-4:]))[0]
          ins.cbytes[-4:] = struct.pack('i', -tmp)
      # 8 bit immediate, simple case
      elif opcode in equiv_addsub8:
        if ins.op2.immediate_value != -0x80:  # -2**7
          ins.cbytes[ins.opc_off] = equiv_addsub8[opcode]
          tmp = struct.unpack('b',  chr(ins.cbytes[-1]))[0]
          ins.cbytes[-1] = struct.pack('b', -tmp)
      # 32 bit immediate, simple case
      elif opcode in equiv_addsub32:
        if ins.op2.immediate_value != -0x80000000: # -2**31
          ins.cbytes[ins.opc_off] = equiv_addsub32[opcode]
          tmp = struct.unpack('i',  str(ins.cbytes[-4:]))[0]
          ins.cbytes[-4:] = struct.pack('i', -tmp)
    return ins.bytes != ins.cbytes  # bytearray with str comparison is ok here

def can_equiv(f):
    """
    checks if any instruction in f can be replaced
    with an equivalent one..
    """
    for ins in f.instrs:
        try:
            if (not ins.irreplaceable) and check_equiv(ins):
                return True
        except:
            continue
    return False

def do_equiv_instrs(f, p=0.5):
  """
  Check each instruction if it has an equivalent one and computes the
  changed bytes set. Optionally, it can generate a changed file with the
  equivalent instructions. Returns the diffs, set of bytes changed, 
  and set of instructions changed, and *updates the instructions*
  (to keep the internal representation consistent with the byte 
   representation).
  """

  instrs = f.instrs
  can_change = []

  # find instructions that have equivalents
  for ins in instrs:
    try:
      has_equiv = (not ins.irreplaceable) and check_equiv(ins)
    except:
        has_equiv = False
    if has_equiv:
      can_change.append(ins)

  # pick a random subset of changes
  changed_instrs = [ins for ins in can_change if random.random()<p]
  
  # compute diffs
  diffs = []
  for ins in changed_instrs:
   diffs.extend(inp.get_diff([ins]))

  # apply the changes to the instruction structs
  for ins in changed_instrs:
    ins.apply_changes()

  # reset the structures
  for ins in can_change:
    ins.reset_changed()

  # get addresses of changed bytes
  changed_bytes = set([ea for ea, orig, new in diffs])

  return diffs, changed_bytes, changed_instrs


def do_equiv_canonicalization(f, pe_file):
  """
  Canonicalize instructions to the representation with the minimal 
  alphabetical order.
  """
  instrs = f.instrs
  can_change = []
  diffs = []
  changed_instrs = []

  # find instructions that have equivalents
  for ins in instrs:
    try:
      has_equiv = (not ins.irreplaceable) and check_equiv(ins)
    except:
        has_equiv = False
    if has_equiv:
      can_change.append(ins)

  # compute diffs
  for ins in can_change:
    ins_diffs = inp.get_diff([ins])
    earliest = min(ins_diffs, key=lambda x: x[0])
    if earliest[2]<earliest[1]: # if lower alphabetical order
        ins.apply_changes()
        diffs.extend(ins_diffs)
        changed_instrs.append(ins)

  # apply the changes to the instruction structs
  for ins in changed_instrs:
    ins.apply_changes()

  # reset the structures
  for ins in can_change:
    ins.reset_changed()

  # get addresses of changed bytes
  changed_bytes = set([ea for ea, orig, new in diffs])

  # apply diffs
  randtoolkit.patch(pe_file, None, diffs)

  return diffs, changed_bytes, changed_instrs

# executes as an IDA python script
if __name__ == "__main__":
  # Find equivalent instructions between cursor position and end of function
  import idautils
  start_ea = ScreenEA()
  end_ea = idc.FindFuncEnd(start_ea)
  print "\nSearching for equiv instrs in %.8X:%.8X" % (start_ea, end_ea)
  for head in idautils.Heads(start_ea, end_ea):
    ibytes = idc.GetManyBytes(head, idc.ItemEnd(head) - head)
    ins = insn.Instruction(head, ibytes, 0)
    if check_equiv(ins):
      eq_ins = insn.Instruction(head, str(ins.cbytes), 0)
      print ins.disas, "(%s) ->" % ins.bytes.encode("hex"),
      print eq_ins.disas, "(%s)" %eq_ins.bytes.encode("hex")

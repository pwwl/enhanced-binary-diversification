# Copyright (c) 2012, Vasilis Pappas <vpappas@cs.columbia.edu>
# This file is part of Orp http://nsl.cs.columbia.edu/projects/orp

# Additionally modified by Mahmood Sharif <mahmoods@alumni.cmu.edu>
# Alternate contact is Keane Lucas <keanelucas@cmu.edu>

import pydasm

REGS = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
NON_32BIT_REGS = set(["al", "ah", "ax", "bl", "bh", "bx", \
                      "cl", "ch", "cx", "dl", "dh", "dx"])
NUM_REGS = 8

nop = pydasm.get_instruction('\x90', pydasm.MODE_32)

# we have to replicate the Instruction and (maybe) Opcode class from pydasm,
# otherwise we won't be able to pickle them..
class Operand(object):

  NONE      = pydasm.OPERAND_TYPE_NONE
  MEMORY    = pydasm.OPERAND_TYPE_MEMORY
  REGISTER  = pydasm.OPERAND_TYPE_REGISTER
  IMMEDIATE = pydasm.OPERAND_TYPE_IMMEDIATE

  def __init__(self, pydasm_op):
    # copy whatever attributes we need from the operands
    self.type = pydasm_op.type
    if pydasm_op.type==pydasm.OPERAND_TYPE_IMMEDIATE:
      self.immediate_value = pydasm_op.immediate
      if self.immediate_value > 0x7FFFFFFF:
        self.immediate_value -= 0x100000000
    else:
      self.immediate_value = None


class Instruction(object):

  def __init__(self, ea, bytes, spd):
    self.addr       = ea
    self.bytes      = bytes
    # copy whatever we need from the pydasm instruction object
    inst            = pydasm.get_instruction(bytes, pydasm.MODE_32)
    if inst == None:
      print "IGNORE:", hex(ea), ''.join(('\\x%02x'%ord(b) for b in bytes))
      inst = nop
    self.disas      = pydasm.get_instruction_string(
                          inst, pydasm.FORMAT_INTEL, ea)
    self.mnem       = pydasm.get_mnemonic_string(inst, pydasm.FORMAT_INTEL)
    self.type       = inst.type
    self.modrm_off  = inst.modrm_offset
    self.opc_off    = inst.opcode_offset
    self.eflags_r   = inst.eflags_used
    self.eflags_w   = inst.eflags_affected
    self.uses_sib   = False
    self.inst_len   = inst.length - inst.opcode_offset  # no prefixes!!
    self.spd        = spd    # stack pointer delta
    self.pos        = -1     # instruction position after ordering
    self.raddr      = ea     # address after reordering (if changed)
    self.implicit   = set()  # registers used implicitly by this instruction
    self.irreplaceable = False  # is the instruction irreplaceable (by equiv.py)?
    self.f_entry    = False  # whether the instruction is a function entry point
    self.f_exit     = inst.type == pydasm.INSTRUCTION_TYPE_RET
    self.regs       = dict() # holds bit positions in the instruction per reg
    self.updated    = False  # for call instr, tells whether it was updated
    self.can_change = set()  # registers that can change in a indirect call
    # these copies of bytes and regs are initialized by reset_changed
    self.cregs      = None
    self.cbytes     = None
    self.creg_names = None
    # liveness information
    self.succ       = set()  # list of successor instruction addresses
    self.USE        = set()  # regs used (read) by this instruction
    self.DEF        = set()  # regs defined (written) by this instruction
    self.IN         = set()  # regs that are live before instruction execution
    self.OUT        = set()  # regs that are live after instruction execution
    self.IN_old     = None
    self.OUT_old    = None
    #TODO: special case for lea optimization (3 operands)
    self._get_use_def(inst)
    self._store_operands(inst)
    self.reset_changed()
    #debug XXX
    #_regs = ((self.USE | self.DEF) - self.implicit) | self.can_change
    #if (not self.disas == "mov edi,edi" and not self.extra_regs and
    #    any((r not in _regs for r in self.regs))):
    #  print "BUG: 0x%08x %s: %s != %s" % (self.addr, self.disas, self.regs, _regs)

  def reset_changed(self):
    self.cregs = self.regs.copy()
    self.cbytes = bytearray(self.bytes)
    self.creg_names = {}

  def apply_changes(self):
    """
    apply the changes
    """
    self.regs = self.cregs.copy()
    self.bytes = str(self.cbytes)
    inst = pydasm.get_instruction(self.bytes, pydasm.MODE_32)
    if inst == None:
      inst = nop
    self.disas      = pydasm.get_instruction_string(inst, pydasm.FORMAT_INTEL, self.addr)
    self.mnem       = pydasm.get_mnemonic_string(inst, pydasm.FORMAT_INTEL)
    self.type       = inst.type
    self.modrm_off  = inst.modrm_offset
    self.opc_off    = inst.opcode_offset
    self.eflags_r   = inst.eflags_used
    self.eflags_w   = inst.eflags_affected
    self.inst_len   = inst.length - inst.opcode_offset  # no prefixes!!
    self.implicit = set()
    self.regs = dict()
    self.DEF = set()
    self.USE = set()
    self._get_use_def(inst)
    self._store_operands(inst)
    self.reset_changed()
    
  def is_ind_call(self):
    return self.mnem == "call" and self.bytes[0] == '\xff'

  def swap_registers(self, r1, r2):
    """Swaps the registers of the instruction and checks if the resulting one
    is correct. Returns False if the resulting instruction is wrong or if the
    instruction was unchanged. On success, 'cregs' and 'cbytes' are updated
    accordingly."""

    def update_bits(r1, r2, bytes, cregs):
      for byte_off, bit_off in cregs[r1]:
        #print map(bin, bytes)
        clear_mask = ~(0b111 << bit_off)
        bytes[byte_off] &= clear_mask
        #print map(bin, bytes)
        set_mask = REGS.index(r2) << bit_off
        bytes[byte_off] |= set_mask
        #print map(bin, bytes)
      return
    
    # translate register names XXX out for now ..
    #print 'translate:', r1, r2, '->', 
    #r1 = self.creg_names[r1] if r1 in self.creg_names else r1
    #r2 = self.creg_names[r2] if r2 in self.creg_names else r2
    #print r1, r2
    
    # check if the swap is feasible
    bytes = self.cbytes[:]
    if r1 in self.cregs:
      try:
        update_bits(r1, r2, bytes, self.cregs)
      except:
        return False
    if r2 in self.cregs:
      try:
        update_bits(r2, r1, bytes, self.cregs)
      except:
        return False

    try:
        # illegal modrm/sip states
        if self.modrm_off:
          mod = pydasm.MASK_MODRM_MOD(bytes[self.modrm_off])
          prev_rm = pydasm.MASK_MODRM_RM(self.cbytes[self.modrm_off])
          rm = pydasm.MASK_MODRM_RM(bytes[self.modrm_off])
          if mod == 0b00 and (prev_rm == 0b101 or rm == 0b101) and prev_rm != rm:
            #print "modrm case 1:", self.disas, "|", r1, r2
            return False
          if (0b00 <= mod <= 0b10 and (prev_rm == 0b100 or rm == 0b100) and
              prev_rm != rm):
            #print "modrm case 2:", self.disas, "|", r1, r2
            return False
          if self.uses_sib:
            idx = pydasm.MASK_SIB_INDEX(bytes[self.modrm_off+1])
            prev_idx = pydasm.MASK_SIB_INDEX(self.cbytes[self.modrm_off+1])
            if (prev_idx == 0b100 or idx == 0b100) and prev_idx != idx:
              #print "sib case 1:", self.disas, "|", r1, r2
              return False
            base = pydasm.MASK_SIB_BASE(bytes[self.modrm_off+1])
            prev_base = pydasm.MASK_SIB_BASE(self.cbytes[self.modrm_off+1])
            #XXX: there is a special sub-case here.. we can swap base with index..
            if (mod == 0b00 and (prev_base == 0b101 or base == 0b101) and
                prev_base != base):
              #print "sib case 2:", self.disas, "|", r1, r2
              return False
        # check if the newly created instruction can be decoded properly
        inst = pydasm.get_instruction(str(bytes), pydasm.MODE_32)
        if not inst:
          print hex(self.addr), "cant swap (", r1, r2,")", self.disas
          return False
        # check if the mnemonic changed
        new_mnem = pydasm.get_mnemonic_string(inst, pydasm.FORMAT_INTEL)
        if self.mnem != new_mnem:
          print hex(self.addr), "cant swap (", r1, r2,")", self.disas, new_mnem
          return False
        # check if the register names are the intended ones (8-bit and 16-bit accesses)
        # without this, the following might happen, for example:
        #    for esi <-> ebx: 'test bl, bl' -> 'test dh, dh'
        orig = pydasm.get_instruction(self.bytes, pydasm.MODE_32)
        for op_i, op in enumerate((orig.op1, orig.op2, orig.op3)):
          if (op.type == pydasm.OPERAND_TYPE_REGISTER and  # register
              self.not32bit(op_i, orig) and # 8-bit (al,..,dl,ah,..,dh) or 16-bit (ax,..,dx)
              REGS[op.reg%4] in (r1, r2) and                 # swapped
              set((r1, r2)) - set((REGS[op.reg%4],)) & set(REGS[4:])): # with (esi..)
            return False
    except:
      return False

    # extend with NOPs
    # FIXME: manualy check if eax is dest and the instruction can be compressed
    #for i in range(inst.length, len(bytes)):
    #  bytes[i] = "\x90"
    # apply the swap!
    if r1 in self.cregs and r2 in self.cregs:
      tmp = self.cregs[r1]
      self.cregs[r1] = self.cregs[r2]
      self.cregs[r2] = tmp
    elif r1 in self.cregs:
      self.cregs[r2] = self.cregs[r1]
      del self.cregs[r1]
    elif r2 in self.cregs:
      self.cregs[r1] = self.cregs[r2]
      del self.cregs[r2]
    self.cbytes = bytes

    #update register names XXX: leave translation out for now ..
    #self.creg_names[r1] = r2
    #self.creg_names[r2] = r1
    #print 'update:', r1, r2, '->', self.creg_names[r1], self.creg_names[r2]
    #print self.disas, "->", pydasm.get_instruction_string(inst, pydasm.FORMAT_INTEL, self.addr)
    return True

  def _store_operands(self, inst):
    self.op1 = Operand(inst.op1)
    self.op2 = Operand(inst.op2)
    self.op3 = Operand(inst.op3)
    registers = []
    # TODO: 16-bit addressing mode for modrm
    if inst.modrm_offset:
      # nice explanatory website: http://www.swansontec.com/sintel.html
      self.modrm_rm = rm = pydasm.MASK_MODRM_RM(inst.modrm)
      self.modrm_reg = reg = pydasm.MASK_MODRM_REG(inst.modrm)
      self.modrm_mod = mod = pydasm.MASK_MODRM_MOD(inst.modrm)
      # from http://ref.x86asm.net/coder32.html#modrm_byte_32
      if not ((mod != 0b11 and rm == 0b100) or (mod == 0b00 and rm == 0b101)):
        registers.append([REGS[rm], inst.modrm_offset, 0])
      elif mod != 0b11 and rm == 0b100 : # sib!
        index = pydasm.MASK_SIB_INDEX(inst.sib)
        base = pydasm.MASK_SIB_BASE(inst.sib)
        if index != 0b100:
          registers.append([REGS[index], inst.modrm_offset+1, 3])
        if base != 0b101 or (base == 0b101 and mod in (0b01, 0b10)):
          registers.append([REGS[base], inst.modrm_offset+1, 0])
        self.uses_sib = True
        # else, index is none or base is displ
      if not (inst.op2.type == pydasm.OPERAND_TYPE_NONE or
              inst.op2.type == pydasm.OPERAND_TYPE_IMMEDIATE or
             (inst.op2.flags & pydasm.AM_REG) == pydasm.AM_REG): #XXX check!
        registers.append([REGS[reg], inst.modrm_offset, 3])
      # else, it's one op instruction and this field is opcode extension
      # or, it's the case where rm is just displ32, no regs
    #check instructions with register arg encoded in opcode
    if self._is_reg_in_opcode(inst):
      reg = inst.opcode & 0b111
      registers.append([REGS[reg], inst.opcode_offset, 0])
      #print self.disas, "register", bin(reg), REGS[reg]
    self.regs = {}
    for reg, byte_off, bit_off in registers:
      if reg not in self.regs:
        self.regs[reg] = []
      self.regs[reg].append((byte_off, bit_off))

  def _is_reg_in_opcode(self, inst):
    # inc, dec, push, pop, mov, bswap
    if ((pydasm.MASK_EXT(inst.flags) == 0 and (
            0x40 <= inst.opcode <= 0x5F or      # inc, dec, push, pop
            0xB0 <= inst.opcode <= 0xBF or      # mov
            0x91 <= inst.opcode <= 0x97)) or    # xchng XXX exclude NOP!
        (pydasm.MASK_EXT(inst.flags) == pydasm.EXT_T2 and (
            0xC8 <= inst.opcode <= 0xCF))):     # bswap
      return True
    return False

  def not32bit(self, op_i, inst=None):
    """
    checks if the operand op_i isn't a 32-bit register.
    (assumes that the operand is a register)
    """
    if not inst:
      inst = pydasm.get_instruction(self.bytes, pydasm.MODE_32)
    op_str = pydasm.get_operand_string(inst, op_i, pydasm.FORMAT_INTEL, self.addr)
    return op_str in NON_32BIT_REGS

  def _get_use_def(self, inst):
    
    if not inst.ptr.checked:# and self.mnem not in ("bswap", "fimull", "cmpsb"):
      print ("NOT TRACKING:", ''.join(['\\x%02x' % ord(b) for b in self.bytes]),
             self.disas)
      return
    # special case for ignoring 'move R, R' (cl.exe does that for patching)
    if (self.mnem == 'mov' and
        inst.op1.type == pydasm.OPERAND_TYPE_REGISTER and
        inst.op2.type == pydasm.OPERAND_TYPE_REGISTER and
        inst.op1.reg == inst.op2.reg):
      return
    # special case for 'xor R, R'
    if (self.mnem == 'xor' and
        inst.op1.type == pydasm.OPERAND_TYPE_REGISTER and
        inst.op2.type == pydasm.OPERAND_TYPE_REGISTER and
        inst.op1.reg == inst.op2.reg):
      if self.not32bit(0, inst):
        # op1 is an 8-bit or 16-bit register
        self.DEF.add(REGS[inst.op1.reg%4])
        self.USE.add(REGS[inst.op1.reg%4])
      else:
        # 32-bit register
        self.DEF.add(REGS[inst.op1.reg])
      return
    # special case for 'rep' prefix
    if (pydasm.MASK_PREFIX_G1(inst.flags) ==
        pydasm.PREFIX_REP >> 24):  # argh! pydasm..
      self.USE.add('ecx')
      self.DEF.add('ecx')
      self.implicit.add('ecx')
    # special case for CMOVcc (e.g., used by less.exe)
    # be conservative, as REG1 may or may not be defined
    # and REG2 may or may not be used
    if (len(self.mnem)>=5 and self.mnem.startswith('cmov')):
      #self.DEF.add(REGS[inst.op1.reg])
      if inst.op1.type == pydasm.OPERAND_TYPE_REGISTER:
        if self.not32bit(0, inst):
          self.DEF.add(REGS[inst.op1.reg%4])
          self.USE.add(REGS[inst.op1.reg%4])
        else:
          self.DEF.add(REGS[inst.op1.reg])
          self.USE.add(REGS[inst.op1.reg])
      elif inst.op1.type == pydasm.OPERAND_TYPE_MEMORY:
        if inst.op1.reg != NUM_REGS:
          self.USE.add(REGS[inst.op1.reg])
        if inst.op1.basereg != NUM_REGS:
          self.USE.add(REGS[inst.op1.basereg])
        if inst.op1.indexreg != NUM_REGS:
          self.USE.add(REGS[inst.op1.indexreg])
      if inst.op2.type == pydasm.OPERAND_TYPE_REGISTER:
        if self.not32bit(1, inst):
          self.USE.add(REGS[inst.op2.reg%4])
        else:
          self.USE.add(REGS[inst.op2.reg])
      elif inst.op2.type == pydasm.OPERAND_TYPE_MEMORY:
        if inst.op2.reg != NUM_REGS:
          self.USE.add(REGS[inst.op2.reg])
        if inst.op2.basereg != NUM_REGS:
          self.USE.add(REGS[inst.op2.basereg])
        if inst.op2.indexreg != NUM_REGS:
          self.USE.add(REGS[inst.op2.indexreg])
      return
    # Special case for SHRD and SHLD
    # (e.g., see: https://www.felixcloutier.com/x86/SHRD.html)
    # !!!!!
    if self.mnem=='shrd' or self.mnem=='shld':
      for i, op in enumerate((inst.op1, inst.op2, inst.op3)):
        if op.type == pydasm.OPERAND_TYPE_REGISTER:
          if self.not32bit(i, inst):
            reg_mod = 4
          else:
            reg_mod = NUM_REGS
          self.USE.add(REGS[op.reg%reg_mod])
          if i==0:
            self.DEF.add(REGS[op.reg%reg_mod])
        elif op.type == pydasm.OPERAND_TYPE_MEMORY:
          if op.reg != NUM_REGS:
            self.USE.add(REGS[op.reg])
          if op.basereg != NUM_REGS:
            self.USE.add(REGS[op.basereg])
          if op.indexreg != NUM_REGS:
            self.USE.add(REGS[op.indexreg])
      return

    # normal cases
    for i, op in enumerate((inst.op1, inst.op2, inst.op3)):
      # skip FPU registers, XMM
      if (op.type == Operand.REGISTER and (
          pydasm.MASK_FLAGS(op.flags) == pydasm.F_f or               # FPU
          pydasm.MASK_AM(op.flags) in (pydasm.AM_W, pydasm.AM_V) or  # XMM
          pydasm.MASK_AM(op.flags) in (pydasm.AM_P, pydasm.AM_Q))):   # MMX
        #print ("skipping", pydasm.get_operand_string(inst, i,
        #       pydasm.FORMAT_INTEL, self.addr), "in", self.disas)
        continue
      # mark USE, DEF, or both for operands that *are* registers
      if op.type == pydasm.OPERAND_TYPE_REGISTER:
        if (op.flags & pydasm.P_r) == pydasm.P_r:
          if self.not32bit(i, inst):
            self.USE.add(REGS[op.reg%4])
          else:
            self.USE.add(REGS[op.reg])
        if (op.flags & pydasm.P_w) == pydasm.P_w:
          if self.not32bit(i, inst):
            self.DEF.add(REGS[op.reg%4])
            self.USE.add(REGS[op.reg%4])
          else:
            self.DEF.add(REGS[op.reg])
        # check for special instructions that encode reg in opcode
        if ((op.flags & pydasm.AM_REG) == pydasm.AM_REG and
            not self._is_reg_in_opcode(inst)):
          self.implicit.add(REGS[op.reg])
      elif op.type == pydasm.OPERAND_TYPE_MEMORY:
        if op.reg != NUM_REGS:
          self.USE.add(REGS[op.reg])
        if op.basereg != NUM_REGS:
          self.USE.add(REGS[op.basereg])
        if op.indexreg != NUM_REGS:
          self.USE.add(REGS[op.indexreg])
    # implicitly used registers
    for i in xrange(len(REGS)):
      if (1 << i) & inst.iop_written:
        self.DEF.add(REGS[i])
        self.implicit.add(REGS[i])
      if (1 << i) & inst.iop_read:
        self.USE.add(REGS[i])
        self.implicit.add(REGS[i])

  def __repr__(self):
    return str(self)

  def __str__(self):
    #targets = [hex(x) for x in self.succ]
    #return "%-30s %s" % (self.disas, targets)
    #return "%3d: %-30s R: %-12s W: %-12s I: %s" % (self.pos, self.disas,
    #     ','.join(self.USE), ','.join(self.DEF), ','.join(self.implicit))
    #return "%3d: %-30s IN: %-12s OUT: %s" % (self.pos,
    #    self.disas, ','.join(self.IN), ','.join(self.OUT))
    # return "%3d: 0x%08X (->0x%08X) %s" % (self.pos, self.addr, self.raddr, self.disas)
    return "%3d: 0x%08X %s \t(%s)" % (self.pos, self.addr, self.disas,
      ''.join(['%02x'%(ord(self.bytes[i]),) for i in range(len(self.bytes)) ]))
    #for reg in REGS[:8]:
    #  if reg in self.IN and reg in self.OUT:
    #    line += ' |'
    #  elif reg in self.IN:
    #    line += ' -'
    #  elif reg in self.OUT:
    #    line += ' ^'
    #  else: line += '  '
    #return line

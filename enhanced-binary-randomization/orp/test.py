#!/usr/bin/env python

# Copyright (c) 2012, Vasilis Pappas <vpappas@cs.columbia.edu>
# This file is part of Orp http://nsl.cs.columbia.edu/projects/orp

# Additionally modified by Mahmood Sharif <mahmoods@alumni.cmu.edu>
# Alternate contact is Keane Lucas <keanelucas@cmu.edu>

import unittest
import glob
import os
import util
import inp
import gadget
import insn
import func
import preserv
import equiv
import swap
import reorder

TEST="./test/"

class EquivInstrsTest(unittest.TestCase):

  # list index equals to the R/M part value of the ModR/M byte
  rm_regs = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']

  def testBothRegisters(self):
    modrm_mod = 0xC0     # 11000000  src operand is a reg (test only this case)
    modrm_regs = [ 0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x38]  
    dir_bit = 0b00000010
    for modrm_rm, reg in enumerate(self.rm_regs):
      for modrm_reg in modrm_regs:
        for opcode in equiv.both_regs+tuple(
            (op^dir_bit for op in equiv.both_regs)):
          if opcode in equiv.same_regs:
            continue
          modrm_byte = modrm_mod | modrm_rm | modrm_reg 
          i = insn.Instruction(0, bytes(chr(opcode)+chr(modrm_byte)), 0)
          self.assertTrue(equiv.check_equiv(i))
          # swapped reg, rm! 
          modrm_byte = modrm_mod | modrm_rm << 3 | modrm_reg >> 3
          nbytes = bytearray(chr(opcode ^ dir_bit)+chr(modrm_byte))
          self.assertEqual(i.cbytes, nbytes)
  
  def testSameRegisters(self):
    for opcode in equiv.same_regs:
      for modrm in equiv.same_reg_modrms:
        i = insn.Instruction(0, bytes(chr(opcode)+chr(modrm)), 0)
        self.assertTrue(equiv.check_equiv(i))
        nbytes = bytearray(chr(equiv.same_regs[opcode][0])+chr(modrm))
        self.assertEqual(i.cbytes, nbytes)

  def testAddSubOpcodeExtension(self):
    ext_mask = 0b00101000 # modrm = mod 2b | reg 3b | rm 3b
    modrm_mod = 0xC0      # 11000000 src operand is a reg (test only this case)
    for opcode in (0x80, 0x81, 0x83):
      for modrm_rm, reg in enumerate(self.rm_regs):
        for ext in (0b101000, 0b000000):
          if opcode == 0x81:
            imm, neg = '\x66\x66\x66\x66', '\x9A\x99\x99\x99'
          else:
            imm, neg = '\x66', '\x9A'
          modrm = modrm_mod | ext | modrm_rm
          i = insn.Instruction(0, bytes(chr(opcode)+chr(modrm)+imm), 0)
          self.assertTrue(equiv.check_equiv(i))
          nbytes = bytearray(chr(opcode)+chr(modrm^ext_mask)+neg)
          self.assertEqual(i.cbytes, nbytes)

  def testAddSubSimple(self):
    for opcode in equiv.equiv_addsub8:
      imm, neg = '\x66', '\x9A'
      i = insn.Instruction(0, bytes(chr(opcode)+imm), 0)
      self.assertTrue(equiv.check_equiv(i))
      nbytes = bytearray(chr(equiv.equiv_addsub8[opcode])+neg)
      self.assertEqual(i.cbytes, nbytes)
    for opcode in equiv.equiv_addsub32:
      imm, neg = '\x66\x66\x66\x66', '\x9A\x99\x99\x99'
      i = insn.Instruction(0, bytes(chr(opcode)+imm), 0)
      self.assertTrue(equiv.check_equiv(i))
      nbytes = bytearray(chr(equiv.equiv_addsub32[opcode])+neg)
      self.assertEqual(i.cbytes, nbytes)
  
  def test_XCHG_XORSUB(self):
    i = insn.Instruction(0, '\x87\xD8', 0) # xchg eax, ebx
    self.assertEqual(equiv.check_equiv(i), True)
    i = insn.Instruction(0, str(i.cbytes), 0) # xchg ebx, eax
    self.assertEqual(i.disas, "xchg ebx,eax")
    #i = insn.Instruction(0, '\x33\xF6', 0) # xor esi, esi
    #self.assertEqual(equiv.check_equiv(i), True)
    #i = insn.Instruction(0, str(i.cbytes), 0) # sub esi, esi
    #self.assertEqual(i.disas, "sub esi,esi")


class GadgetTest(unittest.TestCase):

  INPUT = TEST + "testlib/testlib.dll"

  FUNC = 0x100011D0 # FuncFullOfGadgets
  SIZE = 0x45

  def testGadget(self):

    # Expected gadgets to be extracted from FuncFullOfGadgets
    #    start           end      overlapping   red   len func
    expected = set((
        (self.FUNC+0x06, self.FUNC+0x0f, True,  False, 5, self.FUNC), 
        (self.FUNC+0x07, self.FUNC+0x0f, True,  False, 4, self.FUNC),
        (self.FUNC+0x08, self.FUNC+0x0f, True,  False, 3, self.FUNC),
        (self.FUNC+0x09, self.FUNC+0x0f, True,  False, 2, self.FUNC),
        (self.FUNC+0x0c, self.FUNC+0x0f, True,  False, 3, self.FUNC),
        (self.FUNC+0x0d, self.FUNC+0x0f, True,  False, 2, self.FUNC),
        (self.FUNC+0x11, self.FUNC+0x15, True,  False, 3, self.FUNC),
        (self.FUNC+0x12, self.FUNC+0x15, True,  False, 2, self.FUNC),
        (self.FUNC+0x17, self.FUNC+0x1b, True,  False, 3, self.FUNC),
        (self.FUNC+0x18, self.FUNC+0x1b, True,  False, 2, self.FUNC),
        (self.FUNC+0x1a, self.FUNC+0x22, True,  False, 3, self.FUNC),
        (self.FUNC+0x1d, self.FUNC+0x22, True,  False, 4, self.FUNC),
        (self.FUNC+0x1e, self.FUNC+0x22, True,  False, 4, self.FUNC),
        (self.FUNC+0x1f, self.FUNC+0x22, True,  False, 3, self.FUNC),
        (self.FUNC+0x20, self.FUNC+0x22, True,  False, 2, self.FUNC),
        (self.FUNC+0x24, self.FUNC+0x29, True,  False, 2, self.FUNC),
        (self.FUNC+0x25, self.FUNC+0x29, True,  False, 2, self.FUNC),
        (self.FUNC+0x2b, self.FUNC+0x2f, True,  False, 3, self.FUNC),
        (self.FUNC+0x2c, self.FUNC+0x2f, True,  False, 2, self.FUNC),
        (self.FUNC+0x31, self.FUNC+0x35, True,  False, 3, self.FUNC),
        (self.FUNC+0x32, self.FUNC+0x35, True,  False, 2, self.FUNC),
        (self.FUNC+0x3a, self.FUNC+0x45, True,  False, 5, self.FUNC),
        (self.FUNC+0x3c, self.FUNC+0x45, False, False, 5, self.FUNC),
        (self.FUNC+0x3e, self.FUNC+0x45, True,  False, 5, self.FUNC),
        (self.FUNC+0x3f, self.FUNC+0x45, False, False, 4, self.FUNC),
        (self.FUNC+0x40, self.FUNC+0x45, True,  False, 4, self.FUNC),
        (self.FUNC+0x41, self.FUNC+0x45, True,  False, 3, self.FUNC),
        (self.FUNC+0x42, self.FUNC+0x45, False, False, 3, self.FUNC),
        (self.FUNC+0x43, self.FUNC+0x45, False, False, 2, self.FUNC)))

    funcs = inp.load_data(self.INPUT)

    for ea, f in funcs.iteritems():
      if ea == self.FUNC:
        break
    else:
      self.fail("could not find FuncFullOfGadgets at %x" % self.FUNC)

    gadgets = gadget.find_gadgets5(self.FUNC, self.FUNC+self.SIZE)
    simple = set((g.dump_simple() for g in gadgets))
    result = set((
      (g.start, g.end, g.overlap, g.red, g.ins_num, g.func_ea) for g in simple
    ))
    self.assertEqual(expected, result)


class PydasmModificationsTest(unittest.TestCase):

  # list index equals to the R/M part value of the ModR/M byte
  rm_regs = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']

  def testVariousInstructions(self):
    instrs = [
      # bytes              USE                  DEF                  implicit                 disas
      ('\x8B\xF6',         [],                  [],                  [],                ),  # mov esi, esi
      ('\x8B\xC0',         [],                  [],                  [],                ),  # mov eax, eax
      ('\x93\x66',         ['eax','ebx'],       ['eax','ebx'],       [],                ),  # xchg eax, ebx
      ('\x89\x55\xF4',     ['ebp','edx'],       [],                  [],                ),  # mov [ebp+OFF], edx
      ('\x8B\x55\xF4',     ['ebp'],             ['edx'],             [],                ),  # mov edx, [ebp+OFF]
      ('\x89\x44\xd4\x66', ['esp','edx','eax'], [],                  [],                ),  # mov [esp+edx*8+0x66],eax
      ('\xF3\xAB',         ['eax','ecx','edi'], ['edi','ecx'],       ['eax','ecx','edi']),  # rep stosd
      ('\x98',             ['eax'],             ['eax'],             ['eax'],           ),  # cbw
      ('\x99',             ['eax'],             ['eax','edx'],       ['eax','edx'],     ),  # cwd
      ('\x8b\x4d\xf8',     ['ebp'],             ['ecx'],             [],                ),  # mov ecx,[ebp-0x8]
      ('\xf3\xa5',         ['ecx','edi','esi'], ['ecx','edi','esi'], ['ecx','edi','esi']),  # rep movsd
      ('\xDA\x4E\x1C',     ['esi'],             [],                  [],                ),  # fimull [esi+0x1c]
      ('\x0F\xCF',         [],                  ['edi'],             [],                ),  # bswap edi
      ('\xA6',             ['edi','esi'],       ['edi','esi'],       ['edi','esi'],     ),  # cmpsb
      ('\x0F\xAD\xD0',     ['edx','ecx'],       ['eax'],             ['ecx'],           ),  # shrd eax,edx 
      ('\xDD\x45\x10',     ['ebp'],             [],                  [],                ),  # fldl [ebp+0x10]
      ('\xF2\x0F\x2C\x04\x24',['esp'],          ['eax'],             [],                ),  # cvttsd2si eax,[esp]
      ('\x66\x0F\x28\xC1', [],                  [],                  [],                ),  # movapd xmm0,xmm1
      ('\x0F\x31',         [],                  ['eax','edx'],       ['eax','edx'],     ),  # rdtsc
      ('\x0F\xC1\x10',     ['eax','edx'],       ['edx'],             [],                ),  # xadd [eax],edx
      ('\x0F\xC1\xC3',     ['eax','ebx'],       ['eax','ebx'],       [],                ),  # xadd ebx,eax
      ('\x0f\x58\xc1',     [],                  [],                  [],                ),  # addps xmm0,xmm1
      ('\x0f\x58\x84\x24\xd0\x00\x00\x00',['esp'],[],                [],                ),  # addps xmm0,[esp+0xd0]
      ('\x63\x48\x65',     ['eax','ecx'],       [],                  [],                ),  # arpl [eax+0x65],cx
      ('\x62\x73\x63',     ['esi','ebx'],       [],                  [],                ),  # bound esi,[ebx+0x63]
      ('\x0f\xbc\xd0',     ['eax'],             ['edx'],             [],                ),  # bsf edx,eax
      ('\x0f\xbd\xc8',     ['eax'],             ['ecx'],             [],                ),  # bsr ecx,eax
      ('\x0f\xa3\x10',     ['eax','edx'],       [],                  [],                ),  # btr [eax],edx
      ('\xf5',             [],                  [],                  [],                ),  # cmc
      ('\xf3\x0f\xc2\xc8\x01',[],               [],                  [],                ),  # cmpss xmm1,xmm0,0x1
      ('\xf0\x0f\xb1\x11', ['ecx','edx','eax'], ['eax'],             ['eax'],           ),  # cmpxchg [ecx],edx 
      ('\x2f\x0b',         ['eax'],             ['eax'],             ['eax'],           ),  # das
      ('\x0f\x77',         [],                  [],                  [],                ),  # emms
      ('\xc8\x1e\x00\x00', ['esp','ebp'],       ['esp','ebp'],       ['esp','ebp'],     ),  # enter 0x1e,0x0
      ('\xde\xc6',         [],                  [],                  [],                ),  # faddp st(6),st(0)
      ('\xf2\x0f\x58\xfe', [],                  [],                  [],                ),  # addsd xmm7,xmm6
      ('\x0f\x44\xd1',     ['ecx'],             ['edx'],             [],                ),  # cmove edx,ecx
      ('\x66\x0f\xc2\xc1\x06',[],               [],                  [],                ),  # cmppd xmm0,xmm1,0x6
      ('\xf3\x0f\x2d\xf8', [],                  ['edi'],             [],                ),  # cvtss2si edi,xmm0
      ('\xf2\x0f\x5e\xc9', [],                  [],                  [],                ),  # divsd xmm1,xmm1
      ('\xda\x45\x9c',     ['ebp'],             [],                  [],                ),  # fiaddl [ebp-0x64]
      ('\xd9\x6d\xdc',     ['ebp'],             [],                  [],                ),  # fldcw [ebp-0x24]
      ('\xe4\x1b',         [],                  ['eax'],             ['eax'],           ),  # in al,0x1b
      ('\x0f\xad\x56',     ['edx','esi','ecx'], [],                  ['ecx'],           ),  # shrd [esi+0x0],edx,0x76
      ('\x0f\xac\x56',     ['edx','esi'],       [],                  [],                ),  # shrd [esi+0x0],edx
      ('\xed',             ['edx'],             ['eax'],             ['eax','edx'],     ),  # in eax,dx
      ('\xef',             ['eax'],             ['edx'],             ['eax','edx'],     ),  # out dx,eax
      ('\x6f',             ['edx','esi'],       ['esi'],             ['edx','esi'],     ),  # out dx,eax
      ('\x0f\xc7\x4d\x00', ['ebp','ecx','ebx','eax','edx'],['eax','edx'],['ecx','ebx','eax','edx']),  # cmpxch8b [ebp+0x0]
      ('\x66\x0f\xf7\xc1', ['edi'],             [],                  ['edi'],           ),  # maskmovdqu xmm0,xmm1
      ('\x0f\x29\x45\xa0', ['ebp'],             [],                  [],                ),  # movaps [ebp-0x60],xmm0
      ('\x0f\x7e\x04\x1a', ['edx','ebx'],       [],                  [],                ),  # movd [edx+ebx],mm0
      ('\x66\x0f\x7f\x31', ['ecx'],             [],                  [],                ),  # movdqa [ecx],xmm6
      ('\x0f\x7f\x47\x28', ['edi'],             [],                  [],                ),  # movq [edi+0x28],mm0
      ('\x0f\xdb\x45\xf8', ['ebp'],             [],                  [],                ),  # pand mm0,[ebp-0x8]
      ('\x0f\xc5\xcd\x00', [],                  ['ecx'],             [],                ),  # pextrv cx,xmm1,0x0
      ('\x66\x0f\xd7\xf8', [],                  ['edi'],             [],                ),  # pmovmskb edi,xmm7
      ('\x66\x0f\xef\xf8', [],                  [],                  [],                ),  # pxor xmm7,xmm0
      ('\x0f\x32',         ['ecx'],             ['eax','edx'],       ['eax','ecx','edx']),  # rdmsr
      ('\xd7',             ['eax','ebx'],       ['eax'],             ['eax','ebx']      ),  # xlat
    ]
    for insn_bytes, USE, DEF, implicit in instrs:
      i = insn.Instruction(0, insn_bytes, 0)
      self._assertInst(i, USE, DEF, implicit)

  def test_OpcodeEncodedRegArgs(self):
    for opcode in xrange(0x40, 0x60):
      i = insn.Instruction(0, chr(opcode), 0)
      reg = self.rm_regs[opcode % 8]
      self.assertTrue(i.regs == {reg: [(0, 0)]})
    for opcode in xrange(0x40, 0x60):
      # LOCK prefix
      i = insn.Instruction(0, '\xF0'+chr(opcode), 0)
      reg = self.rm_regs[opcode % 8]
      self.assertTrue(i.regs == {reg: [(1, 0)]})
    for opcode in xrange(0x40, 0x60):
      # LOCK prefix, branch hint
      i = insn.Instruction(0, '\xF0\x2e'+chr(opcode), 0)
      reg = self.rm_regs[opcode % 8]
      self.assertTrue(i.regs == {reg: [(2, 0)]})
    for opcode in xrange(0x40, 0x60):
      # LOCK prefix, branch hint, size override
      i = insn.Instruction(0, '\xF0\x2e\x66'+chr(opcode), 0)
      reg = self.rm_regs[opcode % 8]
      self.assertTrue(i.regs == {reg: [(3, 0)]})
    for opcode in xrange(0x40, 0x60):
      # LOCK prefix, branch hint, 2x size override
      i = insn.Instruction(0, '\xF0\x2e\x66\x67'+chr(opcode), 0)
      reg = self.rm_regs[opcode % 8]
      self.assertTrue(i.regs == {reg: [(4, 0)]})

  def test_PUSH_Reg(self):
    opcodes = ['\x50', '\x51', '\x52', '\x53', '\x54', '\x55', '\x56', '\x57']
    for opcode, reg in zip(opcodes, self.rm_regs):
      i = insn.Instruction(0, opcode, 0)
      self._assertInst(i, [reg, 'esp'], ['esp'], ['esp'])

  def test_POP_Reg(self):
    opcodes = ['\x58', '\x59', '\x5A', '\x5B', '\x5C', '\x5D', '\x5E', '\x5F']
    for opcode, reg in zip(opcodes, self.rm_regs):
      i = insn.Instruction(0, opcode, 0)
      self._assertInst(i, ['esp'], [reg, 'esp'], ['esp'])

  def test_XOR_SameRegPair(self):
    modrm_same_reg_pair = [
      ('\xC0', 'eax'),  # eax,eax
      ('\xC9', 'ecx'),  # ecx,ecx
      ('\xD2', 'edx'),  # edx,edx
      ('\xDB', 'ebx'),  # ebx,ebx
      ('\xE4', 'esp'),  # esp,esp
      ('\xED', 'ebp'),  # ebp,ebp
      ('\xF6', 'esi'),  # esi,esi
      ('\xFF', 'edi')]  # edi,edi
    for modrm, reg in modrm_same_reg_pair:
      i = insn.Instruction(0, '\x33'+modrm, 0)
      self._assertInst(i, [], [reg], [])

  def testSpecialEAXShorterVersions(self):
    inst_special_1byte = [
      # opcodes          USE      DEF
      (['\x14', '\x15'], ['eax'], ['eax']),  # adc  eax, imm32
      (['\x04', '\x05'], ['eax'], ['eax']),  # add  eax, imm32
      (['\x24', '\x25'], ['eax'], ['eax']),  # and  eax, imm32
      (['\x3C', '\x3D'], ['eax'], []     ),  # cmp  eax, imm32
      (['\xA0', '\xA1'], [],      ['eax']),  # mov  eax, moffs32
      (['\xA2', '\xA3'], ['eax'], []     ),  # mov  moffs32, eax
      (['\x0C', '\x0D'], ['eax'], ['eax']),  # or   eax, imm32
      (['\x1C', '\x1D'], ['eax'], ['eax']),  # sbb  eax, imm32
      (['\x2C', '\x2D'], ['eax'], ['eax']),  # sub  eax, imm32
      (['\xA8', '\xA9'], ['eax'], []     ),  # test eax, imm32
      (['\x34', '\x35'], ['eax'], ['eax'])]  # xor  eax, imm32
    for opcodes, reg_USE, reg_DEF in inst_special_1byte:
      for opcode in opcodes:
        i = insn.Instruction(0, opcode+'\xDE\xAD\xBE\xEF', 0)
        self._assertInst(i, reg_USE, reg_DEF, ['eax'])

    # xchg (0x90+rw and 0x90+rb)
    for rd in range(1,8):  # skip NOP (synonymous to xchg eax,eax)
      i = insn.Instruction(0, bytes(chr(0x90+rd)), 0)
      reg = self.rm_regs[rd]
      self._assertInst(i, ['eax', reg], ['eax', reg], [])

    # NOP
    i = insn.Instruction(0, '\x90', 0)
    self._assertInst(i, [], [], [])

  def test_MUL_and_IMUL_OneOperand(self):
    modrm_mod = 0xC0     # 11000000  src operand is a reg (test only this case)
    for modrm_rm, reg in enumerate(self.rm_regs):
      modrm_reg = 0x20   # 00100000  opcode extension for mul (F6/4 and F7/4)
      modrm_byte = modrm_mod | modrm_reg | modrm_rm
      # F6/4 - mul r/m8
      i = insn.Instruction(0, '\xF6'+bytes(chr(modrm_byte)), 0)
      self._assertInst(i, ['eax', reg], ['eax'], ['eax'])
      # F7/4 - mul r/m16 and imul r/m32
      i = insn.Instruction(0, '\xF7'+bytes(chr(modrm_byte)), 0)
      self._assertInst(i, ['eax', reg], ['eax','edx'], ['eax','edx'])
      modrm_reg = 0x28   # 00101000  ext. for one-operand imul (F6/5 and F7/5)
      modrm_byte = modrm_mod | modrm_reg | modrm_rm
      # F6/5 - imul r/m8
      i = insn.Instruction(0, '\xF6'+bytes(chr(modrm_byte)), 0)
      self._assertInst(i, ['eax', reg], ['eax'], ['eax'])
      # F7/5 - imul r/m16 and imul r/m32
      i = insn.Instruction(0, '\xF7'+bytes(chr(modrm_byte)), 0)
      self._assertInst(i, ['eax', reg], ['eax','edx'], ['eax','edx'])

  def test_DIV_and_IDIV(self):
    modrm_mod = 0xC0     # 11000000  src operand is a reg (test only this case)
    for modrm_rm, reg in enumerate(self.rm_regs):
      modrm_reg = 0x30   # 00110000  opcode extension for div (F6/6 and F7/6)
      modrm_byte = modrm_mod | modrm_reg | modrm_rm
      # F6/6 - div r/m8
      i = insn.Instruction(0, '\xF6'+bytes(chr(modrm_byte)), 0)
      self._assertInst(i, ['eax', reg], ['eax'], ['eax'])
      # F7/6 - div r/m16 and div r/m32
      i = insn.Instruction(0, '\xF7'+bytes(chr(modrm_byte)), 0)
      self._assertInst(i, ['eax', 'edx', reg], ['eax','edx'], ['eax','edx'])
      modrm_reg = 0x38   # 00111000  opcode extension for idiv (F6/7 and F7/7)
      modrm_byte = modrm_mod | modrm_reg | modrm_rm
      # F6/7 - idiv r/m8
      i = insn.Instruction(0, '\xF6'+bytes(chr(modrm_byte)), 0)
      self._assertInst(i, ['eax', reg], ['eax'], ['eax'])
      # F7/7 - idiv r/m16 and div r/m32
      i = insn.Instruction(0, '\xF7'+bytes(chr(modrm_byte)), 0)
      self._assertInst(i, ['eax', 'edx', reg], ['eax','edx'], ['eax','edx'])

  def test_RCL_RCR_ROL_ROR_SAL_SAR_SHL_SHR(self):
    modrm_mod = 0xC0     # 11000000  src operand is a reg (test only this case)
    opcodes =    ['\xD0', '\xD1', '\xC0', '\xC1']  # ROX/SHX one or imm8 times
    opcodes_cl = ['\xD2', '\xD3']     # ROX/SHX CL times (implied ecx register)
    #                /0    /1    /2    /3    /4    /5    /7  
    modrm_regs = [ 0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x38] 
    for modrm_rm, reg in enumerate(self.rm_regs):
      for modrm_reg in modrm_regs:
        for opcode in opcodes:
          modrm_byte = modrm_mod | modrm_reg | modrm_rm
          i = insn.Instruction(0, opcode+bytes(chr(modrm_byte))+'\x0f', 0)
          self._assertInst(i, [reg], [reg], [])
        for opcode in opcodes_cl:
          modrm_byte = modrm_mod | modrm_reg | modrm_rm
          i = insn.Instruction(0, opcode+bytes(chr(modrm_byte)), 0)
          self._assertInst(i, [reg, 'ecx'], [reg], ['ecx'])

  def test_SIB_bug(self):
    i = insn.Instruction(0, '\x8D\x04\x85\x5C\x8A\x01\x07', 0)
    #print i.disas, i.USE, i.DEF, i.implicit, i.regs
    self.assertEqual(i.regs, {'eax': [(2L, 3), (1L, 3)]})
  
  def test_OpcodeExtension_bug(self):
    i = insn.Instruction(0, '\xD3\xF8', 0) # sar eax, cl
    self.assertEqual(i.regs, {'eax': [(1L, 0)]})
 
  def test_CALL_bug(self):
    i = insn.Instruction(0, '\xFF\xD6', 0) # call esi
    self.assertEqual(i.regs, {'esi': [(1L, 0)]})
    self.assertEqual(i.USE, set(('esi', 'esp')))

  def test_8bitRegisters(self):
    i = insn.Instruction(0, '\x84\xDB', 0)  # test bl, bl
    self.assertEqual(i.swap_registers('ebx', 'esi'), False)
    self.assertEqual(i.swap_registers('ebx', 'eax'), True)
  
  def _assertInst(self, i, USE, DEF, implicit):
    self.assertEqual((i.USE, i.DEF, i.implicit),
                     (set(USE), set(DEF), set(implicit)),
                     "%s: %s != %s"%(i.disas, (i.USE, i.DEF, i.implicit),
                     (set(USE), set(DEF), set(implicit))))


class ReorderingTest(unittest.TestCase):

  INPUT = TEST + "testlib/testlib.dll"
  FUNC = 0x100012A0  # FuncFullOfReordering
  BBL1, BBL2 = FUNC+0x19, FUNC+0x28

  def testReordering(self):
    # Expected edges in the DAG of each basic block
    expected = [
      set([(23, 24), (23, 25), (23, 26),
           (20, 22), (20, 25), (20, 26),
           (21, 22), (21, 26), (25, 27)]),
      set([(14, 15), (13, 15), (13, 16)]),
    ]

    funcs = inp.load_data(self.INPUT)

    for ea, f in funcs.iteritems():
      if ea == self.FUNC:
        break
    else:
      self.fail("could not find FuncFullOfReordering at %x" % self.FUNC)

    result = []

    for bb in f.blocks:
      if bb.begin not in (self.BBL1, self.BBL2):
        continue
      dag = reorder.BuildBBDependenceDAG(bb)
      result.append(set([(i1.pos, i2.pos) for i1, i2 in dag.edges()]))

    self.assertEqual(expected, result)


class MatrixMultTest(unittest.TestCase):

  PROG = TEST + "testlib/main.exe"
  INPUT = TEST + "testlib/testlib.dll"
  FUNC = 0x10001120 # MatrixMult
  EXPECT = "24 30 36 24 30 36 24 30 36"

  def setUp(self):
    funcs = inp.load_data(self.INPUT)
    for ea, f in funcs.iteritems():
      if ea == self.FUNC:
        break
    else:
      self.fail("could not find MatrixMult at %x" % self.FUNC)
    self.f = f

  def testExecuteEquiv(self):

    GEN_FILE = TEST + "testlib/testlib_patched-equiv.dll"

    changed_bytes = equiv.do_equiv_instrs(self.f.instrs, gen_patched=True)
    # check the number of changed bytes
    self.assertEqual(len(changed_bytes), 13)
    # check the numner of generated files
    self.assertEqual(len(glob.glob(GEN_FILE)), 1)
    output = util.run("%s %s"%(self.PROG, GEN_FILE), 10)
    # check the output of the generated files
    self.assertTrue(
        self.EXPECT in output, "%s: %s %s"%(GEN_FILE, self.EXPECT, output))
    # remove the generated files
    map(os.remove, glob.glob(GEN_FILE))

  def testExecutePreserv(self):

    GEN_FILES = TEST + "testlib/testlib_patched-preserv*.dll"

    # fill in the reg_pairs list (needed by preserv)
    self.f.analyze_registers({})
    preservs, avail_regs = preserv.get_reg_preservations(self.f)
    changed_bytes = preserv.do_reg_preservs(self.f.instrs, self.f.blocks,
                            preservs, avail_regs, gen_patched=True)
    # check the number of changed bytes
    self.assertEqual(len(changed_bytes), 17)
    # check the numner of generated files
    self.assertEqual(len(glob.glob(GEN_FILES)), 1)
    # check the output of the generated files
    for genf in glob.glob(GEN_FILES):
      output = util.run("%s %s" % (self.PROG, genf), 10)
      self.assertTrue(
          self.EXPECT in output, "%s: %s %s" % (genf, self.EXPECT, output))
    # remove the generated files
    map(os.remove, glob.glob(GEN_FILES))

  def testExecuteReorder(self):

    GEN_FILE = TEST + "testlib/testlib_patched-reorder.dll"

    changed_bytes = reorder.do_reordering(self.f.blocks, gen_patched=True)
    # check the number of changed bytes
    self.assertEqual(len(changed_bytes), 56)
    # check the numner of generated files
    self.assertEqual(len(glob.glob(GEN_FILE)), 1)
    # check the output of the generated files
    output = util.run("%s %s"%(self.PROG, GEN_FILE), 10)
    self.assertTrue(
        self.EXPECT in output, "%s: %s %s" % (GEN_FILE, self.EXPECT, output))
    # remove the generated files
    map(os.remove, glob.glob(GEN_FILE))

  def testExecuteSwap(self):

    GEN_FILES = TEST + "testlib/testlib_patched-swap*.dll"

    # MatrixMul calls no other functions, so we perfom a minimal analysis
    self.f.update_calls()
    self.f.analyze_registers({})
    self.f.update_returns(set_default=True)

    swap.liveness_analysis(self.f.code)
    live_regs = swap.get_reg_live_subsets(
        self.f.instrs, self.f.code, self.f.igraph)
    #TODO: swap.split_live_regions(live_regions)
    swaps = swap.get_reg_swaps(live_regs)
    # generates: test/testlib/testlib_patched-swap-XXXXXX.dll
    changed_bytes = swap.do_single_swaps(swaps, gen_patched=True)
    # check the number of changed bytes
    self.assertEqual(len(changed_bytes), 44)
    # check the numner of generated files
    self.assertEqual(len(glob.glob(GEN_FILES)), 42)
    # check the output of the generated files
    for genf in glob.glob(GEN_FILES):
      output = util.run("%s %s"%(self.PROG, genf), 10)
      self.assertTrue(
          self.EXPECT in output, "%s: %s %s" % (genf, self.EXPECT, output))
    # remove the generated files
    map(os.remove, glob.glob(GEN_FILES))


class MD5Test(unittest.TestCase):

  PROG = TEST + "md5/main.exe"
  INPUT = TEST + "md5/md5.dll"
  FUNC = 0x10001040 # MD5Update
  EXPECT = "d174ab98d277d9f5a5611c2c9f419d9f"
  GEN_FILES = TEST + "md5/md5_patched-*.dll"

  def testAll(self):

    funcs = inp.load_data(self.INPUT)

    for ea, f in funcs.iteritems():
      if ea == self.FUNC:
        break
    else:
      self.fail("could not find MD5Update at %x" % self.FUNC) 

    # analyze
    levels = func.classify_functions(funcs)
    func.analyze_functions(funcs, levels)

    # swap
    swap.liveness_analysis(f.code)
    live_regs = swap.get_reg_live_subsets(f.instrs, f.code, f.igraph)
    swap.split_reg_live_subsets(live_regs, f.code)
    swaps = swap.get_reg_swaps(live_regs)
    swap.do_single_swaps(swaps, gen_patched=True)

    # preserv
    preservs, avail_regs = preserv.get_reg_preservations(f)
    preserv.do_reg_preservs(f.instrs, f.blocks, preservs,
                            avail_regs, gen_patched=True)
    # equiv
    equiv.do_equiv_instrs(f.instrs, gen_patched=True)

    # reorder
    reorder.do_reordering(f.blocks, gen_patched=True)

    # check the numner of generated files
    print self.assertEqual(len(glob.glob(self.GEN_FILES)), 50)

    for genf in glob.glob(self.GEN_FILES):
      output = util.run("%s %s" % (self.PROG, genf), 10)
      self.assertTrue(
          self.EXPECT in output, "%s: %s %s" % (genf, self.EXPECT, output))
    # remove the generated files
    map(os.remove, glob.glob(self.GEN_FILES))


if __name__ == '__main__':
  runner = unittest.TextTestRunner(verbosity=2)
  unittest.main(testRunner = runner)

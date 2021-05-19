# Copyright (c) 2021, Mahmood Sharif, Keane Lucas, Michael K. Reiter, Lujo Bauer, and Saurabh Shintre
# This file is code used in Malware Makeover

"""
An implementation of code-diplacement, inspired by
Koo and Polychronakis' implementation.
"""
import random
import semnops
import peLib
import pefile
import struct
import os
import math
import inp
import func
from randtoolkit import patch

# opcodes using addresses relative to EIP
# (taken from Koo and Polychronakis)
EIP_RELATIVE_OPS = {'call': 0xe8, 'ja': 0x870f, 'jae': 0x830f, \
                    'jb': 0x820f, 'jbe': 0x860f, 'jc': 0x820f, \
                    'je': 0x840f, 'jg': 0x8f0f, 'jge': 0x8d0f, \
                    'jl': 0x8c0f, 'jle': 0x8e0f, 'jmp': 0xe9,  \
                    'jna': 0x860f, 'jnae': 0x820f, 'jnb': 0x830f, \
                    'jnbe': 0x870f, 'jnc': 0x830f, 'jne': 0x850f, \
                    'jng': 0x8e0f, 'jnge': 0x8c0f, 'jnl': 0x8d0f, \
                    'jnle': 0x8f0f, 'jno': 0x810f, 'jnp': 0x8b0f, \
                    'jns': 0x890f, 'jnz': 0x850f, 'jo': 0x800f, \
                    'jp': 0x8a0f, 'jpe': 0x8a0f, 'jpo': 0x8b0f, \
                    'js': 0x880f, 'jz': 0x840f}
EIP_RELATIVE_1B = {0xE3: 'jmp', 0xE8: 'call', 0xE9: 'jmp', 0xEB: 'jmp', \
                   0x70: 'jo', 0x71: 'jno', 0x72: 'jb', 0x73: 'jae', \
                   0x74: 'je', 0x75: 'jne', 0x76: 'jbe', 0x77: 'jnbe', \
                   0x78: 'js', 0x79: 'jns', 0x7A: 'jp', 0x7B: 'jnp', \
                   0x7C: 'jl', 0x7D: 'jnl', 0x7E: 'jle', 0x7F: 'jg'}
EIP_RELATIVE_2B = set([0x800F, 0x810F, 0x820F, 0x830F, 0x840F, 0x850F, \
                       0x860F, 0x870F, 0x880F, 0x890F, 0x8A0F, 0x8B0F, \
                       0x8C0F, 0x8D0F, 0x8E0F, 0x8F0F])

def _block_size(block):
    """
    return the block's size in bytes
    """
    return sum([len(ins.bytes) for ins in block.instrs])

def _non_displaceable(ins):
    """
    decides whether a certain instruction is not displaceable
    (e.g., if it contains addresses relative to eip).
    For now, avoid displacing instructions that transfer control
    to non-consecutive instruction that are not relative to EIP.
    """
    global EIP_RELATIVE_OPS
    global EIP_RELATIVE_1B
    global EIP_RELATIVE_2B
    if ins.mnem.lower() in EIP_RELATIVE_OPS:
        if (not ord(ins.bytes[0]) in EIP_RELATIVE_1B) and \
           (not (ord(ins.bytes[0]) + ord(ins.bytes[1])*256) in EIP_RELATIVE_2B):
            return True
    return False

def _is_displaced(ins):
    """
    returns whether an instruction has been displaced already 
    """
    return hasattr(ins, 'displaced') and ins.displaced

def _displaceable_instrs(block, max_bytes=None):
    """
    Given a block, return a list of tuples denoting instructions
    that can be displaced. Each tuple has 4 entries (i0, i1, i2, s).
    i0 points to the starting instruction, i1 denotes the minimum
    number of instructions starting of i0 that can be displaced, 
    and i2 denotes the maximum. I.e., one can displace instructions 
    i0:i0+i1, or i0:i0+i1+1, ..., or i0+i2. s is the number of bytes
    contained in the instructions i0:i0+i2.

    Keep in mind that one needs to displace at least 5 bytes, since
    the 5-bytes-long jump replacing the displaced instructions needs
    a place to fit.
    """
    
    # sort instructions by their addresses
    instrs = block.instrs
    instrs.sort(key=lambda ins: ins.addr)

    displaceable = []
    for i0 in range(len(instrs)):
        ins = instrs[i0]
        if _is_displaced(ins) or _non_displaceable(ins):
            continue

        # find min (if any)
        i1 = 1
        s = len(ins.bytes)
        while i0+i1<len(instrs) and s<5:
            ins = instrs[i0+i1]
            if _is_displaced(ins) or _non_displaceable(ins):
                break
            if (not max_bytes is None) and s+len(ins.bytes)>max_bytes:
                break
            s += len(ins.bytes)
            i1 += 1
            
        # if couldn't find at least 5-bytes-long, consecutive
        # instructions starting at i0 that are possible to
        # displace, then skip
        if s<5:
            continue
        
        # find max
        i2 = i1 + 1
        while i0+i2<=len(instrs):
            ins = instrs[i0+i2-1]
            if _is_displaced(ins) or _non_displaceable(ins):
                break
            s += len(ins.bytes)
            i2 += 1
        i2 -= 1
        
        # update displaceable
        displaceable.append((i0,i1,i2,s))
        
    # done
    return displaceable

def _compute_diffs(instrs, fill_bytes):
    """
    compute the diffs needed to replace the displaced bytes
    """
    i = 0
    addr = instrs[0].addr
    diffs = []
    for ins in instrs:
        bytes = ins.bytes
        if hasattr(ins, 'bytes_before'):
            bytes = ins.bytes_before
        for b in bytes:
            if b!=fill_bytes[i]:
                diffs.append((addr+i, b, fill_bytes[i]))
            i += 1
    return diffs

def _extract_rel_addr(op_bytes, mnemonic_type):
        """
        Extract the relative address at the level from the
        binary operation (borrowed from Koo's and Polychronakis'
        implementation).
        """
        addr = 0x0
        mask = 0x0

        # Aside from mnemonic bytes, all remaining bytes would be a
        # target address (1B, 2B, or 4B). 'Mask' helps to convert a
        # negative value if target address is less than 4B
        for i in range(len(op_bytes[mnemonic_type:])):
            addr |= ord(op_bytes[mnemonic_type + i]) << (8 * i)
        if mnemonic_type == 1:  # 1 byte
            mask |= 0xffffff00
        if mnemonic_type == 2:  # 2 bytes
            mask |= 0xffff0000

        # If MSB is set in a target address, the result should be
        # masked - check some examples:
        #   1B: [0x74, 0xc] -> 0xe
        #   1B: [0xeb, 0xed] -> 0xffffffef (not 0xef)
        #   1B: [0xe9, 0xd6, 0xa9, 0xff, 0xff] -> 0xffffa9db
        #   2B: [0x0f, 0x84, 0x88, 0x0, 0x0, 0x0] -> 0x8e
        if (i + 1 == 1 and ord(op_bytes[1]) & (1 << (8 * mnemonic_type - 1)) > 0) or \
                (i + 1 == 2 and ord(op_bytes[3]) & (1 << (8 * mnemonic_type - 1)) > 0):
            return mask | (addr + len(op_bytes))
        return addr + len(op_bytes)

def _get_eip_relative_addr(ins, disp_addr):
    """
    given an instruction with operation relative to EIP,
    update the instruction's bytes so that it would work
    after displacement.
    """
    # find mnem type
    global EIP_RELATIVE_1B
    global EIP_RELATIVE_2B
    mnem_type = 0
    if ord(ins.bytes[0]) in EIP_RELATIVE_1B:
        mnem_type = 1
    elif ord(ins.bytes[0]) + ord(ins.bytes[1])*256 in EIP_RELATIVE_2B:
        mnem_type = 2
    # if instruction is truly relative to EIP, then
    # store the old bytes, and update the address
    new_bytes = None
    if mnem_type>0:
        try:
            rel_addr = _extract_rel_addr(ins.bytes, mnem_type)
        except:
            return None
        new_addr = ((rel_addr - disp_addr + ins.addr) & 0xffffffff)
        if mnem_type==1:
            mnem_bytes = EIP_RELATIVE_OPS[EIP_RELATIVE_1B[ord(ins.bytes[0])]]
            if mnem_bytes<=0xff:
                new_bytes = struct.pack('<B', mnem_bytes) + \
                            struct.pack('<I', new_addr-5)
            else:
                new_bytes = struct.pack('<H', mnem_bytes) + \
                            struct.pack('<I', new_addr-6)
        else:
            new_bytes = ins.bytes[:mnem_type] + struct.pack('<I', new_addr-6)
    return new_bytes
    
def _merge_file(output):
    """
    used for merging with /tmp/reloc.dat when the
    reloc section needs updating
    """
    reloc_file = '/tmp/reloc.dat' if os.name == 'posix' else 'reloc.dat'
    final_file = output.split('.')[0] + '.final'
    pe_out, epilog = peLib.read_pe(output)

    for s in range(pe_out.FILE_HEADER.NumberOfSections):
        if 'reloc' in pe_out.sections[s].Name:
            reloc_ptr = pe_out.sections[s].PointerToRawData
            break
    reloc_size = pe_out.sections[s].SizeOfRawData

    with open(output, 'rb') as f1:
        result_file = f1.read()
    with open(reloc_file, 'rb') as f2:
        reloc_data = f2.read()

    # Merge process: [pre_reloc_bin + new_reloc_bin + post_reloc_bin]
    if reloc_size - len(reloc_data) >= 0:
        merged = result_file[:reloc_ptr] + reloc_data + \
                 (reloc_size - len(reloc_data)) * '\x00' + \
                 result_file[reloc_ptr + reloc_size:]
    else:
        # This would happen rarely, but possible
        print 'The size of adjusted relocation is larger than that of original one..'
        #it happened and caused an error. Changed this to an Exception rather than sys.exit(1)
        raise Exception('The size of adjusted relocation is larger than that of original one.')

    with open(final_file, 'wb') as f3:
        f3.write(merged)

    pe_out.close()
    f1.close()
    f2.close()
    f3.close()
    os.remove(reloc_file)

    # The following does not work in windows only!
    if os.name == 'posix':
        os.remove(output)
        os.rename(final_file, output)

class DispState:
    """
    A class for maintaining the state of displacements
    and coordinating future ones.
    """

    def __init__(self, pe, epilog=''):
        self.pe = pe             # a pefile object
        self.epilog = epilog     # an epilog that should be appended to the PE
        self.peinfo =  \
               peLib.PEInfo(pe)  # a peinfo object
        self.ndisps = 0          # number of displacements performed
        self.dbytes = 0          # number of displaced bytes (excl. added jumps)
        self.ropf_offset = 0     # offset within the ropf section
        self.moving_regions = [] # list of (start addr, mov size, .ropf start addr)
        self.moving_instrs = []  # list of tuples (instrs list, jmp bytes if any)
        self.init_ropf_start()


    def init_ropf_start(self):
        """
        Use to init ropf_start, while handling non-standard 
        cases
        """
        self.ropf_start = self.peinfo.getImageBase() + \
                ( self.peinfo.getRVA(-1) + \
                  self.peinfo.getVirtualSize(-1) -
                  self.peinfo.getVirtualSize(-1) % self.peinfo.getSectionAlignment()  + \
                  self.peinfo.getSectionAlignment() )

    def add_disp(self, instrs, semnop_bins, jmp_bin, total_bytes):
        """
        add a new displacement, and update the state as necessary
        """
        self.ndisps += 1
        self.dbytes += total_bytes
        n_semnop_bytes = sum([len(semnop_bin) for semnop_bin in semnop_bins])
        self.ropf_offset += sum([len(ins.bytes) for ins in instrs]) + \
                            + n_semnop_bytes + len(jmp_bin)
        self.moving_regions.append( (instrs[0].addr, \
                                     total_bytes, \
                                     instrs[0].disp_addr) )
        self.moving_instrs.append( (instrs, semnop_bins, jmp_bin) )
        

    def get_dbin(self):
        """
        get the binary representation of .ropf section
        """
        dbin = ''
        for instrs, semnop_bins, jmp_bin in self.moving_instrs:
            for ins in instrs:
                dbin += ins.bytes
            dbin += ''.join([''.join(semnop_bin) for semnop_bin in semnop_bins])
            dbin += jmp_bin
        return dbin


def displace_w_budget(functions, disp_state, budget, min_dpf=200, max_disp_instrs=10):
    """
    perform displacement, but make sure that the binary's size
    after displacement increases by the given ~budget.

    min_dpf: minimum number of bytes to displace per function.
    max_disp_instrs: desired maximum number of instructions to displace per block.
    """

    # shuffle the order of functions
    functions = [f for f in filter(lambda x: x.level != -1, functions.itervalues()) \
                 if not '_SEH_' in f.name]
    random.shuffle(functions)

    # compute avg. budget per function:
    #   budget / # displaceable functions
    ndf = 0 # number of displaceable functions
    for f in functions:
        for block in f.blocks:
            displaceable = _displaceable_instrs(block)
            if displaceable:
                ndf += 1
                break
    avg_bpf = int(math.ceil(budget/ndf)) # budget per function

    # update min_dpf
    min_dpf = max(avg_bpf, min_dpf, 5)

    # perform displacements, up to budget
    all_diffs = []
    for f in functions:
        max_dpf = budget - len(disp_state.get_dbin()) - 5
        min_dpf = min(min_dpf, max_dpf)
        diffs, _, _ = displace_block(f, disp_state, min_dpf, \
                                     max_dpf, max_disp_instrs=max_disp_instrs)
        if len(diffs)>0:
            all_diffs.extend(diffs)
            if len(disp_state.get_dbin())>=budget:
                break

    return all_diffs

def displace_block(f, disp_state, min_dpf=None, max_dpf=None, \
                   semnop_chunk_sz=50, max_disp_instrs=None):
    """
    Select a block at random and displace it
    """
    
    # find non displaced blocks, and select one to
    # displace at random
    can_displace = {}
    for block in f.blocks:
        displaceable = _displaceable_instrs(block, max_dpf)
        if displaceable:
            can_displace[block] = displaceable

    # if cannot displace any part of any block
    if len(can_displace)==0:
        return [], set(), set()

    # select a block and instructions within it
    # to perform displacement
    block = random.choice(can_displace.keys())
    displaceable = random.choice(can_displace[block])
    # displaceable = max(can_displace[block], key=lambda x: x[3])
    s_i = displaceable[0]
    if not max_disp_instrs is None:
        e_i = s_i + random.randint( displaceable[1], \
                                   max(displaceable[1], min(max_disp_instrs,displaceable[2])) )
    else:
        e_i = s_i + random.randint(displaceable[1], displaceable[2])
    instrs = block.instrs[s_i:e_i]

    # update the addresses of diplaced bytes in f (these bytes,
    # e.g., can be replaced with semantic nops)
    addresses = (instrs[0].addr, instrs[-1].addr+len(instrs[-1].bytes)-1)
    if hasattr(f, 'displaced_bytes'):
        f.displaced_bytes.append(addresses)
    else:
        f.displaced_bytes = [addresses]
    
    # set the instructions as displaced, and update their new
    # addresses after displacement, and update the opcodes of
    # instructions that are relative to EIP
    global EIP_RELATIVE_OPS
    total_bytes = 0
    disp_offset = 0
    for ins in instrs:
        ins.displaced = True
        ins.disp_addr = disp_state.ropf_start + \
                        disp_state.ropf_offset + \
                        disp_offset
        total_bytes += len(ins.bytes)
        if ins.mnem.lower() in EIP_RELATIVE_OPS:
            new_bytes = _get_eip_relative_addr(ins, ins.disp_addr)
            if not new_bytes is None:
                ins.bytes_before = ins.bytes
                ins.bytes = new_bytes
        disp_offset += len(ins.bytes)
    assert(total_bytes>=5), 'don\'t have enough bytes to displace'
    
    # set the diffs needed to fill the void (jump + nops) created
    # after displacement
    jmp_val = disp_state.ropf_start+disp_state.ropf_offset-instrs[0].addr-5
    fill_bytes = struct.pack('<B', 0xE9) + struct.pack('<i', jmp_val) + \
                 semnops.get_semantic_nop(total_bytes-5)
    diffs = _compute_diffs(instrs, fill_bytes)

    # if min_dpf is provided, make sure the displaced bytes occupy
    # at least min_dpf bytes
    if min_dpf is None:
        semnop_bins = [[]]
        has_semnop_bins = False
        n_semnop_bytes = 0
    else:
        n_semnop_bytes = min_dpf-disp_offset-5
        if instrs[-1].mnem=='ret':
            n_semnop_bytes += 5
        if n_semnop_bytes==0:
            semnop_bins = [[]]
            has_semnop_bins = False
        else:
            semnop_bins = []
            semnop_bins_offsets = []
            for i in range(0, n_semnop_bytes, semnop_chunk_sz):
                semnop_bin = semnops.get_semantic_nop( min(semnop_chunk_sz, \
                                                           n_semnop_bytes-i) )
                semnop_bin = [b for b in semnop_bin]
                semnop_bins.append(semnop_bin)
                semnop_bins_offsets.append(disp_state.ropf_offset+disp_offset+i)
            has_semnop_bins = True
    
    # compute the opcode for the jump needed to return to the
    # correct instruction after running the displaced code
    if instrs[-1].mnem=='ret':
        # no need for a jmp after a return (possibly jmp too,
        # but I've seen cases where jmp was treated as call)
        jmp_bin = ''
    else:
        jmp_back_val = instrs[-1].addr-instrs[-1].disp_addr-total_bytes-n_semnop_bytes
        if hasattr(instrs[-1], 'bytes_before'):
            jmp_back_val -= (len(instrs[-1].bytes)-len(instrs[-1].bytes_before))
        jmp_bin = struct.pack('<B', 0xE9) + struct.pack('<i', jmp_back_val)

    # update lists of semnops in f that will be in the .ropf section
    if has_semnop_bins:
        if hasattr(f, 'ropf_semnops'):
            f.ropf_semnops.extend(semnop_bins)
            f.ropf_semnops_offsets.extend(semnop_bins_offsets)
        else:
            f.ropf_semnops = semnop_bins
            f.ropf_semnops_offsets = semnop_bins_offsets
    
    # update the global displacement state
    disp_state.add_disp(instrs, semnop_bins, jmp_bin, total_bytes)
    
    # # debug
    # print('-> Displaced instructions:')
    # for ins in instrs:
    #     print('%s (disp addr: %08X)'%(ins, ins.disp_addr))
    # import pydasm
    # if jmp_bin:
    #     inst = pydasm.get_instruction(jmp_bin, pydasm.MODE_32)
    #     jmp_addr = instrs[-1].disp_addr+len(instrs[-1].bytes)
    #     disasm = pydasm.get_instruction_string(inst, \
    #                                            pydasm.FORMAT_INTEL, \
    #                                            jmp_addr)
    #     print('* jump back ins:\n\t%s\n'%disasm)
    # else:
    #     print('')
        
    # done
    changed_instrs = set(instrs)
    changed_bytes = set([addr for addr, _, _ in diffs])
    return diffs, changed_bytes, changed_instrs

def transfer_disp_payload(target_binary, disp_state_source):

    # from disp_state_source, extract the semnops that
    # should be added to the target binary
    trans_semnops_bin = ''
    for instrs, semnop_bins, jmp_bin in disp_state_source.moving_instrs:
        n_ins_bytes = 0
        for ins in instrs:
            n_ins_bytes += len(ins.bytes)
        trans_semnops_bin += semnops.get_semantic_nop(n_ins_bytes) + \
                ''.join([''.join(semnop_bin) for semnop_bin in semnop_bins]) + \
                semnops.get_semantic_nop(len(jmp_bin))
        
    # load pe, functions, and init disp_state
    pe, epilog = peLib.read_pe(target_binary)
    disp_state = DispState(pe)
    functions = inp.get_functions(target_binary)
    levels = func.classify_functions(functions)
    func.analyze_functions(functions, levels)

    # find a function to transfer the semnops to
    candidate_functions = []
    for f in filter(lambda x: x.level != -1, functions.itervalues()):
        if "_SEH_" in f.name:  
            continue
        for block in f.blocks:
            displaceable = _displaceable_instrs(block)
            if displaceable:
                candidate_functions.append(f)
                break
    assert(len(candidate_functions)>0)
    f = random.choice(candidate_functions)

    ######################################
    # starting here transfer the payload #
    # to one of the blocks in f ....     #
    ######################################

    # find non displaced blocks, and select one to
    # displace at random
    can_displace = {}
    for block in f.blocks:
        displaceable = _displaceable_instrs(block)
        if displaceable:
            can_displace[block] = displaceable

    # select a block and instructions within it
    # to perform displacement
    block = random.choice(can_displace.keys())
    displaceable = random.choice(can_displace[block])
    s_i = displaceable[0]
    e_i = s_i + random.randint(displaceable[1], displaceable[2])
    instrs = block.instrs[s_i:e_i]

    # update the addresses of diplaced bytes in f (these bytes,
    # e.g., can be replaced with semantic nops)
    addresses = (instrs[0].addr, instrs[-1].addr+len(instrs[-1].bytes)-1)
    if hasattr(f, 'displaced_bytes'):
        f.displaced_bytes.append(addresses)
    else:
        f.displaced_bytes = [addresses]

    # set the instructions as displaced, and update their new
    # addresses after displacement, and update the opcodes of
    # instructions that are relative to EIP
    global EIP_RELATIVE_OPS
    total_bytes = 0
    disp_offset = 0
    for ins in instrs:
        ins.displaced = True
        ins.disp_addr = disp_state.ropf_start + \
                        disp_state.ropf_offset + \
                        disp_offset
        total_bytes += len(ins.bytes)
        if ins.mnem.lower() in EIP_RELATIVE_OPS:
            new_bytes = _get_eip_relative_addr(ins, ins.disp_addr)
            if not new_bytes is None:
                ins.bytes_before = ins.bytes
                ins.bytes = new_bytes
        disp_offset += len(ins.bytes)
    assert(total_bytes>=5), 'don\'t have enough bytes to displace'

    # set the diffs needed to fill the void (jump + nops) created
    # after displacement
    jmp_val = disp_state.ropf_start+disp_state.ropf_offset-instrs[0].addr-5
    fill_bytes = struct.pack('<B', 0xE9) + struct.pack('<i', jmp_val) + \
                 semnops.get_semantic_nop(total_bytes-5)
    diffs = _compute_diffs(instrs, fill_bytes)

    # set semnop bins and their offsets
    semnop_bins = [[b for b in trans_semnops_bin]]
    semnop_bins_offsets = [disp_state.ropf_offset+disp_offset]

    # compute the opcode for the jump needed to return to the
    # correct instruction after running the displaced code
    if instrs[-1].mnem=='ret':
        # no need for a jmp after a return (possibly jmp too,
        # but I've seen cases where jmp was treated as call)
        jmp_bin = ''
    else:
        jmp_back_val = instrs[-1].addr-instrs[-1].disp_addr-total_bytes-len(trans_semnops_bin)
        if hasattr(instrs[-1], 'bytes_before'):
            jmp_back_val -= (len(instrs[-1].bytes)-len(instrs[-1].bytes_before))
        jmp_bin = struct.pack('<B', 0xE9) + struct.pack('<i', jmp_back_val)

    # update lists of semnops in f that will be in the .ropf section
    f.ropf_semnops = semnop_bins
    f.ropf_semnops_offsets = semnop_bins_offsets

    # update the global displacement state
    disp_state.add_disp(instrs, semnop_bins, jmp_bin, total_bytes)

    # path the pe and add displaced stuff
    patch(pe, disp_state, diffs)
    adj_pe = peLib.AdjustPE(pe)
    adj_pe.update_displacement(disp_state)

    # done
    return pe, disp_state


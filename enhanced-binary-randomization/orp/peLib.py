#!/usr/bin/env python
# coding: utf-8
"""
Copyright (c) 2015 Hyungjoon Koo <hykoo@cs.stonybrook.edu>
PE Library to write a modified PE with a new section
This file is added to support new feature to orp
"""

import sys
import struct
import util
import os
import itertools
try:
    import pydasm, pefile
except ImportError, e:
    print "You need to install the following packages: pydasm, pefile"
    sys.exit(1)

class PEInfoError(Exception):
    pass

class PEInfo:
    """
    Extract necessary information at NT Headers from a given PE
    (a) File header (b) Optional header (c) section headers
    """
    def __init__(self, pe):
        self.pe = pe
        self.DEBUG = True

    '''
    [1] NT_HEADERS - FILE_HEADER
    '''
    def getNumOfSections(self):
        return self.pe.FILE_HEADER.NumberOfSections

    def setNumOfSections(self, newNumOfSections):
        # Newly defined section - [.ropf]
        self.pe.FILE_HEADER.NumberOfSections = newNumOfSections

    '''
    [2] NT_HEADERS - OPTIONAL_HEADER
    '''
    def getSizeOfCode(self):
        return self.pe.OPTIONAL_HEADER.SizeOfCode

    def setSizeOfCode(self, newSize):
        self.pe.OPTIONAL_HEADER.SizeOfCode = newSize

    def getSizeOfImage(self):
        return self.pe.OPTIONAL_HEADER.SizeOfImage

    def setSizeOfImage(self, newSize):
        self.pe.OPTIONAL_HEADER.SizeOfImage = newSize

    def getSizeOfInitializedData(self):
        return self.pe.OPTIONAL_HEADER.SizeOfInitializedData

    def setSizeOfInitializedData(self, newSize):
        self.pe.OPTIONAL_HEADER.SizeOfInitializedData = newSize

    def getSizeOfUninitializedData(self):
        return self.pe.OPTIONAL_HEADER.SizeOfUninitializedData

    def setSizeOfUninitializedData(self, newSize):
        self.pe.OPTIONAL_HEADER.SizeOfUninitializedData = newSize

    def getImageBase(self):
        return self.pe.OPTIONAL_HEADER.ImageBase

    def setImageBase(self, newBase):
        self.pe.OPTIONAL_HEADER.ImageBase = newBase

    def getFileAlignment(self):
        return self.pe.OPTIONAL_HEADER.FileAlignment

    def getSectionAlignment(self):
        return self.pe.OPTIONAL_HEADER.SectionAlignment

    def getSizeOfHeaders(self):
        return self.pe.OPTIONAL_HEADER.SizeOfHeaders

    def getAddressOfEntryPoint(self):
        return self.pe.OPTIONAL_HEADER.AddressOfEntryPoint

    def getRelocationSize(self):
        for s in range(len(self.pe.sections)):
            if 'reloc' in self.getSectionName(s):
                return self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size
        return 0

    def setRelocationSize(self, newSize):
        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size = newSize

    def setNewChecksum(self):
        self.pe.OPTIONAL_HEADER.CheckSum = self.pe.generate_checksum()

    def printEssentialOptionalInfo(self):
        print "\t  a. Size of Headers: %s" % hex(self.getSizeOfHeaders())
        print "\t  b. Size of Code*: %s" % hex(self.getSizeOfCode())
        print "\t  c. Size of Image*: %s" % hex(self.getSizeOfImage())
        print "\t  d. Size of Initialized Data*: %s" % hex(self.getSizeOfInitializedData())
        print "\t  e. Size of Uninitialized Data: %s" % hex(self.getSizeOfUninitializedData())
        print "\t  f. Image Base: %s" % hex(self.getImageBase())
        print "\t  g. Address of Entry Point: %s" % hex(self.getAddressOfEntryPoint())
        print "\t  h. File Alignment: %s" % hex(self.getFileAlignment())
        print "\t  i. Section Alignment: %s" % hex(self.getSectionAlignment())
        print "\t  j. Relocation Size*: %s" % hex(self.getRelocationSize())

    '''
    [3] NT_HEADERS - SECTION_HEADER
    '''
    def getSectionName(self, sec):
        return self.pe.sections[sec].Name

    def getVirtualSize(self, sec):
        return self.pe.sections[sec].Misc_VirtualSize

    def getRVA(self, sec):
        return self.pe.sections[sec].VirtualAddress

    def getSizeOfRawData(self, sec):
        return self.pe.sections[sec].SizeOfRawData

    def getCharacteristics(self, sec):
        return self.pe.sections[sec].Characteristics

    def getPointerToRawData(self, sec):
        return self.pe.sections[sec].PointerToRawData

    def printAllSectionInfo(self):
        for section in self.pe.sections:
            print section

    '''
    [4] GENERAL SECTIONS
    '''
    def setBytesAtOffset(self, offset, data):
        self.pe.set_bytes_at_offset(offset, data)

class AdjustPEError(Exception):
    pass

def read_pe(pe_path):
    """
    Given the path of the PE, load it using PE file, 
    and remove any rubbish appended to the end.
    """
    pe = pefile.PE(pe_path)
    peinfo = PEInfo(pe)
    pointer_to_end = peinfo.getPointerToRawData(-1) + \
                     peinfo.getSizeOfRawData(-1)
    epilog = pe.__data__[pointer_to_end:]
    if len(epilog)>0:
        pe.__data__ = pe.__data__[:pointer_to_end]
    return pe, epilog

def write_pe(pe_path, pe, epilog):
    """
    Attach the epilog the the PE's data, and store
    it in the given path
    """
    pe.__data__ = pe.__data__[:] + epilog
    pe.write(filename=pe_path)

def _get_reloc_entries(disp_state):
    reloc_entries = []
    if disp_state.peinfo.getRelocationSize() > 0:
        for reloc in disp_state.pe.DIRECTORY_ENTRY_BASERELOC:
            for entry in reloc.entries:
                reloc_entries.append((entry.struct.Data, entry.rva, entry.type))
    else:
        reloc_entries = None
    return reloc_entries

class AdjustPE:
    """
    This class is for PE update (NT_HEADER + SECTION_HEADER + .ropf Section)
    """
    def __init__(self, pe):
        self.pe = pe
        self.peinfo = PEInfo(self.pe)

   # Adjust IMAGE_FILE_HEADER
    def _update_file_header(self):
        """
        Nothing to change for IMAGE_DOS_HEADER (64B including 40B DOS Stub)
        NT_HEADERS - IMAGE_FILE_HEADER (20B in total)
            NumberOfSections: increasing by 1
        """
        curNumOfSections = self.peinfo.getNumOfSections()
        if curNumOfSections < 2:
            raise AdjustPEError("There is only a single section. Check it out.")
            sys.exit(1)
        self.peinfo.setNumOfSections(curNumOfSections + 1)

    # Adjust IMAGE_OPTIONAL_HEADER
    def _update_optional_header(self, SizeOfRawData, VirtualAddress):
        """
        Reallocation layout example
            BEFORE: [.text] - [.rdata] - [.data] - [.reloc] - ...
            AFTER:  [.text] - [.rdata] - [.data] - [.reloc] - ... - [.ropf]
        NT_HEADERS - IMAGE_OPTIONAL_HEADER elements to update (36 fields, 96B in total)
            SizeOfCode(aligned): Rounded up for all code sections
            SizeOfImage(unaligned): ImageBase + End of the section
            SizeOfInitializedData (aligned)
            SizeOfUninitializedData (aligned)
            Checksum
        """
        # n: the number to be rounded, r: alignment
        def __multiple_round(n, r):
            return (n + (r - 1)) / r * r

        # SizeOfImage = RVA + aligned(SizeOfRawData) of the increased .ropf section
        # https://msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx
        # FIXED: Must be multiple of SectionAlignment, in bytes, including all headers!!
        sectionAlignment = self.peinfo.getSectionAlignment()
        self.peinfo.setSizeOfImage(VirtualAddress + __multiple_round(SizeOfRawData, sectionAlignment))

        newSizeOfCode = 0
        newSizeOfInitializedData = 0
        newSizeOfUninitializedData = 0

        # Recalculate the sizes of each section and check out the characteristics
        for section in self.pe.sections:
            if section.Characteristics & 0x00000020:
                # Section contains code.
                newSizeOfCode += section.SizeOfRawData
            if section.Characteristics & 0x00000040:
                # Section contains initialized data.
                newSizeOfInitializedData += section.SizeOfRawData
            if section.Characteristics & 0x00000080:
                # Section contains uninitialized data.
                newSizeOfUninitializedData += section.SizeOfRawData

        self.peinfo.setSizeOfCode(newSizeOfCode + SizeOfRawData)
        self.peinfo.setSizeOfInitializedData(newSizeOfInitializedData)
        self.peinfo.setSizeOfUninitializedData(newSizeOfUninitializedData)
        self.peinfo.setNewChecksum()

    def _adjust_reloc(self, moving_regions, reloc_entries):
        """
        Adjust relocation entries in .reloc section
        """
        # Obtain existing entries in from original relocation blocks
        reloc_blocks = {}
        for (data, rva, type) in reloc_entries:
            if type == 0:
                continue
            base = rva & 0xFFFFF000
            if base not in reloc_blocks.keys():
                reloc_blocks[base] = [data]
            else:
                reloc_blocks[base] += [data]

        ropf_va = self.peinfo.getImageBase() + self.peinfo.getRVA(-1) + self.peinfo.getVirtualSize(-1) - \
                   self.peinfo.getVirtualSize(-1) % self.peinfo.getSectionAlignment() + self.peinfo.getSectionAlignment()
        ropf_section_start = ropf_va - self.peinfo.getImageBase()

        mov_ranges = []
        ropf_starts = {}
        for (ms, sz, ropf_start) in sorted(moving_regions):
            mov_ranges.append((ms, ms+sz))
            ropf_starts[ms] = ropf_start

        # Classify entries to be updated from original relocation blocks
        new_reloc_blocks = {}
        for b_base in sorted(reloc_blocks.keys()):
            for entry in reloc_blocks[b_base]:
                b_rva = (b_base | (entry & 0x0FFF))
                reloc_addr = self.peinfo.getImageBase() + b_rva
                (mov_start, mov_end) = util.get_addr_range(mov_ranges, reloc_addr)

                # Case that the reloc addr has not been affected by displaced regions in .text section
                if mov_start == 0:
                    if b_base not in new_reloc_blocks.keys():
                        new_reloc_blocks[b_base] = [entry]
                    else:
                        new_reloc_blocks[b_base] += [entry]

                # Case that the reloc addr should be updated due to displaced regions in .text section
                else:
                    '''
                    New bases should be defined, which remaining entries belong to
                        1) original_offset (in displaced region) = reloc_addr - mov_start
                        2) ropf_offset = ropf_start (=ropf_starts[mov_start]) + orginal_offset
                        3) new_base = ropf_section_start + ((ropf_offset - ropf_va) & 0xFFFFF000)
                        4) new_entry = ((ropf_offset - ropf_va) & 0x0FFF) | 0x3000
                           <FIXED> type is always IMAGE_REL_BASED_HIGHLOW (instead of 'type << 12')
                           'type' would be set to 0 at '.ropf' in case that
                            an executable file (.exe) itself has '.reloc' section
                    '''
                    ropf_offset = ropf_starts[mov_start] + (reloc_addr - mov_start)
                    new_base = ropf_section_start + ((ropf_offset - ropf_va) & 0xFFFFF000)
                    new_entry = ((ropf_offset - ropf_va) & 0x00000FFF) | 0x3000

                    if new_base not in new_reloc_blocks.keys():
                        new_reloc_blocks[new_base] = [new_entry]
                    else:
                        new_reloc_blocks[new_base] += [new_entry]

        # Checking the correctness of new relocation table
        c1 = 0
        for b in sorted(reloc_blocks.keys()):
            c1 += len(reloc_blocks[b])
            # print "%s: %d" % (hex(b), len(reloc_blocks[b]))

        c2 = 0
        for b in sorted(new_reloc_blocks.keys()):
            block_size = len(new_reloc_blocks[b])
            c2 += block_size
            try:
                diff = block_size - len(reloc_blocks[b])
            except:
                diff = block_size
            # print "%s: %d(%d)" % (hex(b), len(new_reloc_blocks[b]), diff)

        assert(c1 == c2), "The number of relocation entries before/after does not match!!"

        # Build new relocation blocks in .reloc section
        new_reloc_data = ''
        for b_base in sorted(new_reloc_blocks.keys()):
            new_reloc_data += struct.pack('<I', b_base)
            b_size = len(new_reloc_blocks[b_base])*2 + 8
            new_reloc_data += struct.pack('<I', b_size if b_size % 4 == 0 else b_size + 2)
            for entry in sorted(new_reloc_blocks[b_base]):
                new_reloc_data += struct.pack('<H', entry)
            if b_size % 4 != 0:
                new_reloc_data += struct.pack('<H', 0)

        self.peinfo.setRelocationSize(len(new_reloc_data))

        # Adjust relocation table in a .reloc section
        for s in range(self.peinfo.getNumOfSections()):
            if 'reloc' in self.peinfo.getSectionName(s):
                reloc_ptr = self.peinfo.getPointerToRawData(s)

        # !!! pefile keeps failing to write .reloc section !!!
        # !!! For now manually update the section with raw data :(
        self.peinfo.setBytesAtOffset(reloc_ptr, new_reloc_data)
        reloc_file = '/tmp/reloc.dat' if os.name == 'posix' else 'reloc.dat'
        with open(reloc_file, 'wb') as f:
            f.write(new_reloc_data)

    def update_displacement(self, disp_state, DEBUG=False):
        """
        Adjust IMAGE_SECTION_HEADER and ACTUAL SECTION DATA
        Each section has 40B in size
        IMAGE_SECTION_HEADER elements to update for each section
            VirtualSize: unaligned
            RVA (Virtual address): aligned
            Size of Raw Data: aligned(VirtualSize)
            Pointer to Raw Data: aligned, may not be the same with RVA
            Characteristics
        """

        # Mahmood: simple hack to be compatible with Koo's
        # and Polychronakis' code
        moving_regions = disp_state.moving_regions
        moving_code = disp_state.get_dbin()

        FileAlignment = self.peinfo.getFileAlignment()
        SectionAlignment = self.peinfo.getSectionAlignment()
        SizeOfHeaders = self.peinfo.getSizeOfHeaders()
        NumOfSections = self.peinfo.getNumOfSections()
        ActualCodeSize = len(moving_code)

        # Adjust relocation table in a .reloc section if any
        reloc_entries = _get_reloc_entries(disp_state)
        if reloc_entries is not None:
            self._adjust_reloc(moving_regions, reloc_entries)

        '''
        # Copy the existing sections to the new space and create the new one at the end
        
        |<------------------------------          (SizeOfHeaders)           ------------------------------------->| 
         ---------------------------------------------------------------------------------------------------------------------------------------
        | DOS_HEADER |  |         NT_HEADER         |               SECTION_HEADER                  |(empty_space)| SECTION 1 | ... | SECTION N |
        |------------|--|---------------------------|-----------------------------------------------|-------------|-----------|-----|-----------|
        | (DOS_STUB) |00|  FILE_HDR  | OPTIONAL_HDR | .text |.rdata | .data | .rsrc |  ...  | .ropf |0000000000000|  [.text]  | ... |  [.ropf]  |
        |------------|--|------------|--------------|-------|-------|-------|-------|-------|-------|-------------|-----------|-----|-----------|
        |<--(64B) -->|  |<-- (20B)-->|<-- (224B) -->| (40B) | (40B) | (40B) | (40B) | (40B) | (40B) |             |           | ... |           |
           ↓            ↑                           ↑                                       ↑
          e_lfanew------┘                  offsetToSectionTable                     offsetToNewSection
        '''

        offsetToSectionTable = (self.pe.DOS_HEADER.e_lfanew + 4 +
                                self.pe.FILE_HEADER.sizeof() +
                                self.pe.FILE_HEADER.SizeOfOptionalHeader)
        offsetToNewSection = offsetToSectionTable + NumOfSections * 40

        # After adding a new section, the size of headers needs to be adjusted
        if SizeOfHeaders < offsetToSectionTable + (NumOfSections + 1) * 40:
            data = '\x00' * FileAlignment
            self.pe.__data__ = (self.pe.__data__[:SizeOfHeaders] + data +
                                self.pe.__data__[SizeOfHeaders + len(data):])

            # Filled with null between the last section header and SizeOfHeaders
            data = self.pe.get_data(offsetToNewSection, SizeOfHeaders - offsetToNewSection)
            self.pe.set_bytes_at_offset(offsetToNewSection + FileAlignment, data)

            # Check the VirtualAddress of each section if it fits in well
            for dataDir in self.pe.OPTIONAL_HEADER.DATA_DIRECTORY:
                if dataDir.Size > 0 and (offsetToNewSection < dataDir.VirtualAddress < SizeOfHeaders):
                    dataDir.VirtualAddress += FileAlignment

            # Increase SizeOfHeader by FileAlignment due to a new section
            self.pe.OPTIONAL_HEADER.SizeOfHeaders += FileAlignment

            # Set a new section header
            newSectionAddr = offsetToSectionTable + 20
            for section in self.pe.sections:
                self.pe.set_dword_at_offset(newSectionAddr, section.PointerToRawData + FileAlignment)
                newSectionAddr += 40
            self.pe.parse_sections(offsetToSectionTable)

        IMAGE_SCN_CNT_CODE = 0x00000020
        IMAGE_SCN_MEM_EXECUTE = 0x20000000
        IMAGE_SCN_MEM_READ = 0x40000000

        # Initialize a new section header
        Name=".ropf"
        VirtualSize=0x00000000          # Real Size of new section code
        VirtualAddress=0x00000000       # RVA to map corresponding section in PE
        SizeOfRawData=0x00000000        # Aligned Size of VirtualSize with FileAlignement
        PointerToRawData=0x00000000     # File offset starting corresponding section
        PointerToRelocations=0x00000000 # Used in OBJ only (do not care, Always 0)
        PointerToLinenumbers=0x00000000 # COFF style line number (do not care, Always 0)
        NumberOfRelocations=0x0000      # Used in OBJ only (do not care, Always 0)
        NumberOfLineNumbers=0x0000      # COFF style line number (do not care, Always 0)
        Characteristics=0x00000000      # Make it readable, executable in code

        # Set each field on a new section header [.ropf]
        # A. VirtualSize: unaligned
        VirtualSize += ActualCodeSize
        if ActualCodeSize % FileAlignment != 0: # Padding the code up to FileAlignment
            moving_code += '\x00' * (FileAlignment - ActualCodeSize % FileAlignment)

        # B. RVA (Virtual address): aligned by SectionAlignment   
        if VirtualAddress < self.peinfo.getVirtualSize(-1) + self.peinfo.getRVA(-1) \
            or VirtualAddress % SectionAlignment != 0:
            if (self.peinfo.getVirtualSize(-1) % SectionAlignment) != 0:
                VirtualAddress = self.peinfo.getRVA(-1) + self.peinfo.getVirtualSize(-1) - \
                                 self.peinfo.getVirtualSize(-1) % SectionAlignment + SectionAlignment
            else:
                VirtualAddress = self.peinfo.getRVA(-1) + self.peinfo.getVirtualSize(-1)

        # C. SizeOfRawData: aligned size of VirtualSize by FileAlignment
        if ActualCodeSize % FileAlignment == 0:
            SizeOfRawData += ActualCodeSize
        else:
            SizeOfRawData += (VirtualSize / FileAlignment) * FileAlignment + FileAlignment

        # D. PointerToRawData: aligned size of ActualCode by FileAlignment
        PointerToRawData += self.peinfo.getPointerToRawData(-1) + self.peinfo.getSizeOfRawData(-1)

        # E. Characteristics: CODE & 'RX' Permission
        Characteristics |= (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ)

        # F. Write a new section header (.ropf)
        self.pe.set_bytes_at_offset(offsetToNewSection, Name)
        self.pe.set_dword_at_offset(offsetToNewSection + 0x08, VirtualSize)
        self.pe.set_dword_at_offset(offsetToNewSection + 0x0C, VirtualAddress)
        self.pe.set_dword_at_offset(offsetToNewSection + 0x10, SizeOfRawData)
        self.pe.set_dword_at_offset(offsetToNewSection + 0x14, PointerToRawData)
        self.pe.set_dword_at_offset(offsetToNewSection + 0x18, PointerToRelocations)
        self.pe.set_dword_at_offset(offsetToNewSection + 0x1C, PointerToLinenumbers)
        self.pe.set_word_at_offset(offsetToNewSection + 0x20, NumberOfRelocations)
        self.pe.set_word_at_offset(offsetToNewSection + 0x22, NumberOfLineNumbers)
        self.pe.set_dword_at_offset(offsetToNewSection + 0x24, Characteristics)
        
        # G. Write the moving_code to the new section (.ropf)
        if ActualCodeSize > 0:
            addl_data = self.pe.__data__[PointerToRawData:]
            if len(addl_data)>0:
                self.pe.__data__ = self.pe.__data__[:PointerToRawData]
                if len(addl_data)<2 or addl_data[:2]!='#!':
                    addl_data = ''
                self.pe.__data__ = self.pe.__data__[:] + moving_code + \
                                   addl_data
            else:
                self.pe.__data__ = self.pe.__data__[:] + moving_code

        # H. Increase the number of sections by 1 (.ropf)
        self._update_file_header()
        self._update_optional_header(SizeOfRawData, VirtualAddress)

    def update_kreuk(self, junk, DEBUG=False):

        # Mahmood: simple hack to be compatible with Koo's
        # and Polychronakis' code
        moving_code = junk

        FileAlignment = self.peinfo.getFileAlignment()
        SectionAlignment = self.peinfo.getSectionAlignment()
        SizeOfHeaders = self.peinfo.getSizeOfHeaders()
        NumOfSections = self.peinfo.getNumOfSections()
        ActualCodeSize = len(moving_code)

        '''
        # Copy the existing sections to the new space and create the new one at the end
        
        |<------------------------------          (SizeOfHeaders)           ------------------------------------->| 
         ---------------------------------------------------------------------------------------------------------------------------------------
        | DOS_HEADER |  |         NT_HEADER         |               SECTION_HEADER                  |(empty_space)| SECTION 1 | ... | SECTION N |
        |------------|--|---------------------------|-----------------------------------------------|-------------|-----------|-----|-----------|
        | (DOS_STUB) |00|  FILE_HDR  | OPTIONAL_HDR | .text |.rdata | .data | .rsrc |  ...  | .ropf |0000000000000|  [.text]  | ... |  [.ropf]  |
        |------------|--|------------|--------------|-------|-------|-------|-------|-------|-------|-------------|-----------|-----|-----------|
        |<--(64B) -->|  |<-- (20B)-->|<-- (224B) -->| (40B) | (40B) | (40B) | (40B) | (40B) | (40B) |             |           | ... |           |
           ↓            ↑                           ↑                                       ↑
          e_lfanew------┘                  offsetToSectionTable                     offsetToNewSection
        '''

        offsetToSectionTable = (self.pe.DOS_HEADER.e_lfanew + 4 +
                                self.pe.FILE_HEADER.sizeof() +
                                self.pe.FILE_HEADER.SizeOfOptionalHeader)
        offsetToNewSection = offsetToSectionTable + NumOfSections * 40

        # After adding a new section, the size of headers needs to be adjusted
        if SizeOfHeaders < offsetToSectionTable + (NumOfSections + 1) * 40:
            data = '\x00' * FileAlignment
            self.pe.__data__ = (self.pe.__data__[:SizeOfHeaders] + data +
                                self.pe.__data__[SizeOfHeaders + len(data):])

            # Filled with null between the last section header and SizeOfHeaders
            data = self.pe.get_data(offsetToNewSection, SizeOfHeaders - offsetToNewSection)
            self.pe.set_bytes_at_offset(offsetToNewSection + FileAlignment, data)

            # Check the VirtualAddress of each section if it fits in well
            for dataDir in self.pe.OPTIONAL_HEADER.DATA_DIRECTORY:
                if dataDir.Size > 0 and (offsetToNewSection < dataDir.VirtualAddress < SizeOfHeaders):
                    dataDir.VirtualAddress += FileAlignment

            # Increase SizeOfHeader by FileAlignment due to a new section
            self.pe.OPTIONAL_HEADER.SizeOfHeaders += FileAlignment

            # Set a new section header
            newSectionAddr = offsetToSectionTable + 20
            for section in self.pe.sections:
                self.pe.set_dword_at_offset(newSectionAddr, section.PointerToRawData + FileAlignment)
                newSectionAddr += 40
            self.pe.parse_sections(offsetToSectionTable)

        IMAGE_SCN_CNT_CODE = 0x00000020
        IMAGE_SCN_MEM_EXECUTE = 0x20000000
        IMAGE_SCN_MEM_READ = 0x40000000

        # Initialize a new section header
        Name=".ropf"
        VirtualSize=0x00000000          # Real Size of new section code
        VirtualAddress=0x00000000       # RVA to map corresponding section in PE
        SizeOfRawData=0x00000000        # Aligned Size of VirtualSize with FileAlignement
        PointerToRawData=0x00000000     # File offset starting corresponding section
        PointerToRelocations=0x00000000 # Used in OBJ only (do not care, Always 0)
        PointerToLinenumbers=0x00000000 # COFF style line number (do not care, Always 0)
        NumberOfRelocations=0x0000      # Used in OBJ only (do not care, Always 0)
        NumberOfLineNumbers=0x0000      # COFF style line number (do not care, Always 0)
        Characteristics=0x00000000      # Make it readable, executable in code

        # Set each field on a new section header [.ropf]
        # A. VirtualSize: unaligned
        VirtualSize += ActualCodeSize
        if ActualCodeSize % FileAlignment != 0: # Padding the code up to FileAlignment
            moving_code += '\x00' * (FileAlignment - ActualCodeSize % FileAlignment)

        # B. RVA (Virtual address): aligned by SectionAlignment   
        if VirtualAddress < self.peinfo.getVirtualSize(-1) + self.peinfo.getRVA(-1) \
            or VirtualAddress % SectionAlignment != 0:
            if (self.peinfo.getVirtualSize(-1) % SectionAlignment) != 0:
                VirtualAddress = self.peinfo.getRVA(-1) + self.peinfo.getVirtualSize(-1) - \
                                 self.peinfo.getVirtualSize(-1) % SectionAlignment + SectionAlignment
            else:
                VirtualAddress = self.peinfo.getRVA(-1) + self.peinfo.getVirtualSize(-1)

        # C. SizeOfRawData: aligned size of VirtualSize by FileAlignment
        if ActualCodeSize % FileAlignment == 0:
            SizeOfRawData += ActualCodeSize
        else:
            SizeOfRawData += (VirtualSize / FileAlignment) * FileAlignment + FileAlignment

        # D. PointerToRawData: aligned size of ActualCode by FileAlignment
        PointerToRawData += self.peinfo.getPointerToRawData(-1) + self.peinfo.getSizeOfRawData(-1)

        # E. Characteristics: CODE & 'RX' Permission
        Characteristics |= (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ)

        # F. Write a new section header (.ropf)
        self.pe.set_bytes_at_offset(offsetToNewSection, Name)
        self.pe.set_dword_at_offset(offsetToNewSection + 0x08, VirtualSize)
        self.pe.set_dword_at_offset(offsetToNewSection + 0x0C, VirtualAddress)
        self.pe.set_dword_at_offset(offsetToNewSection + 0x10, SizeOfRawData)
        self.pe.set_dword_at_offset(offsetToNewSection + 0x14, PointerToRawData)
        self.pe.set_dword_at_offset(offsetToNewSection + 0x18, PointerToRelocations)
        self.pe.set_dword_at_offset(offsetToNewSection + 0x1C, PointerToLinenumbers)
        self.pe.set_word_at_offset(offsetToNewSection + 0x20, NumberOfRelocations)
        self.pe.set_word_at_offset(offsetToNewSection + 0x22, NumberOfLineNumbers)
        self.pe.set_dword_at_offset(offsetToNewSection + 0x24, Characteristics)
        
        # G. Write the moving_code to the new section (.ropf)
        if ActualCodeSize > 0:
            addl_data = self.pe.__data__[PointerToRawData:]
            if len(addl_data)>0:
                self.pe.__data__ = self.pe.__data__[:PointerToRawData]
                if len(addl_data)<2 or addl_data[:2]!='#!':
                    addl_data = ''
                self.pe.__data__ = self.pe.__data__[:] + moving_code + \
                                   addl_data
            else:
                self.pe.__data__ = self.pe.__data__[:] + moving_code

        # H. Increase the number of sections by 1 (.ropf)
        self._update_file_header()
        self._update_optional_header(SizeOfRawData, VirtualAddress)

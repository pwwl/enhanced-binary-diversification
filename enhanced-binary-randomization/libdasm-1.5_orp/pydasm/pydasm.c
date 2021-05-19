
/*
 * pydasm -- Python module wrapping libdasm
 * (c) 2005 ero / dkbza.org
 *
*/


#include <Python.h>
#include "../libdasm.h"


#define INSTRUCTION_STR_BUFFER_LENGTH   256

/*
    Instruction types borrowed from
    "libdasm.h"
*/
char *instruction_types[] = {
	"INSTRUCTION_TYPE_ASC",
	"INSTRUCTION_TYPE_DCL",
	"INSTRUCTION_TYPE_MOV",
	"INSTRUCTION_TYPE_MOVSR",
	"INSTRUCTION_TYPE_ADD",
	"INSTRUCTION_TYPE_XADD",
	"INSTRUCTION_TYPE_ADC",
	"INSTRUCTION_TYPE_SUB",
	"INSTRUCTION_TYPE_SBB",
	"INSTRUCTION_TYPE_INC",
	"INSTRUCTION_TYPE_DEC",
	"INSTRUCTION_TYPE_DIV",
	"INSTRUCTION_TYPE_IDIV",
	"INSTRUCTION_TYPE_NOT",
	"INSTRUCTION_TYPE_NEG",
	"INSTRUCTION_TYPE_STOS",
	"INSTRUCTION_TYPE_LODS",
	"INSTRUCTION_TYPE_SCAS",
	"INSTRUCTION_TYPE_MOVS",
	"INSTRUCTION_TYPE_MOVSX",
	"INSTRUCTION_TYPE_MOVZX",
	"INSTRUCTION_TYPE_CMPS",
	"INSTRUCTION_TYPE_SHX",
	"INSTRUCTION_TYPE_ROX",
	"INSTRUCTION_TYPE_MUL",
	"INSTRUCTION_TYPE_IMUL",
	"INSTRUCTION_TYPE_EIMUL",
	"INSTRUCTION_TYPE_XOR",
	"INSTRUCTION_TYPE_LEA",
	"INSTRUCTION_TYPE_XCHG",
	"INSTRUCTION_TYPE_CMP",
	"INSTRUCTION_TYPE_TEST",
	"INSTRUCTION_TYPE_PUSH",
	"INSTRUCTION_TYPE_AND",
	"INSTRUCTION_TYPE_OR",
	"INSTRUCTION_TYPE_POP",
	"INSTRUCTION_TYPE_JMP",
	"INSTRUCTION_TYPE_JMPC",
	"INSTRUCTION_TYPE_JECXZ",
	"INSTRUCTION_TYPE_SETC",
	"INSTRUCTION_TYPE_MOVC",
	"INSTRUCTION_TYPE_LOOP",
	"INSTRUCTION_TYPE_CALL",
	"INSTRUCTION_TYPE_RET",
	"INSTRUCTION_TYPE_ENTER",
	"INSTRUCTION_TYPE_INT",
	"INSTRUCTION_TYPE_BT",
	"INSTRUCTION_TYPE_BTS",
	"INSTRUCTION_TYPE_BTR",
	"INSTRUCTION_TYPE_BTC",
	"INSTRUCTION_TYPE_BSF",
	"INSTRUCTION_TYPE_BSR",
	"INSTRUCTION_TYPE_BSWAP",
	"INSTRUCTION_TYPE_SGDT",
	"INSTRUCTION_TYPE_SIDT",
	"INSTRUCTION_TYPE_SLDT",
	"INSTRUCTION_TYPE_LFP",
	"INSTRUCTION_TYPE_CLD",
	"INSTRUCTION_TYPE_STD",
	"INSTRUCTION_TYPE_XLAT",
	"INSTRUCTION_TYPE_FCMOVC",
	"INSTRUCTION_TYPE_FADD",
	"INSTRUCTION_TYPE_FADDP",
	"INSTRUCTION_TYPE_FIADD",
	"INSTRUCTION_TYPE_FSUB",
	"INSTRUCTION_TYPE_FSUBP",
	"INSTRUCTION_TYPE_FISUB",
	"INSTRUCTION_TYPE_FSUBR",
	"INSTRUCTION_TYPE_FSUBRP",
	"INSTRUCTION_TYPE_FISUBR",
	"INSTRUCTION_TYPE_FMUL",
	"INSTRUCTION_TYPE_FMULP",
	"INSTRUCTION_TYPE_FIMUL",
	"INSTRUCTION_TYPE_FDIV",
	"INSTRUCTION_TYPE_FDIVP",
	"INSTRUCTION_TYPE_FDIVR",
	"INSTRUCTION_TYPE_FDIVRP",
	"INSTRUCTION_TYPE_FIDIV",
	"INSTRUCTION_TYPE_FIDIVR",
	"INSTRUCTION_TYPE_FCOM",
	"INSTRUCTION_TYPE_FCOMP",
	"INSTRUCTION_TYPE_FCOMPP",
	"INSTRUCTION_TYPE_FCOMI",
	"INSTRUCTION_TYPE_FCOMIP",
	"INSTRUCTION_TYPE_FUCOM",
	"INSTRUCTION_TYPE_FUCOMP",
	"INSTRUCTION_TYPE_FUCOMPP",
	"INSTRUCTION_TYPE_FUCOMI",
	"INSTRUCTION_TYPE_FUCOMIP",
	"INSTRUCTION_TYPE_FST",
	"INSTRUCTION_TYPE_FSTP",
	"INSTRUCTION_TYPE_FIST",
	"INSTRUCTION_TYPE_FISTP",
	"INSTRUCTION_TYPE_FISTTP",
	"INSTRUCTION_TYPE_FLD",
	"INSTRUCTION_TYPE_FILD",
	"INSTRUCTION_TYPE_FICOM",
	"INSTRUCTION_TYPE_FICOMP",
	"INSTRUCTION_TYPE_FFREE",
	"INSTRUCTION_TYPE_FFREEP",
	"INSTRUCTION_TYPE_FXCH",
	"INSTRUCTION_TYPE_SYSENTER",
	"INSTRUCTION_TYPE_FPU_CTRL",
	"INSTRUCTION_TYPE_FPU",

	"INSTRUCTION_TYPE_MMX",

	"INSTRUCTION_TYPE_SSE",

	"INSTRUCTION_TYPE_OTHER",
	"INSTRUCTION_TYPE_PRIV",
    NULL };

/*
    Operand types borrowed from
    "libdasm.h"
*/
char *operand_types[] = {
	"OPERAND_TYPE_NONE",
	"OPERAND_TYPE_MEMORY",
	"OPERAND_TYPE_REGISTER",
	"OPERAND_TYPE_IMMEDIATE",
    NULL };

/*
    Registers borrowed from
    "libdasm.h"
*/
char *registers[] = {
    "REGISTER_EAX",
    "REGISTER_ECX",
    "REGISTER_EDX",
    "REGISTER_EBX",
    "REGISTER_ESP",
    "REGISTER_EBP",
    "REGISTER_ESI",
    "REGISTER_EDI",
    "REGISTER_NOP",
    NULL };


/*
    Register types borrowed from
    "libdasm.h"
*/
char *register_types[] = {
    "REGISTER_TYPE_GEN",
    "REGISTER_TYPE_SEGMENT",
    "REGISTER_TYPE_DEBUG",
    "REGISTER_TYPE_CONTROL",
    "REGISTER_TYPE_TEST",
    "REGISTER_TYPE_XMM",
    "REGISTER_TYPE_MMX",
    "REGISTER_TYPE_FPU",
    NULL };

// Instruction flags (prefixes)
// made using :s/^#define \([A-Z0-9a-z_]*\)[\t ]*\([0-9a-fx]*\)/{"\1",\t\t\2}/
struct flag {
  char *name;
  long value;
} flags[] = {
// Group 1
{"PREFIX_LOCK",		0x01000000},	// 0xf0
{"PREFIX_REPNE",	0x02000000},	// 0xf2
{"PREFIX_REP",		0x03000000},	// 0xf3
{"PREFIX_REPE",		0x03000000},	// 0xf3
// Group 2
{"PREFIX_ES_OVERRIDE",		0x00010000},	// 0x26
{"PREFIX_CS_OVERRIDE",		0x00020000},	// 0x2e
{"PREFIX_SS_OVERRIDE",		0x00030000},	// 0x36
{"PREFIX_DS_OVERRIDE",		0x00040000},	// 0x3e
{"PREFIX_FS_OVERRIDE",		0x00050000},	// 0x64
{"PREFIX_GS_OVERRIDE",		0x00060000},	// 0x65
// Group 3 & 4
{"PREFIX_OPERAND_SIZE_OVERRIDE",	0x00000100},	// 0x66
{"PREFIX_ADDR_SIZE_OVERRIDE",		0x00001000},	// 0x67
// Extensions
{"EXT_G1_1",		0x00000001},
{"EXT_G1_2",		0x00000002},
{"EXT_G1_3",		0x00000003},
{"EXT_G2_1",		0x00000004},
{"EXT_G2_2",		0x00000005},
{"EXT_G2_3",		0x00000006},
{"EXT_G2_4",		0x00000007},
{"EXT_G2_5",		0x00000008},
{"EXT_G2_6",		0x00000009},
{"EXT_G3_1",		0x0000000a},
{"EXT_G3_2",		0x0000000b},
{"EXT_G4",		0x0000000c},
{"EXT_G5",		0x0000000d},
{"EXT_G6",		0x0000000e},
{"EXT_G7",		0x0000000f},
{"EXT_G8",		0x00000010},
{"EXT_G9",		0x00000011},
{"EXT_GA",		0x00000012},
{"EXT_GB",		0x00000013},
{"EXT_GC",		0x00000014},
{"EXT_GD",		0x00000015},
{"EXT_GE",		0x00000016},
{"EXT_GF",		0x00000017},
{"EXT_G0",		0x00000018},
// Extra groups for 2 and 3-byte opcodes, and FPU stuff
{"EXT_T2",		0x00000020},	// opcode table 2
{"EXT_CP",		0x00000030},	// co-processor
// Instruction type flags
{"TYPE_3",		0x80000000},
// Operand flags
{"FLAGS_NONE",		0},
// Operand Addressing Methods, from the Intel manual
{"AM_A",		0x00010000},		// Direct address with segment prefix
{"AM_C",		0x00020000},		// MODRM reg field defines control register
{"AM_D",		0x00030000},		// MODRM reg field defines debug register
{"AM_E",		0x00040000},		// MODRM byte defines reg/memory address
{"AM_G",		0x00050000},		// MODRM byte defines general-purpose reg
{"AM_I",		0x00060000},		// Immediate data follows
{"AM_J",		0x00070000},		// Immediate value is relative to EIP
{"AM_M",		0x00080000},		// MODRM mod field can refer only to memory
{"AM_O",		0x00090000},		// Displacement follows (without modrm/sib)
{"AM_P",		0x000a0000},		// MODRM reg field defines MMX register
{"AM_Q",		0x000b0000},		// MODRM defines MMX register or memory 
{"AM_R",		0x000c0000},		// MODRM mod field can only refer to register
{"AM_S",		0x000d0000},		// MODRM reg field defines segment register
{"AM_T",		0x000e0000},		// MODRM reg field defines test register
{"AM_V",		0x000f0000},		// MODRM reg field defines XMM register
{"AM_W",		0x00100000},		// MODRM defines XMM register or memory 
// Extra addressing modes used in this implementation
{"AM_I1",		0x00200000},	// Immediate byte 1 encoded in instruction
{"AM_REG",		0x00210000},	// Register encoded in instruction
{"AM_IND",		0x00220000},	// Register indirect encoded in instruction
// Operand Types, from the intel manual
{"OT_a",		0x01000000},
{"OT_b",		0x02000000},	// always 1 byte
{"OT_c",		0x03000000},	// byte or word, depending on operand
{"OT_d",		0x04000000},	// double-word
{"OT_q",		0x05000000},	// quad-word
{"OT_dq",		0x06000000},	// double quad-word
{"OT_v",		0x07000000},	// word or double-word, depending on operand
{"OT_w",		0x08000000},	// always word
{"OT_p",		0x09000000},	// 32-bit or 48-bit pointer
{"OT_pi",		0x0a000000},	// quadword MMX register
{"OT_pd",		0x0b000000},	// 128-bit double-precision float
{"OT_ps",		0x0c000000},	// 128-bit single-precision float
{"OT_s",		0x0d000000},	// 6-byte pseudo descriptor
{"OT_sd",		0x0e000000},	// Scalar of 128-bit double-precision float
{"OT_ss",		0x0f000000},	// Scalar of 128-bit single-precision float
{"OT_si",		0x10000000},	// Doubleword integer register
{"OT_t",		0x11000000},	// 80-bit packed FP data
// Operand permissions
{"P_r",		0x00004000},	// Read
{"P_w",		0x00002000},	// Write
{"P_x",		0x00001000},	// Execute
// Additional operand flags
{"F_s",		0x00000100},	// sign-extend 1-byte immediate
{"F_r",		0x00000200},	// use segment register
{"F_f",		0x00000400}};	// use FPU register

//Helper macros
/* made using :'<,'>s/\(.*\)/PyObject *_\1(PyObject *self, PyObject 
 *args)\r{\r int x;\r\r    if (!PyArg_ParseTuple(args, "i", \&x))\r
 return NULL;\r\r    return PyLong_FromLong (\1(x));\r}\r/ */
PyObject *_MASK_PREFIX_G1(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_PREFIX_G1(x));
}

PyObject *_MASK_PREFIX_G2(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_PREFIX_G2(x));
}

PyObject *_MASK_PREFIX_G3(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_PREFIX_G3(x));
}

PyObject *_MASK_PREFIX_OPERAND(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_PREFIX_OPERAND(x));
}

PyObject *_MASK_PREFIX_ADDR(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_PREFIX_ADDR(x));
}

PyObject *_MASK_EXT(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_EXT(x));
}

PyObject *_MASK_TYPE_FLAGS(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_TYPE_FLAGS(x));
}

PyObject *_MASK_TYPE_VALUE(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_TYPE_VALUE(x));
}

PyObject *_MASK_AM(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_AM(x));
}

PyObject *_MASK_OT(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_OT(x));
}

PyObject *_MASK_PERMS(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_PERMS(x));
}

PyObject *_MASK_FLAGS(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_FLAGS(x));
}

PyObject *_MASK_REG(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_REG(x));
}

PyObject *_MASK_MODRM_MOD(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_MODRM_MOD(x));
}

PyObject *_MASK_MODRM_REG(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_MODRM_REG(x));
}

PyObject *_MASK_MODRM_RM(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_MODRM_RM(x));
}

PyObject *_MASK_SIB_SCALE(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_SIB_SCALE(x));
}

PyObject *_MASK_SIB_INDEX(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_SIB_INDEX(x));
}

PyObject *_MASK_SIB_BASE(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_SIB_BASE(x));
}




PyObject *module;   // Main module Python object


/*
    Check whether we got a Python Object
*/
PyObject *check_object(PyObject *pObject)
{
	PyObject *pException;
	
	if(!pObject) {
		pException = PyErr_Occurred();
		if(pException)
            PyErr_Print();
        return NULL;
	}
    
    return pObject;
}


/*
    Assign an attribute "attr" named "name" to an object "obj"
*/
void assign_attribute(PyObject *obj, char *name, PyObject *attr)
{
    PyObject_SetAttrString(obj, name, attr);
    Py_DECREF(attr);
}


/*
    Get an attribute named "attr_name" from object "obj"
    The function steals the reference! note the decrement of
    the reference count.
*/
PyObject *get_attribute(PyObject *obj, char *attr_name)
{
    PyObject *pObj;
    
    pObj = PyObject_GetAttrString(obj, attr_name);
	if(!check_object(pObj)) {
        PyErr_SetString(PyExc_ValueError, "Can't get attribute from object");
        return NULL;
    }
    
    Py_DECREF(pObj);
    return pObj;
}


/*
    Get an Long attribute named "attr_name" from object "obj" and
    return it as a "long int"
*/
long int get_long_attribute(PyObject *o, char *attr_name)
{
    PyObject *pObj;
    
    pObj = get_attribute(o, attr_name);
	if(!pObj)
        return 0;
        
    return PyLong_AsLong(pObj);;
}


/*
    Create a new class and take care of decrementing references.
*/
PyObject *create_class(char *class_name)
{
    PyObject *pClass;
    PyObject *pClassDict = PyDict_New();
    PyObject *pClassName = PyString_FromString(class_name);
    
    pClass = PyClass_New(NULL, pClassDict, pClassName);
    if(!check_object(pClass))
        return NULL;
        
    Py_DECREF(pClassDict);
    Py_DECREF(pClassName);
    
    return pClass;
}


/*
    Create an "Inst" Python object from an INST structure.
*/
PyObject *create_inst_object(INST *pinst)
{
    PyObject *pPInst = create_class("Inst");
    
    if(!pPInst)
        return NULL;

    assign_attribute(pPInst, "type", PyLong_FromLong(pinst->type));
    assign_attribute(pPInst, "mnemonic", PyString_FromString(pinst->mnemonic));
    assign_attribute(pPInst, "flags1", PyLong_FromLong(pinst->flags1));
    assign_attribute(pPInst, "flags2", PyLong_FromLong(pinst->flags2));
    assign_attribute(pPInst, "flags3", PyLong_FromLong(pinst->flags3));
    assign_attribute(pPInst, "modrm", PyLong_FromLong(pinst->modrm));
    assign_attribute(pPInst, "checked", PyLong_FromLong(pinst->checked));
    
    return pPInst;
}

/*
    Fill an INST structure from the data in an "Inst" Python object.
*/
void fill_inst_structure(PyObject *pPInst, PINST *_pinst)
{
    ssize_t mnemonic_length;
    PINST pinst;
    
    if(!pPInst || !_pinst)
        return;
        
    *_pinst = (PINST)calloc(1, sizeof(INST));
    pinst = *_pinst;
    if(!pinst) {
		PyErr_SetString(PyExc_MemoryError, "Can't allocate memory");
		return;
	}
    
    pinst->type = get_long_attribute(pPInst, "type");
    
    PyString_AsStringAndSize(
        get_attribute(pPInst, "mnemonic"),
        (void *)&pinst->mnemonic, &mnemonic_length);


    pinst->flags1 = get_long_attribute(pPInst, "flags1");
    pinst->flags2 = get_long_attribute(pPInst, "flags2");
    pinst->flags3 = get_long_attribute(pPInst, "flags3");
    pinst->modrm = get_long_attribute(pPInst, "modrm");
    pinst->checked = get_long_attribute(pPInst, "checked");
}


/*
    Create an "Operand" Python object from an OPERAND structure.
*/
PyObject *create_operand_object(OPERAND *op)
{
    PyObject *pOperand = create_class("Operand");
    
    if(!pOperand)
        return NULL;

    assign_attribute(pOperand, "type", PyLong_FromLong(op->type));
    assign_attribute(pOperand, "reg", PyLong_FromLong(op->reg));
    assign_attribute(pOperand, "basereg", PyLong_FromLong(op->basereg));
    assign_attribute(pOperand, "indexreg", PyLong_FromLong(op->indexreg));
    assign_attribute(pOperand, "scale", PyLong_FromLong(op->scale));
    assign_attribute(pOperand, "dispbytes", PyLong_FromLong(op->dispbytes));
    assign_attribute(pOperand, "dispoffset", PyLong_FromLong(op->dispoffset));
    assign_attribute(pOperand, "immbytes", PyLong_FromLong(op->immbytes));
    assign_attribute(pOperand, "immoffset", PyLong_FromLong(op->immoffset));
    assign_attribute(pOperand, "sectionbytes", PyLong_FromLong(op->sectionbytes));
    assign_attribute(pOperand, "section", PyLong_FromLong(op->section));
    assign_attribute(pOperand, "displacement", PyLong_FromLong(op->displacement));
    assign_attribute(pOperand, "immediate", PyLong_FromLong(op->immediate));
    assign_attribute(pOperand, "flags", PyLong_FromLong(op->flags));
    
    return pOperand;
}


/*
    Fill an OPERAND structure from the data in an "Operand" Python object.
*/
void fill_operand_structure(PyObject *pOperand, OPERAND *op)
{
    if(!pOperand || !op)
        return;
        
    op->type = get_long_attribute(pOperand, "type");
    op->reg = get_long_attribute(pOperand, "reg");
    op->basereg = get_long_attribute(pOperand, "basereg");
    op->indexreg = get_long_attribute(pOperand, "indexreg");
    op->scale = get_long_attribute(pOperand, "scale");
    op->dispbytes = get_long_attribute(pOperand, "dispbytes");
    op->dispoffset = get_long_attribute(pOperand, "dispoffset");
    op->immbytes = get_long_attribute(pOperand, "immbytes");
    op->immoffset = get_long_attribute(pOperand, "immoffset");
    op->sectionbytes = get_long_attribute(pOperand, "sectionbytes");
    op->section = get_long_attribute(pOperand, "section");
    op->displacement = get_long_attribute(pOperand, "displacement");
    op->immediate = get_long_attribute(pOperand, "immediate");
    op->flags = get_long_attribute(pOperand, "flags");
}


/*
    Create an "Instruction" Python object from an INSTRUCTION structure.
*/
PyObject *create_instruction_object(INSTRUCTION *insn)
{
    PyObject *pInstruction = create_class("Instruction");

    if(!pInstruction)
        return NULL;
    
    assign_attribute(pInstruction, "length", PyLong_FromLong(insn->length));
    assign_attribute(pInstruction, "type", PyLong_FromLong(insn->type));
    assign_attribute(pInstruction, "mode", PyLong_FromLong(insn->mode));
    assign_attribute(pInstruction, "opcode", PyLong_FromLong(insn->opcode));
    assign_attribute(pInstruction, "modrm", PyLong_FromLong(insn->modrm));
    assign_attribute(pInstruction, "modrm_offset", PyLong_FromLong(insn->modrm_offset));
    assign_attribute(pInstruction, "opcode_offset", PyLong_FromLong(insn->opcode_offset));
    assign_attribute(pInstruction, "sib", PyLong_FromLong(insn->sib));
    assign_attribute(pInstruction, "extindex", PyLong_FromLong(insn->extindex));
    assign_attribute(pInstruction, "fpuindex", PyLong_FromLong(insn->fpuindex));
    assign_attribute(pInstruction, "dispbytes", PyLong_FromLong(insn->dispbytes));
    assign_attribute(pInstruction, "immbytes", PyLong_FromLong(insn->immbytes));
    assign_attribute(pInstruction, "sectionbytes", PyLong_FromLong(insn->sectionbytes));
    assign_attribute(pInstruction, "op1", create_operand_object(&insn->op1));
    assign_attribute(pInstruction, "op2", create_operand_object(&insn->op2));
    assign_attribute(pInstruction, "op3", create_operand_object(&insn->op3));
    assign_attribute(pInstruction, "ptr", create_inst_object(insn->ptr));
    assign_attribute(pInstruction, "flags", PyLong_FromLong(insn->flags));
    assign_attribute(pInstruction, "eflags_affected", PyLong_FromLong(insn->eflags_affected));
    assign_attribute(pInstruction, "eflags_used", PyLong_FromLong(insn->eflags_used));
    assign_attribute(pInstruction, "iop_written", PyLong_FromLong(insn->iop_written));
    assign_attribute(pInstruction, "iop_read", PyLong_FromLong(insn->iop_read));
        
    return pInstruction;
}


/*
    Fill an INSTRUCTION structure from the data in an "Instruction" Python object.
*/
void fill_instruction_structure(PyObject *pInstruction, INSTRUCTION *insn)
{
    insn->length = get_long_attribute(pInstruction, "length");
    insn->type = get_long_attribute(pInstruction, "type");
    insn->mode = get_long_attribute(pInstruction, "mode");
    insn->opcode = get_long_attribute(pInstruction, "opcode");
    insn->modrm = get_long_attribute(pInstruction, "modrm");
    insn->modrm_offset = get_long_attribute(pInstruction, "modrm_offset");
    insn->opcode_offset = get_long_attribute(pInstruction, "opcode_offset");
    insn->sib = get_long_attribute(pInstruction, "sib");
    insn->extindex = get_long_attribute(pInstruction, "extindex");
    insn->fpuindex = get_long_attribute(pInstruction, "fpuindex");
    insn->dispbytes = get_long_attribute(pInstruction, "dispbytes");
    insn->immbytes = get_long_attribute(pInstruction, "immbytes");
    insn->sectionbytes = get_long_attribute(pInstruction, "sectionbytes");
    insn->flags = get_long_attribute(pInstruction, "flags");
    fill_operand_structure(get_attribute(pInstruction, "op1"), &insn->op1);
    fill_operand_structure(get_attribute(pInstruction, "op2"), &insn->op2);
    fill_operand_structure(get_attribute(pInstruction, "op3"), &insn->op3);
    fill_inst_structure(get_attribute(pInstruction, "ptr"), &insn->ptr);
    insn->iop_written = get_long_attribute(pInstruction, "iop_written");
    insn->iop_read = get_long_attribute(pInstruction, "iop_read");
    
}

/*
    Python counterpart of libdasm's "get_instruction"
*/
#define GET_INSTRUCTION_DOCSTRING                                               \
    "Decode an instruction from the given buffer.\n\n"                          \
    "Takes in a string containing the data to disassemble and the\nmode, "      \
    "either MODE_16 or MODE_32. Returns an Instruction object or \nNone if "    \
    "the instruction can't be disassembled."
    
PyObject *pydasm_get_instruction(PyObject *self, PyObject *args)
{
	PyObject *pBuffer, *pMode;
	INSTRUCTION insn;
	int size, mode;
	ssize_t data_length;
    char *data;

    
	if(!args || PyObject_Length(args)!=2) {
		PyErr_SetString(PyExc_TypeError,
			"Invalid number of arguments, 2 expected: (data, mode)");
		return NULL;
	}
	
	pBuffer = PyTuple_GetItem(args, 0);
	if(!check_object(pBuffer)) {
        PyErr_SetString(PyExc_ValueError, "Can't get buffer from arguments");
    }
    
	pMode = PyTuple_GetItem(args, 1);
	if(!check_object(pMode)) {
        PyErr_SetString(PyExc_ValueError, "Can't get mode from arguments");
    }
    mode = PyLong_AsLong(pMode);

    PyString_AsStringAndSize(pBuffer, &data, &data_length);
	
	size = get_instruction(&insn, (unsigned char *)data, mode);
    
    if(!size) {    
        Py_INCREF(Py_None);
        return Py_None;
    }

    return create_instruction_object(&insn);
}


/*
    Python counterpart of libdasm's "get_instruction_string"
*/
#define GET_INSTRUCTION_STRING_DOCSTRING                                    \
    "Transform an instruction object into its string representation.\n\n"   \
    "The function takes an Instruction object; its format, either \n"       \
    "FORMAT_INTEL or FORMAT_ATT and finally an offset (refer to \n"         \
    "libdasm for meaning). Returns a string representation of the \n"       \
    "disassembled instruction."
    
PyObject *pydasm_get_instruction_string(PyObject *self, PyObject *args)
{
	PyObject *pInstruction, *pFormat, *pOffset, *pStr;
	INSTRUCTION insn;
	unsigned long int offset, format;
    char *data;

    
	if(!args || PyObject_Length(args)!=3) {
		PyErr_SetString(PyExc_TypeError,
			"Invalid number of arguments, 3 expected: (instruction, format, offset)");
		return NULL;
	}
	
	pInstruction = PyTuple_GetItem(args, 0);
	if(!check_object(pInstruction)) {
        PyErr_SetString(PyExc_ValueError, "Can't get instruction from arguments");
    }
    if(pInstruction == Py_None) {
        Py_INCREF(Py_None);
        return Py_None;
    }
    memset(&insn, 0, sizeof(INSTRUCTION));
    fill_instruction_structure(pInstruction, &insn);
    
	pFormat = PyTuple_GetItem(args, 1);
	if(!check_object(pFormat)) {
        PyErr_SetString(PyExc_ValueError, "Can't get format from arguments");
    }
    format = PyLong_AsLong(pFormat);
	
	pOffset = PyTuple_GetItem(args, 2);
	if(!check_object(pOffset)) {
        PyErr_SetString(PyExc_ValueError, "Can't get offset from arguments");
    }
    offset = PyLong_AsLong(pOffset);

    data = (char *)calloc(1, INSTRUCTION_STR_BUFFER_LENGTH);
    if(!data) {
		PyErr_SetString(PyExc_MemoryError, "Can't allocate memory");
		return NULL;
	}
    
    if(!get_instruction_string(&insn, format, offset,
        data, INSTRUCTION_STR_BUFFER_LENGTH))
    {    
        Py_INCREF(Py_None);
        return Py_None;
    }
    
    pStr = PyString_FromStringAndSize(data, strlen(data));    
    free(insn.ptr);
    free(data);
    
    return pStr;
}


/*
    Python counterpart of libdasm's "get_mnemonic_string"
*/
#define GET_MNEMONIC_STRING_DOCSTRING                                       \
    "Transform an instruction object's mnemonic into its string representation.\n\n"    \
    "The function takes an Instruction object and its format, either \n"    \
    "FORMAT_INTEL or FORMAT_ATT. Returns a string representation of the \n" \
    "mnemonic."
    
PyObject *pydasm_get_mnemonic_string(PyObject *self, PyObject *args)
{
	PyObject *pInstruction, *pFormat, *pStr;
	INSTRUCTION insn;
	unsigned long int format;
    char *data;

	if(!args || PyObject_Length(args)!=2) {
		PyErr_SetString(PyExc_TypeError,
			"Invalid number of arguments, 3 expected: (instruction, format)");
		return NULL;
	}
	
	pInstruction = PyTuple_GetItem(args, 0);
	if(!check_object(pInstruction)) {
        PyErr_SetString(PyExc_ValueError, "Can't get instruction from arguments");
    }
    fill_instruction_structure(pInstruction, &insn);
    
	pFormat = PyTuple_GetItem(args, 1);
	if(!check_object(pFormat)) {
        PyErr_SetString(PyExc_ValueError, "Can't get format from arguments");
    }
    format = PyLong_AsLong(pFormat);
	
    data = (char *)calloc(1, INSTRUCTION_STR_BUFFER_LENGTH);
    if(!data) {
		PyErr_SetString(PyExc_MemoryError, "Can't allocate memory");
		return NULL;
	}
    
    get_mnemonic_string(&insn, format, data, INSTRUCTION_STR_BUFFER_LENGTH);
      
    pStr = PyString_FromStringAndSize(data, strlen(data));
    free(insn.ptr);
    free(data);
    
    return pStr;
}


/*
    Python counterpart of libdasm's "get_operand_string"
*/
#define GET_OPERAND_STRING_DOCSTRING                                        \
    "Transform an instruction object's operand into its string representation.\n\n"    \
    "The function takes an Instruction object; the operand index (0,1,2);\n"\
    " its format, either FORMAT_INTEL or FORMAT_ATT and finally an offset\n"\
    "(refer to libdasm for meaning). Returns a string representation of \n" \
    "the disassembled operand."
    
PyObject *pydasm_get_operand_string(PyObject *self, PyObject *args)
{
	PyObject *pInstruction, *pFormat, *pOffset, *pOpIndex, *pStr;
	INSTRUCTION insn;
	unsigned long int offset, format, op_idx;
    char *data;

    
	if(!args || PyObject_Length(args)!=4) {
		PyErr_SetString(PyExc_TypeError,
			"Invalid number of arguments, 4 expected: (instruction, operand index, format, offset)");
		return NULL;
	}
	
	pInstruction = PyTuple_GetItem(args, 0);
	if(!check_object(pInstruction)) {
        PyErr_SetString(PyExc_ValueError, "Can't get instruction from arguments");
    }
    memset(&insn, 0, sizeof(INSTRUCTION));
    fill_instruction_structure(pInstruction, &insn);
    
	pOpIndex = PyTuple_GetItem(args, 1);
	if(!check_object(pOpIndex)) {
        PyErr_SetString(PyExc_ValueError, "Can't get operand index from arguments");
    }
    op_idx = PyLong_AsLong(pOpIndex);
	
    pFormat = PyTuple_GetItem(args, 2);
	if(!check_object(pFormat)) {
        PyErr_SetString(PyExc_ValueError, "Can't get format from arguments");
    }
    format = PyLong_AsLong(pFormat);
	
	pOffset = PyTuple_GetItem(args, 3);
	if(!check_object(pOffset)) {
        PyErr_SetString(PyExc_ValueError, "Can't get offset from arguments");
    }
    offset = PyLong_AsLong(pOffset);

    data = (char *)calloc(1, INSTRUCTION_STR_BUFFER_LENGTH);
    if(!data) {
		PyErr_SetString(PyExc_MemoryError, "Can't allocate memory");
		return NULL;
	}
    
    if(!get_operand_string(&insn, &(insn.op1)+op_idx,
        format, offset, data, INSTRUCTION_STR_BUFFER_LENGTH))
    {    
        Py_INCREF(Py_None);
        return Py_None;
    }
    
    pStr = PyString_FromStringAndSize(data, strlen(data));
    free(insn.ptr);
    free(data);
    
    return pStr;
}


/*
    Python counterpart of libdasm's "get_register_type"
*/
#define GET_REGISTER_TYPE_DOCSTRING                                         \
    "Get the type of the register used by the operand.\n\n"                 \
    "The function takes an Operand object and returns a Long representing\n"\
    "the type of the register."
    
PyObject *pydasm_get_register_type(PyObject *self, PyObject *args)
{
	PyObject *pOperand;
    OPERAND op;

	if(!args || PyObject_Length(args)!=1) {
		PyErr_SetString(PyExc_TypeError,
			"Invalid number of arguments, 1 expected: (operand)");
		return NULL;
	}
	
	pOperand = PyTuple_GetItem(args, 0);
	if(!check_object(pOperand)) {
        PyErr_SetString(PyExc_ValueError, "Can't get instruction from arguments");
    }
    memset(&op, 0, sizeof(OPERAND));
    fill_operand_structure(pOperand, &op);
        
    return PyLong_FromLong(get_register_type(&op));
}


/*
    Map all the exported methods.
*/
static PyMethodDef pydasmMethods[] = {
	{"get_instruction", pydasm_get_instruction, METH_VARARGS,
	GET_INSTRUCTION_DOCSTRING},
	{"get_instruction_string", pydasm_get_instruction_string, METH_VARARGS,
	GET_INSTRUCTION_STRING_DOCSTRING},
	{"get_mnemonic_string", pydasm_get_mnemonic_string, METH_VARARGS,
	GET_MNEMONIC_STRING_DOCSTRING},
	{"get_operand_string", pydasm_get_operand_string, METH_VARARGS,
	GET_OPERAND_STRING_DOCSTRING},
	{"get_register_type", pydasm_get_register_type, METH_VARARGS,
	GET_REGISTER_TYPE_DOCSTRING},
//made using :'<,'>s/\(.*\)/    {"\1", _\1, METH_VARARGS, NULL},
    {"MASK_PREFIX_G1", _MASK_PREFIX_G1, METH_VARARGS, NULL},
    {"MASK_PREFIX_G1", _MASK_PREFIX_G1, METH_VARARGS, NULL},
    {"MASK_PREFIX_G2", _MASK_PREFIX_G2, METH_VARARGS, NULL},
    {"MASK_PREFIX_G3", _MASK_PREFIX_G3, METH_VARARGS, NULL},
    {"MASK_PREFIX_OPERAND", _MASK_PREFIX_OPERAND, METH_VARARGS, NULL},
    {"MASK_PREFIX_ADDR", _MASK_PREFIX_ADDR, METH_VARARGS, NULL},
    {"MASK_EXT", _MASK_EXT, METH_VARARGS, NULL},
    {"MASK_TYPE_FLAGS", _MASK_TYPE_FLAGS, METH_VARARGS, NULL},
    {"MASK_TYPE_VALUE", _MASK_TYPE_VALUE, METH_VARARGS, NULL},
    {"MASK_AM", _MASK_AM, METH_VARARGS, NULL},
    {"MASK_OT", _MASK_OT, METH_VARARGS, NULL},
    {"MASK_PERMS", _MASK_PERMS, METH_VARARGS, NULL},
    {"MASK_FLAGS", _MASK_FLAGS, METH_VARARGS, NULL},
    {"MASK_REG", _MASK_REG, METH_VARARGS, NULL},
    {"MASK_MODRM_MOD", _MASK_MODRM_MOD, METH_VARARGS, NULL},
    {"MASK_MODRM_REG", _MASK_MODRM_REG, METH_VARARGS, NULL},
    {"MASK_MODRM_RM", _MASK_MODRM_RM, METH_VARARGS, NULL},
    {"MASK_SIB_SCALE", _MASK_SIB_SCALE, METH_VARARGS, NULL},
    {"MASK_SIB_INDEX", _MASK_SIB_INDEX, METH_VARARGS, NULL},
    {"MASK_SIB_BASE", _MASK_SIB_BASE, METH_VARARGS, NULL},
	{NULL, NULL, 0, NULL}
};


/*
    Init the module, set constants.
*/
PyMODINIT_FUNC initpydasm(void)
{
    int i;
    PyObject *pModule;
    
	pModule = Py_InitModule("pydasm", pydasmMethods);

    assign_attribute(pModule, "FORMAT_ATT", PyLong_FromLong(0));
    assign_attribute(pModule, "FORMAT_INTEL", PyLong_FromLong(1));

    assign_attribute(pModule, "MODE_16", PyLong_FromLong(1));
    assign_attribute(pModule, "MODE_32", PyLong_FromLong(0));
    
    for(i=0; instruction_types[i]; i++)
        assign_attribute(pModule, instruction_types[i], PyLong_FromLong(i));
    
    for(i=0; operand_types[i]; i++)
        assign_attribute(pModule, operand_types[i], PyLong_FromLong(i));

    for(i=0; registers[i]; i++)
        assign_attribute(pModule, registers[i], PyLong_FromLong(i));
        
    for(i=0; register_types[i]; i++)
        assign_attribute(pModule, register_types[i], PyLong_FromLong(i+1));
    
    for(i=0; i < sizeof(flags)/sizeof(struct flag); i++)
        assign_attribute(pModule, flags[i].name, PyLong_FromLong(flags[i].value));
}


int main(int agrc, char *argv[])
{
	Py_SetProgramName(argv[0]);
	
	Py_Initialize();
	
	initpydasm();

	return 0;
}


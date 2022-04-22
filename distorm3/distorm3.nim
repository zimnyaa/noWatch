when hostCPU == "i386":
  {.passC: "-DDISTORM_STATIC -include stdint.h".}
  const SUFFIX = "32"
else:
  {.passC: "-DSUPPORT_64BIT_OFFSET".}
  const SUFFIX = "64"

import distorm3/mnemonics

import os
const PATH = currentSourcePath.splitPath.head

{.passC: "-I " & PATH & "/private/distorm/include".}

{.compile: PATH & "/private/distorm/src/decoder.c".}
{.compile: PATH & "/private/distorm/src/distorm.c".}
{.compile: PATH & "/private/distorm/src/instructions.c".}
{.compile: PATH & "/private/distorm/src/insts.c".}
{.compile: PATH & "/private/distorm/src/mnemonics.c".}
{.compile: PATH & "/private/distorm/src/operands.c".}
{.compile: PATH & "/private/distorm/src/prefix.c".}
{.compile: PATH & "/private/distorm/src/textdefs.c".}

type
  DecodeType* = enum
    Decode16Bits
    Decode32Bits
    Decode64Bits

  DecodeResult* = enum
    DECRES_NONE
    DECRES_SUCCESS
    DECRES_MEMORYERR
    DECRES_INPUTERR
    DECRES_FILTERED

  DecodeFeature* {.size: sizeof(int).} = enum
    #Features for decompose
    DF_NONE
    DF_MAXIMUM_ADDR16
    DF_MAXIMUM_ADDR32
    DF_RETURN_FC_ONLY = 4
    DF_STOP_ON_CALL = 8
    DF_STOP_ON_RET = 0x10
    DF_STOP_ON_SYS = 0x20
    DF_STOP_ON_UNC_BRANCH = 0x40
    DF_STOP_ON_CND_BRANCH = 0x80
    DF_STOP_ON_INT = 0x100
    DF_STOP_ON_CMOV = 0x200
    DF_STOP_ON_HLT = 0x400
    DF_STOP_ON_PRIVILEGED = 0x800
    DF_SINGLE_BYTE_STEP = 0x1000
    DF_FILL_EFLAGS = 0x2000
    DF_USE_ADDR_MASK = 0x4000

  ValuePtr* {.bycopy.} = object
    seg*: uint16
    off*: uint32

  ValueEx* {.bycopy.} = object
    i1*: uint32
    i2*: uint32

  CodeInfo* {.bycopy.} = object
    codeOffset*: uint
    addrMask*: uint
    nextOffset*: uint
    code*: pointer
    codeLen*: int
    dt*: DecodeType
    features*: DecodeFeature

  Value* {.bycopy, union.} = object
    sbyte*: int8
    byt*: uint8
    sword*: int16
    word*: uint16
    sdword*: int32
    dword*: uint32
    sqword*: int64
    qword*: uint64
    adr*: uint
    pptr*: ValuePtr
    ex*: ValueEx

  Operand* {.bycopy.} = object
    kind*: uint8
    index*: RegisterType
    size*: uint16

  WString* {.bycopy.} = object
    length*: cuint
    p*: array[48, char]

  DInst* {.bycopy.} = object
    imm*: Value
    disp*: uint64
    adr*: uint
    flags*: uint16
    unusedPrefixesMask*: uint16
    usedRegistersMask*: uint32
    opcode*: InstructionType
    ops*: array[4, Operand]
    opsNo*: uint8
    size*: uint8
    segment*: uint8
    base*: uint8
    scale*: uint8
    dispSize*: uint8
    meta*: uint16
    modifiedFlagsMask*: uint16
    testedFlagsMask*: uint16
    undefinedFlagsMask*: uint16

  DecodedInst* {.bycopy.} = object
    offset*: uint
    size*: cuint
    mnemonic*: WString
    operands*: WString
    instructionHex*: WString

proc `$`*(ws: WString): string = $cast[cstring](unsafeAddr ws.p[0])
proc `$`*(di: DecodedInst): string = $di.mnemonic & " " & $di.operands

proc distorm_decompose*(ci: ptr CodeInfo, res: ptr DInst, maxInstructions: uint32, usedInstructionsCount: ptr uint32): DecodeResult {.importc: "distorm_decompose" & SUFFIX, cdecl.}
proc distorm_decode*(codeOffset: uint, code: pointer, codeLen: int32, dt: DecodeType, res: ptr DecodedInst, maxInstructions: uint32, usedInstructionsCount: ptr uint32): DecodeResult {.importc: "distorm_decode" & SUFFIX, cdecl.}
proc distorm_format*(ci: ptr CodeInfo, di: ptr DInst, res: ptr DecodedInst) {.importc: "distorm_format" & SUFFIX, cdecl.}
proc distorm_version*(): uint32 {.importc, cdecl.}


{.emit:"""
// credit: https://github.com/Mr-Un1k0d3r/EDRs/blob/main/hook_finder64.c


#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <winnt.h>


VOID checkexports(VOID *lib, BOOL bNt) {
    printf("listing hooks\n");
    IMAGE_DOS_HEADER* MZ = (IMAGE_DOS_HEADER*)lib;
    IMAGE_NT_HEADERS* PE = (IMAGE_NT_HEADERS*)((BYTE*)lib + MZ->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* export = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)lib + PE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    DWORD *name = (DWORD*)((BYTE*)lib + export->AddressOfNames);

    DWORD i = 0;
    for(i; i < export->NumberOfNames; i++) 

{


        CheckJmp((CHAR*)lib + name[i], (DWORD*)GetProcAddress(lib, lib + name[i]), bNt);
    }    
}

VOID CheckJmp(CHAR *name, DWORD* address, BOOL bNt) {
    BYTE* opcode = (BYTE*)address;


    if(bNt) {
        if(!(name[0] == 'N' && name[1] == 't')) {
            return;
        }
    }
    if(*opcode == 0xe9) {
        printf("  !hooked : %s\n", name);
    }
}
""".}

proc checkexports(lib: PVOID, bNt: bool) {.importc: "checkexports", nodecl.}


proc listdlls() =
  var hSnap: HANDLE = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0)
  var me32: MODULEENTRY32
  me32.dwSize = cast[DWORD](sizeof(MODULEENTRY32))

  echo " ! listing loaded modules"
  if Module32First(hSnap, &me32):
    while true:
      echo fmt" ! {lpwstrc(me32.szExePath)} -> loaded @ {toHex(cast[DWORD](me32.modBaseAddr))}."
      var modnextres = Module32Next(hSnap, &me32) 
      if modnextres != 1: break

  CloseHandle(hSnap)


proc dump_func_toret(library: string, funcname: string, max_ret_count: int) =
  var libhandle = loadLib(library)
  var funcaddr = libhandle.symAddr(funcname)
  echo " ! funcaddr -> ", toHex(cast[int](funcaddr))

  var
    decodedInstructionsCount = 0'u32
    decodedInsts: array[4096, DInst]

    ci = CodeInfo(
      codeOffset: 0x0,
      code: funcaddr,
      codeLen: 4096,
      dt: Decode64Bits,
      features: DF_NONE
    )

    formatted_inst: DecodedInst
    ret_count: int = 0
    offset: int = 0


  discard distorm_decompose(addr ci, addr decodedInsts[0], sizeof(DInst).uint32, addr decodedInstructionsCount)
  for i in 0..<decodedInstructionsCount:
    distorm_format(addr ci, addr decodedInsts[i], addr formatted_inst)
    echo fmt" ! {formatted_inst.instructionHex:>16} | ", formatted_inst.mnemonic, " ", formatted_inst.operands
    offset += cast[int](decodedInsts[i].size)
    if $(decodedInsts[i].opcode) == "I_RET":
      ret_count += 1
    if $(decodedInsts[i].opcode) == "I_JMP":
      echo fmt" !                    absaddr (patch) 0x", toHex(cast[int](decodedInsts[i].imm.dword) + offset + cast[int](funcaddr) - 4294967296)
    if ret_count == max_ret_count:
      break

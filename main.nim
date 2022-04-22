import distorm3/distorm3
import dynlib, winim
import ptr_math 

import std/strutils
import std/strformat
import std/tables

include utils/utils
include utils/inspect
include utils/attacks


# commands
var runtime_config = {
  "currentlibrary": "ntdll.dll",
  "ret_depth": "2"
}.toTable




proc refresh_cmd(args: string) =
  let low: uint16 = 0
  var 
      processH = GetCurrentProcess()
      mi : MODULEINFO
      ntdllModule = GetModuleHandleA(runtime_config["currentlibrary"])
      ntdllBase : LPVOID
      ntdllFile : FileHandle
      ntdllMapping : HANDLE
      ntdllMappingAddress : LPVOID
      hookedDosHeader : PIMAGE_DOS_HEADER
      hookedNtHeader : PIMAGE_NT_HEADERS
      hookedSectionHeader : PIMAGE_SECTION_HEADER

  GetModuleInformation(processH, ntdllModule, addr mi, cast[DWORD](sizeof(mi)))
  ntdllBase = mi.lpBaseOfDll
  ntdllFile = getOsFileHandle(open("C:\\windows\\system32\\"&runtime_config["currentlibrary"],fmRead))
  ntdllMapping = CreateFileMapping(ntdllFile, NULL, 16777218, 0, 0, NULL) # 0x02 =  PAGE_READONLY & 0x1000000 = SEC_IMAGE
  ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0)
  hookedDosHeader = cast[PIMAGE_DOS_HEADER](ntdllBase)
  hookedNtHeader = cast[PIMAGE_NT_HEADERS](cast[DWORD_PTR](ntdllBase) + hookedDosHeader.e_lfanew)
  for Section in low ..< hookedNtHeader.FileHeader.NumberOfSections:
      hookedSectionHeader = cast[PIMAGE_SECTION_HEADER](cast[DWORD_PTR](IMAGE_FIRST_SECTION(hookedNtHeader)) + cast[DWORD_PTR](IMAGE_SIZEOF_SECTION_HEADER * Section))
      if ".text" in toString(hookedSectionHeader.Name):
          var oldProtection : DWORD = 0
          VirtualProtect(ntdllBase + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize, 0x40, addr oldProtection)
          copyMem(ntdllBase + hookedSectionHeader.VirtualAddress, ntdllMappingAddress + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize)
          VirtualProtect(ntdllBase + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize, oldProtection, addr oldProtection)
  CloseHandle(processH)
  CloseHandle(ntdllFile)
  CloseHandle(ntdllMapping)
  FreeLibrary(ntdllModule)

var commands = {"refresh": refresh_cmd}.toTable
var helpstrings = {"refresh": "reload .text of the currentlibrary from disk (evasion)"}.toTable()

proc disas_cmd(args: string) =
  dump_func_toret(runtime_config["currentlibrary"], args, parseInt(runtime_config["ret_depth"]))  
commands["disas"] = disas_cmd
helpstrings["disas"] = "disassemble a function in the current library (discovery)"

proc disas_addr_cmd(args: string) =
  var
    max_ret_count: int = parseInt(runtime_config["ret_depth"])
    decodedInstructionsCount = 0'u32
    decodedInsts: array[4096, DInst]

    ci = CodeInfo(
      codeOffset: 0x0,
      code: cast[PVOID](parseHexInt(args)),
      codeLen: 4096,
      dt: Decode64Bits,
      features: DF_NONE
    )

    formatted_inst: DecodedInst
    ret_count: int = 0



  discard distorm_decompose(addr ci, addr decodedInsts[0], sizeof(DInst).uint32, addr decodedInstructionsCount)
  for i in 0..<decodedInstructionsCount:
    distorm_format(addr ci, addr decodedInsts[i], addr formatted_inst)
    echo fmt" ! {formatted_inst.instructionHex:>16} | ", formatted_inst.mnemonic, " ", formatted_inst.operands
    if $(decodedInsts[i].opcode) == "I_RET":
      ret_count += 1
    if ret_count == max_ret_count:
      break

commands["disas_addr"] = disas_addr_cmd  
helpstrings["disas_addr"] = "disassemble @address (discovery)"  


proc modname_cmd(args: string) =
  var module_base: LPVOID
  var module_name: array[MAX_PATH, WCHAR]
  RtlPcToFileHeader(cast[PVOID](parseHexInt(args)), &module_base);
  GetModuleFileNameEx(GetCurrentProcess(), cast[HMODULE](module_base), &module_name[0], cast[DWORD](sizeof(module_name)));

  echo " ! 0x", toHex(cast[int](cast[PVOID](parseHexInt(args)))), " is in ", lpwstrc(module_name)
commands["modname"] = modname_cmd
helpstrings["modname"] = "find module name for address (discovery)"

proc showrwx_cmd(args: string) =
  echo " ! enumerating"
  var mbi: MEMORY_BASIC_INFORMATION
  var offset: LPVOID 
  var process: HANDLE = GetCurrentProcess()
  var processEntry: PROCESSENTRY32
  processEntry.dwSize = cast[DWORD](sizeof(PROCESSENTRY32))

   
  var module_base: LPVOID
  var module_name: array[MAX_PATH, WCHAR]

  while VirtualQueryEx(process, offset, addr(mbi), sizeof(mbi)) != 0:
    offset = cast[LPVOID](cast[DWORD_PTR](mbi.BaseAddress) + mbi.RegionSize)
    if mbi.AllocationProtect == PAGE_EXECUTE_READWRITE and mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE:
      

      RtlPcToFileHeader(mbi.BaseAddress, &module_base);
      GetModuleFileNameEx(GetCurrentProcess(), cast[HMODULE](module_base), &module_name[0], cast[DWORD](sizeof(module_name)));

      echo " ! RWX: 0x", toHex(cast[int](mbi.BaseAddress)), " ", lpwstrc(module_name)
      zeromem(&module_name[0], sizeof(module_name))
commands["showrwx"] = showrwx_cmd
helpstrings["showrwx"] = "show rwx pages in the current process (discovery)"

proc showrx_cmd(args: string) =
  echo " ! enumerating"
  var mbi: MEMORY_BASIC_INFORMATION
  var offset: LPVOID 
  var process: HANDLE = GetCurrentProcess()
  var processEntry: PROCESSENTRY32
  processEntry.dwSize = cast[DWORD](sizeof(PROCESSENTRY32))

  var module_base: LPVOID
  var module_name: array[MAX_PATH, WCHAR]

  while VirtualQueryEx(process, offset, addr(mbi), sizeof(mbi)) != 0:

    offset = cast[LPVOID](cast[DWORD_PTR](mbi.BaseAddress) + mbi.RegionSize)
    if mbi.AllocationProtect == PAGE_EXECUTE_READ:

      RtlPcToFileHeader(mbi.BaseAddress, &module_base);
      GetModuleFileNameEx(GetCurrentProcess(), cast[HMODULE](module_base), &module_name[0], cast[DWORD](sizeof(module_name)));

      echo " ! RX: 0x", toHex(cast[int](mbi.BaseAddress)), " ", lpwstrc(module_name)
      zeromem(&module_name[0], sizeof(module_name))
commands["showrx"] = showrx_cmd
helpstrings["showrx"] = "show rx pages in the current process (discovery)"
      
proc virtualquery_cmd(args: string) =
  echo " ! enumerating"
  var mbi: MEMORY_BASIC_INFORMATION
  var offset: LPVOID 
  var process: HANDLE = GetCurrentProcess()
  var processEntry: PROCESSENTRY32
  processEntry.dwSize = cast[DWORD](sizeof(PROCESSENTRY32))

  var module_base: LPVOID
  var module_name: array[MAX_PATH, WCHAR]

  while VirtualQueryEx(process, offset, addr(mbi), sizeof(mbi)) != 0:

    offset = cast[LPVOID](cast[DWORD_PTR](mbi.BaseAddress) + mbi.RegionSize)
    
    RtlPcToFileHeader(mbi.BaseAddress, &module_base);
    GetModuleFileNameEx(GetCurrentProcess(), cast[HMODULE](module_base), &module_name[0], cast[DWORD](sizeof(module_name)));
    if args != "":
      if args in lpwstrc(module_name):
        echo " ! addr: 0x", toHex(cast[int](mbi.BaseAddress)), " ", lpwstrc(module_name), " prot:", mbi.AllocationProtect
    else:
      echo " ! addr: 0x", toHex(cast[int](mbi.BaseAddress)), " ", lpwstrc(module_name), " prot:", mbi.AllocationProtect
    zeromem(&module_name[0], sizeof(module_name))
commands["virtualquery"] = virtualquery_cmd
helpstrings["virtualquery"] = "show all vmemory pages (discovery)"
      

proc showjump_cmd(args: string) =
  var hDll: HANDLE = LoadLibrary(runtime_config["currentlibrary"]);
  checkexports(cast[PVOID](hDll), true)
commands["jmphooks"] = showjump_cmd
helpstrings["jmphooks"] = "show jmp instructions at the beginning of all functions in the current library (discovery)"

proc listdll_cmd(args: string) =
  listdlls()
commands["listdlls"] = listdll_cmd
helpstrings["listdlls"] = "list running DLLs in the current process (discovery)"



# utility commands
proc show_help(args: string) =
  echo "supported commands:"
  for cname in commands.keys:
    echo fmt"{cname:>16} -> ", helpstrings[cname]
  echo "attack commands:"
  for cname in attack_commands.keys:
    echo fmt"{cname:>16} -> ", attack_help[cname]


commands["help"] = show_help
helpstrings["help"] = "show help (util)"

proc set_cmd(args: string) =
  var cfgkey, cfgval: string
  cfgkey = split(args, " ", 1)[0]
  cfgval = split(args, " ", 1)[1]
  runtime_config[cfgkey] = cfgval
commands["set"] = set_cmd
helpstrings["set"] = "set runtime config (util)"

proc showconfig_cmd(args: string) =
  echo runtime_config
commands["showconfig"] = showconfig_cmd
helpstrings["showconfig"] = "show runtime config (util)"



# interactive cli part
discard AllocConsole()
discard SetConsoleTitle("noWatch <3");
discard stdout.reopen("CONOUT$", fmWrite)
discard stdin.reopen("CONIN$", fmRead)


var full_command = ""
var command = ""
var args = ""

stdout.write("nw|" & runtime_config["currentlibrary"] & ">")
full_command = readLine(stdin)

while full_command != "exit":
  if " " in full_command:
    command = split(full_command, " ", 1)[0]
    args = split(full_command, " ", 1)[1]
  else:
    command = full_command
    args = ""
  if command in commands:
    commands[command](args) 
  elif command in attack_commands:
    attack_commands[command](args) 
  elif command != "":
    show_help(args)

  stdout.write("nw|" & runtime_config["currentlibrary"] & ">")
  full_command = readLine(stdin)

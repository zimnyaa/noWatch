import winim

proc NimMain() {.cdecl, importc.}

proc Run() : int {.stdcall, exportc, dynlib.} =
  MessageBox(0, "Run", "Run called", MB_OK)
  return 0
  
proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID) : BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  MessageBox(0, "DllMain", "DllMain called", MB_OK)
  
  return true
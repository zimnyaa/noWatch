# noWatch
---

**noWatch** is an interactive console application that allows tampering with EDR userland hooks and testing EDR detection capabilities. It is meant to be used as a standalone binary or converted with `donut` and remotely injected. In general, it is designed as a drop-in replacement for testing what C2 framework features can get detected without deploying C2 in an Internet-isolated detection lab.
Usage demo:

---
![nowatch_0 0 1](https://user-images.githubusercontent.com/502153/164777170-41ed8161-f646-4336-a124-1b31c4c0b35c.gif)


**nowatch** capabilities are divided into discovery commands and attacks. Discovery commands are simple and few:
```
         modname -> find module name for address (discovery)
          showrx -> show rx pages in the current process (discovery)
             set -> set runtime config (util)
        jmphooks -> show jmp instructions at the beginning of all functions in the current library (discovery)
      disas_addr -> disassemble @address (discovery)
      showconfig -> show runtime config (util)
         refresh -> reload .text of the currentlibrary from disk (evasion)
        listdlls -> list running DLLs in the current process (discovery)
           disas -> disassemble a function in the current library (discovery)
    virtualquery -> show all vmemory pages (discovery)
         showrwx -> show rwx pages in the current process (discovery)
            help -> show help (util)
```

attacks are pretty simple, as they are meant to test various malicious activity primitives
```
     crt_inject -> execute msgbox remotely with CreateRemoteThread
         loadclr -> load a demo C# assembly to the process
         loadpsh -> execute psh with System.Management.Automation
           spawn -> calls startprocess
         dropdll -> drop a stub dll to disk
            exec -> calls execCmd
        patchetw -> patch EtwEventWrite with a single RET (evasion)
             iwr -> fetches a URL (http only), prints first 200 chars
    local_inject -> execute msgbox locally
       patchamsi -> patch AMSI (evasion)
     impersonate -> calls ImpersonateLoggedOnUser on pid
      whoami_bof -> calls whoami.o BOF (for testing COFFLoading)
      unhook_bof -> calls unhook.o BOF (as another unhooking method)
      ppid_spoof -> create suspended notepad process with PPID spoofing to explorer
```

# dependencies&building
`$ nimble install winim ptr_math memlib`

- Distorm3 from nimble is also used, but it had to be patched, so it's shipped here as well. In general, disassembly in **noWatch** is really bad and unreliable. Use a proper debugger if you can.

```
$ nim c --threads:on --passL:"-static-libgcc -static -lpthread" --app:gui --threadAnalysis:off .\main.nim
$ nim c --nomain --app:lib -o:.\resources\stub.dll .\resources\stub.nim
```
# credits and offensive Nim resources
- https://github.com/byt3bl33d3r/OffensiveNim
- https://github.com/gdabah/distorm
- https://github.com/khchen/winim
- https://github.com/khchen/memlib
- `sliverarmory`, `trustedsec` and `rsmudge` for the bofs

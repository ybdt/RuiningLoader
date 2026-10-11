x64:
    load "../../build/services.x64.o"
        merge

    mergelib "../../crystal_palace/libtcg.x64.zip"

    # ── DFR resolvers: ror13 for always-loaded modules, strings for everything else ──
    dfr "resolve" "ror13" "KERNEL32, NTDLL"
    dfr "resolve_ext" "strings"

    # ── ised: break signature islands around resolver function bodies ──
    # The resolve/resolve_ext functions are shared library code and prime signature targets
    pack $NOP "b" 0x90
    ised insert "call findModuleByHash" $NOP +safe
    ised insert "call findFunctionByHash" $NOP +safe
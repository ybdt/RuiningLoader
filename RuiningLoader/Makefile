CC_64=x86_64-w64-mingw32-gcc
NASM=nasm
CFLAGS=-DWIN_X64 -shared -Wall -Wno-pointer-arith -mno-stack-arg-probe -fno-zero-initialized-in-bss -fasynchronous-unwind-tables -mabi=ms -foptimize-sibling-calls -falign-functions=1 -falign-jumps=1 -falign-loops=1

all: build/loader.x64.o build/hooks.x64.o build/pico.x64.o build/services.x64.o build/stomp.x64.o build/cfg.x64.o

build:
	@mkdir -p build

build/loader.x64.o: build
	@echo "  CC  build/pico.x64.o"
	@$(CC_64) $(CFLAGS) -c src/pico.c -o build/pico.x64.o
	@echo "  CC  build/loader.x64.o"
	@$(CC_64) $(CFLAGS) -c src/loader.c -o build/loader.x64.o
	@echo "  CC  build/stomp.x64.o"
	@$(CC_64) $(CFLAGS) -c src/stomp.c -o build/stomp.x64.o
	@echo "  CC  build/services.x64.o"
	@$(CC_64) $(CFLAGS) -c src/services.c -o build/services.x64.o
	@echo "  CC  build/hooks.x64.o"
	@$(CC_64) $(CFLAGS) -c src/hooks.c -o build/hooks.x64.o
	@echo "  CC  build/cfg.x64.o"
	@$(CC_64) $(CFLAGS) -c src/cfg.c -o build/cfg.x64.o

clean:
	@rm -f build/*.o build/*.bin output/*
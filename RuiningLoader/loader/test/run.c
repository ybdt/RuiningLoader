/*
 * (c) 2025 Raphael Mudge
 * A very quick'n'dirty shellcode injector.
 *
 * Part of the Crystal Palace distribution
 *
 * BSD 3-clause license.
 */
#include <windows.h>
#include <stdio.h>
#include <winsock.h>

/* context passed to the timer queue callback */
typedef struct {
	char * picData;
	DWORD  picSize;
} PIC_CLEANUP_CTX;

/* timer callback: runs go(), then wipes and frees the RWX PIC allocation */
VOID CALLBACK RunAndCleanupPIC(PVOID lpParam, BOOLEAN TimerOrWaitFired) {
	PIC_CLEANUP_CTX * ctx = (PIC_CLEANUP_CTX *)lpParam;

	/* execute the PIC loader (go function) */
	( (void (*)())ctx->picData )();

	/* go() returned — PIC code is no longer executing, clean up the RWX allocation */
	SecureZeroMemory(ctx->picData, ctx->picSize);
	VirtualFree(ctx->picData, 0, MEM_RELEASE);
	ctx->picData = NULL;
	printf("[cleanup] PIC loader memory wiped and freed.\n");
}

DWORD GetVolSerialNo() {
	DWORD volumeSerialNumber = 0;
	GetVolumeInformationA("c:\\", NULL, 0, &volumeSerialNumber, NULL, NULL, NULL, 0);
	return volumeSerialNumber;
}

/*
 * When no arguments are provided, run.x##.exe prints usage information AND several KEY=VALUE
 * pairs to aid working with some of the Tradecraft Garden samples.
 *
 * The ./link command in Crystal Palace takes KEY=VAL arguments, which are just a bunch of bytes
 * specified in hex. The ./link command has no knowledge of the types we're passing (e..g, a char
 * array, a pointer, something else)? and so we need to print the values in little-endian byte
 * order to make everything work out right.
 */
#ifdef WIN_X64
typedef union {
	ULONG_PTR value;
	struct {
		DWORD a;
		DWORD b;
	} parts;
} QWORD;

ULONG_PTR rev64(ULONG_PTR val) {
	QWORD temp = { .value = val };
	DWORD swap;

	swap = temp.parts.b;
	temp.parts.b = htonl(temp.parts.a);
	temp.parts.a = htonl(swap);

	return temp.value;
}
#endif

int main(int argc, char * argv[]) {
	/* check or args */
	if (argc != 2) {
		printf("USAGE: %s <file.bin>\n", argv[0]);
		printf("\nSimple Loader 4 (Pointer Patching):\n\n");

		#ifdef WIN_X64
			printf("GMH=%016llx\n", rev64((ULONG_PTR)GetModuleHandle));
			printf("GPA=%016llx\n", rev64((ULONG_PTR)GetProcAddress));
		#else
			printf("GMH=%08lx\n", htonl((DWORD)GetModuleHandle));
			printf("GPA=%08lx\n", htonl((DWORD)GetProcAddress));
		#endif

		/* print out our envkey with little endian-byte order. */
		DWORD serialNoRev = htonl(GetVolSerialNo());

		printf("\nSimple Loader 5 (Execution Guardrails):\n\n");
		printf("ENVKEY=%08lx%08lx\n", serialNoRev, serialNoRev);

		return 0;
	}

	/* continue on! */
	HANDLE hFile;
	char * file = argv[1];
	char * data;
	DWORD  fileSz;
	DWORD  read;

	/* open the file for reading */
	hFile = CreateFile(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("Unable to open %s for read: %ld", file, GetLastError());
		return 0;
	}

	/* get our file size */
	fileSz = GetFileSize(hFile, NULL);
	if (fileSz == INVALID_FILE_SIZE) {
		printf("Invalid file size for %s: %ld", file, GetLastError());
		goto end;
	}

	/* allocate the right amount of memory */
	data = (char *)VirtualAlloc(NULL, fileSz, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	printf("Allocated 0x%p (%ld bytes) for PIC\n", data, fileSz);

	/* read the file */
	if (!ReadFile(hFile, data, fileSz, &read, NULL)) {
		printf("Read %ld bytes from %s failed: %ld", fileSz, file, GetLastError());
		goto end;
	}

	/* check the result */
	if (fileSz != read) {
		printf("Read %ld bytes of %ld from %s. Incomplete!", read, fileSz, file);
		goto end;
	}

	printf("Read %ld bytes from %s. Press 'enter' to continue.\n", fileSz, file);

	/* wait! */
	getchar();

	/* schedule go() + cleanup via a timer queue (fires immediately, one-shot) */
	PIC_CLEANUP_CTX ctx = { data, fileSz };
	HANDLE hTimerQueue = CreateTimerQueue();
	HANDLE hTimer      = NULL;

	if (!CreateTimerQueueTimer(&hTimer, hTimerQueue, RunAndCleanupPIC, &ctx, 0, 0, WT_EXECUTEONLYONCE)) {
		printf("CreateTimerQueueTimer failed: %ld\n", GetLastError());
		goto end;
	}

	/* keep process alive — DLL background threads continue running */
	Sleep(INFINITE);

end:
	CloseHandle(hFile);
	return 0;
}

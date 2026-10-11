# StealthPalace: Adaptix Service Extender

**StealthPalace** is a custom service extender for the **Adaptix C2 Framework**. It provides a sophisticated interface for compiling agents with Reflective DLL (RDLL) loading capabilities, automated event hooking, and advanced evasion techniques like module stomping.

---

## 🚀 Key Features

* **Custom UI Integration:** A native Adaptix dialog for managing agent builds.
* **Multi-Format Support:** Compile agents into `Exe`, `Dll`, `Bin` (Shellcode), or `Svc` (Service) formats.
* **Automated Agent Wrapping:** Hooks into the `agent.generate` event to automatically process and wrap DLLs during the standard generation workflow.
* **Evasion Tuning:** Integrated options for **Module Stomping** (Host/Stomp DLL selection) and compiler flags (`-mconsole`, COFF skipping).
* **State Persistence:** Settings are saved server-side on the Teamserver, ensuring consistency across different operator sessions.

---

## 📂 Component Overview

### 1. `ax_config.axs` (Frontend / AxScript)
This script manages the client-side logic and user interface within the Adaptix console.
* **UI Engine:** Uses `form.create_dialog` and `gridlayout` to build a 5-section configuration window.
* **RPC Communication:** Sends commands (`run_compile`, `save_settings`) to the Go backend via `ax.service_command`.
* **Real-time Feedback:** Captures logs from the compilation process and displays them in a dedicated multi-line text output widget.

### 2. `pl_main.go` (Backend / Go Plugin)
The Go-based service that runs on the Teamserver.
* **Service Dispatcher:** Implements the `Call` method to route RPC requests from the AxScript.
* **Event Interception:** Registers a `HookPost` hook on the `agent.generate` event. 
* **The Wrapper:** When an agent is generated, the backend intercepts the raw bytes, applies the configured StealthPalace transformations (via the `Compile` logic), and modifies the final task output before it reaches the operator.

### 3. `pl_agent.go` (Build Orchestrator)
This module contains the core logic for compiling and wrapping agents.
* **COFF Compilation:** Compiles the original DLL into a COFF object file.
* **Linking:** Links the COFF object into a raw binary blob (agent.bin).
* **Shellcode Header Generation:** Converts the binary blob into a C-style shellcode header.
* **Final Wrapping:** Combines the shellcode header with the appropriate loader template (Exe, Dll, Svc) and applies evasion techniques like module stomping if configured.
* **Output Management:** Saves the final compiled agent to the specified output directory and returns logs/status updates to the frontend.
* **Error Handling:** Implements robust error handling at each stage of the build process, ensuring that any issues are logged and communicated back to the operator for troubleshooting.


---

## 🧑‍💻 Adaptix Teamserver code changes:

### `ts_agent_builder.go`
```diff
-	// --- POST HOOK ---
-	postEvent = &eventing.EventDataAgentGenerate{
-		AgentName:     builder.Name,
-		ListenersName: builder.ListenersName,
-		Config:        builder.Config,
-		FileName:      fileName,
-		FileContent:   fileContent,
-	}
-	ts.EventManager.EmitAsync(eventing.EventAgentGenerate, postEvent)
-	// -----------------

-_ = ts.TsAgentBuildSendFile(builder.Id, fileName, fileContent)
```

```diff
+	// --- POST HOOK ---
+	postEvent = &eventing.EventDataAgentGenerate{
+		AgentName:     builder.Name,
+		ListenersName: builder.ListenersName,
+		Config:        builder.Config,
+		FileName:      fileName,
+		FileContent:   fileContent,
+		BuilderId:     builder.Id,
+	}
+	// ts.EventManager.EmitAsync(eventing.EventAgentGenerate, postEvent)
+	if !ts.EventManager.Emit(eventing.EventAgentGenerate, eventing.HookPost, postEvent) {
+		if postEvent.Error != nil {
+			_ = ts.TsAgentBuildLog(builder.Id, adaptix.BUILD_LOG_ERROR, "Error: "+postEvent.Error.Error())
+		} else {
+			_ = ts.TsAgentBuildLog(builder.Id, adaptix.BUILD_LOG_ERROR, "Error: operation cancelled by hook")
+		}
+		goto RET
+	}
+    // -----------------
+_ = ts.TsAgentBuildSendFile(builder.Id, postEvent.FileName, postEvent.FileContent)
```

### Building the teamserver with the new code changes:
```bash
cd AdaptixServer
GOEXPERIMENT=jsonv2,greenteagc go build -buildvcs=false -ldflags="-s -w" -o adaptixserver
cp adaptixserver /path/to/your/teamserver/
```
---

## 🛠 Installation & Setup

Follow these steps to build and integrate the StealthPalace extender:

1. **Clone the Repository:**
```bash
git clone https://github.com/MaorSabag/Adaptix-StealthPalace.git
cd Adaptix-StealthPalace 
```
2. **Configure Root Path:** Open `pl_agent.go` and set the `root` variable to reflect the full absolute path of your local repository.
3. **Build the Go Service:**
```bash
cd src_service
make
```
Ensure that the resulting dist/ folder contains the following files:
- `stealthpalace.so` (the compiled service plugin)
- `config.yaml` (the configuration file with default settings)
- `ax_config.axs` (the Adaptix UI script)

4. **Register with Adaptix:**
Add the path to the StealthPalace configuration file into your profile.yaml under the extenders section.
```yaml
  extenders:
    - "Adaptix-StealthPalace/src_service/dist/config.yaml"
```
5. **Mark Crystal Palace's link file as executable:**
```bash
chmod +x /path/to/Adaptix-StealthPalace/crystal_palace/link
```
---

## 🖥 Usage

### Manual Build
1.  Open the **AxScript** menu and select **StealthPalace - Compile Agent**.
2.  Select your base **Agent DLL**.
3.  Set your **Output Format** and **Name**.
4.  (Optional) Enable **Stomp Options** and provide the target **Host DLL**.
5.  Click **▶ Compile**. The output log will show the compilation progress.

### Automated Workflow
Once settings are saved via the "Save Settings" button, StealthPalace works in the background. Any time you generate an agent using the standard Adaptix listeners/agent generation UI, StealthPalace will automatically wrap that output based on your last saved configuration.

---

## ⚙️ Configuration Flags

| Flag | Function |
| :--- | :--- |
| **Debug** | Compiles with `-mconsole` for visible debugging output. |
| **Skip COFF** | Reuses existing object files to speed up the build process. |
| **Skip Link** | Reuses the existing `agent.bin` if only formatting changes are needed. |
| **Module Stomping** | Overwrites the exported functions of a legitimate DLL in memory to hide the agent's presence. |

---

## 📝 Technical Implementation Details

### Data Flow
1.  **UI (`.axs`)** ➔ Encapsulates build parameters into a JSON object.
2.  **Teamserver RPC** ➔ Routes JSON to `PluginService.Call`.
3.  **Go Backend (`.go`)** ➔ Decodes parameters and executes the `Compile` function.
4.  **Logging** ➔ Backend sends `compile_log` actions back to the client to update the UI text area.
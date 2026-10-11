package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	adaptix "github.com/Adaptix-Framework/axc2"
)

// ─── Consts ──────────────────────────────────────────────────────────────────

const (
    HookPre  = 0
    HookPost = 1

	BUILD_LOG_NONE    = 0
	BUILD_LOG_INFO    = 1
	BUILD_LOG_ERROR   = 2
	BUILD_LOG_SUCCESS = 3
)

// ─── Interfaces ───────────────────────────────────────────────────────────────

type Teamserver interface {
	TsEventHookRegister(eventType string, name string, phase int, priority int, handler func(event any) error) string
	TsServiceSendDataAll(service string, data string)
	TsServiceSendDataClient(operator string, service string, data string)
	TsExtenderDataSave(extenderName string, key string, value []byte) error
	TsExtenderDataLoad(extenderName string, key string) ([]byte, error)
	
	// imported from ts_agent_builder.go
	TsAgentBuildLog(builderId string, status int, message string) error

}

// ─── Globals ──────────────────────────────────────────────────────────────────

var (
	Ts        	Teamserver
	ModuleDir 	string
	Settings   	= defaultSaveSettings()
)

// ─── Service Type ─────────────────────────────────────────────────────────────

type PluginService struct{}

// ─── Struct ───────────────────────────────────────────────────────────────────

type DllPayload struct {
	DLLContent string `json:"dll_content"`
}

type EventType string
type HookPhase int

type BaseEvent struct {
    Type      EventType   // Event type
    Phase     HookPhase   // Phase (Pre/Post)
    Cancelled bool        // Cancellation flag
    Error     error       // Error (if any)
}

type EventDataAgentGenerate struct {
    BaseEvent
    AgentName     string   // Agent type name
    ListenersName []string // List of listeners
    Config        string   // Configuration (JSON)
    FileName      string   // File name
    FileContent   []byte   // File content
	BuilderId     string   // Builder ID for logging
}

// ─── Request Shapes ───────────────────────────────────────────────────────────

type Params struct {
	DLL               string `json:"dll"`
	Format            string `json:"format"`
	Out               string `json:"out"`
	Pic               string `json:"pic"`
	WrapDLL           bool   `json:"wrap_dll"`
	Debug             bool   `json:"debug"`
	SkipCoff          bool   `json:"skip_coff"`
	SkipLink          bool   `json:"skip_link"`
	StompDLL          string `json:"stomp_dll"`
	HostDLL           string `json:"host_dll"`
	StompDllTechnique string `json:"stomp_dll_technique"`
	SleepObf          bool   `json:"sleep_obf"`
	SleepObfTechnique string `json:"sleep_obf_technique"`
	Xor               bool   `json:"xor"`
	XorKey            string `json:"xor_key"`
}

type SaveSettings struct {
	Format            string `json:"format"`
	Out               string `json:"out"`
	Pic               string `json:"pic"`
	WrapDLL           bool   `json:"wrap_dll"`
	Debug             bool   `json:"debug"`
	SkipCoff          bool   `json:"skip_coff"`
	SkipLink          bool   `json:"skip_link"`
	StompDLL          string `json:"stomp_dll"`
	HostDLL           string `json:"host_dll"`
	StompDllTechnique string `json:"stomp_dll_technique"`
	SleepObf          bool   `json:"sleep_obf"`
	SleepObfTechnique string `json:"sleep_obf_technique"`
	Xor               bool   `json:"xor"`
	XorKey            string `json:"xor_key"`
}


// ─── Response Shapes ──────────────────────────────────────────────────────────

type Result struct {
	Action  string `json:"action"`
	Success bool   `json:"success"`
	Output  string `json:"output,omitempty"`
	Error   string `json:"error,omitempty"`
}


// ─── JSON Transport Helpers ──────────────────────────────────────────────────

func sendJSON(operator string, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		fmt.Printf("[stealthpalace] JSON marshal failure: %v\n", err)
		return
	}
	Ts.TsServiceSendDataClient(operator, "stealthpalace", string(data))
}

func sendError(operator, action, msg string) {
	sendJSON(operator, Result{
		Action:  action,
		Success: false,
		Error:   msg,
	})
}

func sendSuccess(operator, action, msg string) {
	sendJSON(operator, Result{
		Action:  action,
		Success: true,
		Output:  msg,
	})
}


// ─── InitPlugin ───────────────────────────────────────────────────────────────

func InitPlugin(ts any, moduleDir string, serviceConfig string) adaptix.PluginService {
	Ts = ts.(Teamserver)
	ModuleDir = moduleDir

	fmt.Println("[stealthpalace] InitPlugin → service registered and ready")
	loadSettings, err := Ts.TsExtenderDataLoad("stealthpalace", "settings")
	if err == nil {
		s := defaultSaveSettings()
		if err := json.Unmarshal(loadSettings, &s); err == nil {
			Settings = s
			fmt.Printf("[stealthpalace] Loaded saved settings: %+v\n", Settings)
		} else {
			fmt.Printf("[stealthpalace] Failed to parse saved settings: %v\n", err)
		}
	} else {
		fmt.Printf("[stealthpalace] No saved settings found, using defaults\n")
	}

	hookId := Ts.TsEventHookRegister("agent.generate", "stealth_palace_wrapper", HookPost, 50, stealthPalaceWrapper)
	fmt.Printf("[stealthpalace] Registered event hook: %s\n", hookId)

	return &PluginService{}
}


// ─── Dispatcher Entry ─────────────────────────────────────────────────────────

func (p *PluginService) Call(operator string, function string, args string) {

	fmt.Printf("[stealthpalace] RPC: operator=%q function=%q\n", operator, function)

	switch strings.ToLower(function) {

	case "run_compile":
		handleCompile(operator, args)

	case "save_settings":
		handleSaveSettings(operator, args)

	case "load_settings":
		handleLoadSettings(operator)

	default:
		sendError(operator, "error", fmt.Sprintf("unknown function: %s", function))
	}
}


// ─── Handlers ─────────────────────────────────────────────────────────────────


// ── Compile Handler ───────────────────────────────────────────────────────────

func handleCompile(operator string, args string) {

	var p Params
	if err := json.Unmarshal([]byte(args), &p); err != nil {
		sendError(operator, "compile_log", fmt.Sprintf("invalid args: %v", err))
		return
	}

	// ─── Validation ──────────────────────────────

	if len(p.DLL) == 0 {
		sendError(operator, "compile_log", "dll parameter is required")
		return
	}

	if p.Format == "" {
		p.Format = "exe"
	}
	if p.Out == "" {
		p.Out = "agent"
	}
	if p.Pic == "" {
		p.Pic = "agent.bin"
	}

	p.Format = strings.ToLower(p.Format)

	if !isValidFormat(p.Format) {
		sendError(operator, "compile_log", "invalid format (use exe|dll|svc|bin)")
		return
	}

	fmt.Printf("[stealthpalace] compile → format=%s out=%s debug=%v skip_coff=%v skip_link=%v host_dll=%s stomp_dll=%s stomp_technique=%s\n", p.Format, p.Out, p.Debug, p.SkipCoff, p.SkipLink, p.HostDLL, p.StompDLL, p.StompDllTechnique)

	fmt.Printf("[stealthpalace] DLL payload length: %d bytes\n", len(p.DLL))

	// ─── Execute Build ───────────────────────────

	defer func() {
		if r := recover(); r != nil {
			sendError(operator, "compile_log", fmt.Sprintf("panic: %v", r))
		}
	}()

	Compile(operator, "", p)
}

func handleSaveSettings(operator string, args string) {
	s := defaultSaveSettings()
	if err := json.Unmarshal([]byte(args), &s); err != nil {
		sendError(operator, "save_settings_log", fmt.Sprintf("invalid args: %v", err))
		return
	}
	Settings = s
	saveData, err := json.Marshal(Settings)
	if err != nil {
		sendError(operator, "save_settings_log", fmt.Sprintf("failed to serialize settings: %v", err))
		return
	}
	if err := Ts.TsExtenderDataSave("stealthpalace", "settings", saveData); err != nil {
		sendError(operator, "save_settings_log", fmt.Sprintf("failed to save settings: %v", err))
		return
	}
	sendSuccess(operator, "save_settings_log", "settings saved successfully")
}

func handleLoadSettings(operator string) {
	loadSettings, err := Ts.TsExtenderDataLoad("stealthpalace", "settings")
	if err != nil {
		sendError(operator, "load_settings_log", fmt.Sprintf("failed to load settings: %v", err))
		return
	}
	var s SaveSettings
	if err := json.Unmarshal(loadSettings, &s); err != nil {
		sendError(operator, "load_settings_log", fmt.Sprintf("failed to parse settings: %v", err))
		return
	}

	sendSuccess(operator, "load_settings_result", string(loadSettings))
}

// ─── Hooks ──────────────────────────────────────────────────────────────────

func stealthPalaceWrapper(event any) error {

	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[stealthpalace] Hook panic recovered: %v\n", r)
		}
	}()

	v := reflect.ValueOf(event)
	if v.Kind() != reflect.Ptr || v.IsNil() {
		return errors.New("event is not a valid pointer")
	}
	
	s := v.Elem()

	fContentField := s.FieldByName("FileContent")
	if !fContentField.IsValid() {
		return errors.New("field 'FileContent' not found in event")
	}
	fNameField := s.FieldByName("FileName")
	if !fNameField.IsValid() {
		return errors.New("field 'FileName' not found in event")
	}
	
	if !strings.HasSuffix(fNameField.String(), ".dll") {
		return nil
	}

	if !Settings.WrapDLL {
		fmt.Printf("[stealthpalace] DLL wrapping disabled; skipping %s\n", fNameField.String())
		return nil
	}

	builderIdField := s.FieldByName("BuilderId")
	if !builderIdField.IsValid() {
		return errors.New("field 'BuilderId' not found in event")
	}
	if builderIdField.Kind() != reflect.String {
		return errors.New("field 'BuilderId' is not a string")
	}
	builderId := builderIdField.String()
	if builderId == "" {
		return errors.New("field 'BuilderId' is empty")
	}

	originalBytes := fContentField.Bytes()
	b64Content := base64.StdEncoding.EncodeToString(originalBytes)

	Ts.TsAgentBuildLog(builderId, BUILD_LOG_INFO, fmt.Sprintf("Stealthpalace Wrapping %s (%d bytes)", fNameField.String(), len(originalBytes)))

	var p Params
	dllContent := map[string]string{
		"dll_content": b64Content,
	}
	
	dllContentBytes, _ := json.Marshal(dllContent)
	if err := json.Unmarshal(dllContentBytes, &p); err != nil {
		return fmt.Errorf("invalid DLL content mapping: %v", err)
	}

	p.DLL = string(dllContentBytes)
	p.Format            = strings.ToLower(Settings.Format)
	p.Out               = Settings.Out
	p.Pic               = Settings.Pic
	p.Debug             = Settings.Debug
	p.SkipCoff          = Settings.SkipCoff
	p.SkipLink          = Settings.SkipLink
	p.HostDLL           = Settings.HostDLL
	p.StompDLL          = Settings.StompDLL
	p.StompDllTechnique = Settings.StompDllTechnique
	p.SleepObf          = Settings.SleepObf
	p.SleepObfTechnique = Settings.SleepObfTechnique
	p.Xor               = Settings.Xor
	p.XorKey            = Settings.XorKey

	fmt.Printf("StompDllTechnique: %v\n", p.StompDllTechnique)

	newFileContent := Compile("", builderId, p)

	if newFileContent != nil {
		if fContentField.CanSet() {
			fContentField.SetBytes(newFileContent)
			fmt.Printf("[stealthpalace] Successfully modified FileContent (%d bytes)\n", len(newFileContent))
			Ts.TsAgentBuildLog(builderId, BUILD_LOG_INFO, "FileContent modified successfully")
		}

		if fNameField.IsValid() && fNameField.CanSet() {
			newName := fmt.Sprintf("%s.%s", p.Out, p.Format)
			fNameField.SetString(newName)
			fmt.Printf("[stealthpalace] Renamed agent to: %s\n", newName)
			Ts.TsAgentBuildLog(builderId, BUILD_LOG_SUCCESS, fmt.Sprintf("Agent built successfully: %s", newName))
		}
	}

	return nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func isValidFormat(f string) bool {
	switch f {
	case "exe", "dll", "svc", "bin":
		return true
	default:
		return false
	}
}

func defaultSaveSettings() SaveSettings {
	return SaveSettings{
		Format:            "exe",
		Out:               "agent",
		Pic:               "agent.bin",
		WrapDLL:           true,
		SleepObf:          false,
		SleepObfTechnique: "ekko",
		StompDllTechnique: "loadlibraryex",
		Xor:               false,
		XorKey:            "",
	}
}
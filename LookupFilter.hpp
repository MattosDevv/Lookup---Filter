#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <winternl.h>
#include <vector>
#include <string>
#include <iostream>
#include <iomanip>
#include <sstream>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "ntdll.lib")

//  ======================== Cores ANSI ========================
#define COL_RESET   "\033[0m"
#define COL_RED     "\033[91m"
#define COL_YELLOW  "\033[93m"
#define COL_GREEN   "\033[92m"
#define COL_CYAN    "\033[96m"
#define COL_GRAY    "\033[90m"
#define COL_WHITE   "\033[97m"
#define COL_MAGENTA "\033[95m"

// ======================== NtQueryInformationThread typedef ========================
typedef NTSTATUS(NTAPI* pNtQueryInformationThread)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
    );

// ======================== ThreadBasicInformation ========================
#define ThreadQuerySetWin32StartAddress 9

// Estruturas de resultado 
struct HookResult {
    std::string funcName;
    std::string hookType; // "inline", "EAT", "IAT"
};

struct ThreadResult {
    ULONG_PTR startAddress;
};

struct ProcessResult {
    DWORD   pid;
    std::string name;
    std::vector<HookResult>   hooks;
    std::vector<ThreadResult> strangeThreads;
};

// Funções principais 
class ProcessScanner {
public:
    ProcessScanner();
    ~ProcessScanner() = default;

    void Run();

private:
    pNtQueryInformationThread NtQueryInformationThread_ = nullptr;

    // Lista de funções da ntdll a analisar
    static constexpr const char* kFunctions[] = {
        "NtCreateFile",
        "NtOpenFile",
        "NtReadFile",
        "NtWriteFile",
        "NtOpenProcess",
        "NtTerminateProcess",
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx"
    };

    // Obtém endereço local de uma função exportada pela ntdll
    ULONG_PTR GetLocalFuncAddress(const char* funcName);

    // Verifica inline hook (primeiros bytes)
    bool CheckInlineHook(HANDLE hProcess, ULONG_PTR remoteAddr, std::string& outType);

    // Verifica EAT hook no módulo remoto vs local
    bool CheckEATHook(HANDLE hProcess, HMODULE hRemoteNtdll, const char* funcName);

    // Verifica IAT hook
    bool CheckIATHook(HANDLE hProcess, HMODULE hRemoteModule, const char* funcName, ULONG_PTR& outRemoteAddr);

    // Obtém o endereço base de ntdll.dll no processo remoto
    HMODULE GetRemoteNtdll(HANDLE hProcess);

    // Verifica se um endereço pertence a algum módulo carregado no processo
    bool AddressInAnyModule(HANDLE hProcess, ULONG_PTR addr);

    // Analisa threads do processo
    std::vector<ThreadResult> ScanThreads(DWORD pid, HANDLE hProcess);

    // Analisa hooks no processo
    std::vector<HookResult> ScanHooks(HANDLE hProcess, DWORD pid);

    // Scan completo de um processo
    ProcessResult ScanProcess(DWORD pid, const std::string& name);

    // Imprime resultado
    void PrintResult(const ProcessResult& res);

    // Helpers
    std::string HexAddr(ULONG_PTR addr);
};
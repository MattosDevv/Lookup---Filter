#include "LookupFilter.hpp"


// ====================== Constructor ======================

ProcessScanner::ProcessScanner() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        NtQueryInformationThread_ = reinterpret_cast<pNtQueryInformationThread>(
            GetProcAddress(hNtdll, "NtQueryInformationThread")
            );
    }
}


// Helpers

std::string ProcessScanner::HexAddr(ULONG_PTR addr) {
    std::ostringstream oss;
    oss << "0x" << std::uppercase << std::hex << std::setw(16) << std::setfill('0') << addr;
    return oss.str();
}

ULONG_PTR ProcessScanner::GetLocalFuncAddress(const char* funcName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 0;
    return reinterpret_cast<ULONG_PTR>(GetProcAddress(hNtdll, funcName));
}


// Obtém HMODULE de ntdll.dll no processo remoto

HMODULE ProcessScanner::GetRemoteNtdll(HANDLE hProcess) {
    HMODULE modules[512] = {};
    DWORD needed = 0;

    if (!EnumProcessModules(hProcess, modules, sizeof(modules), &needed))
        return nullptr;

    DWORD count = needed / sizeof(HMODULE);
    char modName[MAX_PATH] = {};

    for (DWORD i = 0; i < count; i++) {
        if (GetModuleBaseNameA(hProcess, modules[i], modName, MAX_PATH)) {
            if (_stricmp(modName, "ntdll.dll") == 0)
                return modules[i];
        }
    }
    return nullptr;
}


// Inline Hook – verifica os primeiros bytes da função no processo remoto

bool ProcessScanner::CheckInlineHook(HANDLE hProcess, ULONG_PTR remoteAddr, std::string& outType) {
    if (!remoteAddr) return false;

    BYTE buf[16] = {};
    SIZE_T read = 0;
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(remoteAddr), buf, sizeof(buf), &read) || read < 6)
        return false;

    // JMP rel32  — E9 xx xx xx xx
    if (buf[0] == 0xE9) { outType = "inline/jmp-rel32";   return true; }

    // JMP [rip+0] — FF 25 00 00 00 00
    if (buf[0] == 0xFF && buf[1] == 0x25) { outType = "inline/jmp-rip";    return true; }

    // CALL rel32 — E8
    if (buf[0] == 0xE8) { outType = "inline/call";         return true; }

    // MOV RAX, imm64 + JMP RAX — 48 B8 ... FF E0
    // (hot-patch style trampoline)
    if (buf[0] == 0x48 && buf[1] == 0xB8) {
        // verifica se há JMP RAX (FF E0) nos próximos bytes
        for (int i = 2; i <= 10; i++) {
            if (buf[i] == 0xFF && buf[i + 1] == 0xE0) {
                outType = "inline/mov-rax-jmp";
                return true;
            }
        }
    }

    // PUSH imm32 + RET — 68 xx xx xx xx C3
    if (buf[0] == 0x68 && buf[5] == 0xC3) { outType = "inline/push-ret";   return true; }

    // INT3 sled (breakpoint hook)
    if (buf[0] == 0xCC) { outType = "inline/int3";         return true; }

    return false;
}


// EAT Hook – compara endereço exportado no módulo remoto vs local

bool ProcessScanner::CheckEATHook(HANDLE hProcess, HMODULE hRemoteNtdll, const char* funcName) {
    if (!hRemoteNtdll) return false;

    ULONG_PTR remoteBase = reinterpret_cast<ULONG_PTR>(hRemoteNtdll);
    SIZE_T rd = 0;

    // Le o header PE do modulo remoto
    IMAGE_DOS_HEADER dosHdr = {};
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(remoteBase), &dosHdr, sizeof(dosHdr), &rd))
        return false;

    IMAGE_NT_HEADERS64 ntHdr = {};
    if (!ReadProcessMemory(hProcess,
        reinterpret_cast<LPCVOID>(remoteBase + dosHdr.e_lfanew),
        &ntHdr, sizeof(ntHdr), &rd))
        return false;

    // Tamanho total do modulo remoto - usado para checar se funcRVA esta dentro
    DWORD moduleSize = ntHdr.OptionalHeader.SizeOfImage;

    DWORD exportRVA = ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exportSize = ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!exportRVA) return false;

    IMAGE_EXPORT_DIRECTORY exportDir = {};
    if (!ReadProcessMemory(hProcess,
        reinterpret_cast<LPCVOID>(remoteBase + exportRVA),
        &exportDir, sizeof(exportDir), &rd))
        return false;

    for (DWORD i = 0; i < exportDir.NumberOfNames; i++) {
        DWORD nameRVA = 0;
        ReadProcessMemory(hProcess,
            reinterpret_cast<LPCVOID>(remoteBase + exportDir.AddressOfNames + i * 4),
            &nameRVA, sizeof(nameRVA), &rd);

        char exportedName[128] = {};
        ReadProcessMemory(hProcess,
            reinterpret_cast<LPCVOID>(remoteBase + nameRVA),
            exportedName, sizeof(exportedName) - 1, &rd);

        if (_stricmp(exportedName, funcName) != 0) continue;

        WORD ordinal = 0;
        ReadProcessMemory(hProcess,
            reinterpret_cast<LPCVOID>(remoteBase + exportDir.AddressOfNameOrdinals + i * 2),
            &ordinal, sizeof(ordinal), &rd);

        DWORD funcRVA = 0;
        ReadProcessMemory(hProcess,
            reinterpret_cast<LPCVOID>(remoteBase + exportDir.AddressOfFunctions + ordinal * 4),
            &funcRVA, sizeof(funcRVA), &rd);

        if (!funcRVA) return false;

        // EAT hook real: o RVA exportado aponta para FORA do modulo.
        // Forwarder (ex: "ntdll.NtCreateFile") e considerado normal -
        // fica dentro do range da export directory e nao conta como hook.
        bool isForwarder = (funcRVA >= exportRVA && funcRVA < exportRVA + exportSize);
        bool isOutsideModule = (funcRVA >= moduleSize);

        if (!isForwarder && isOutsideModule)
            return true;

        break;
    }
    return false;
}


// IAT Hook – percorre a IAT do primeiro módulo do processo e compara

bool ProcessScanner::CheckIATHook(HANDLE hProcess, HMODULE hRemoteModule, const char* funcName, ULONG_PTR& outRemoteAddr) {
    if (!hRemoteModule) return false;

    ULONG_PTR remoteBase = reinterpret_cast<ULONG_PTR>(hRemoteModule);
    SIZE_T rd = 0;

    IMAGE_DOS_HEADER dosHdr = {};
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(remoteBase), &dosHdr, sizeof(dosHdr), &rd)) return false;

    IMAGE_NT_HEADERS64 ntHdr = {};
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(remoteBase + dosHdr.e_lfanew), &ntHdr, sizeof(ntHdr), &rd)) return false;

    DWORD importRVA = ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!importRVA) return false;

    IMAGE_IMPORT_DESCRIPTOR importDesc = {};
    ULONG_PTR importAddr = remoteBase + importRVA;

    while (true) {
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(importAddr), &importDesc, sizeof(importDesc), &rd)) break;
        if (!importDesc.Name) break;

        char dllName[128] = {};
        ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(remoteBase + importDesc.Name), dllName, sizeof(dllName) - 1, &rd);

        if (_stricmp(dllName, "ntdll.dll") == 0) {
            ULONG_PTR iltAddr = remoteBase + (importDesc.OriginalFirstThunk ? importDesc.OriginalFirstThunk : importDesc.FirstThunk);
            ULONG_PTR iatAddr = remoteBase + importDesc.FirstThunk;

            for (DWORD i = 0; ; i++) {
                IMAGE_THUNK_DATA64 iltThunk = {}, iatThunk = {};
                ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(iltAddr + i * 8), &iltThunk, 8, &rd);
                ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(iatAddr + i * 8), &iatThunk, 8, &rd);

                if (!iltThunk.u1.AddressOfData) break;

                // Verifica se é import por nome (não por ordinal)
                if (!(iltThunk.u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
                    IMAGE_IMPORT_BY_NAME ibn = {};
                    ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(remoteBase + iltThunk.u1.AddressOfData), &ibn, sizeof(ibn), &rd);
                    char importName[128] = {};
                    ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(remoteBase + iltThunk.u1.AddressOfData + 2), importName, sizeof(importName) - 1, &rd);

                    if (_stricmp(importName, funcName) == 0) {
                        ULONG_PTR expectedAddr = GetLocalFuncAddress(funcName);
                        ULONG_PTR actualAddr = static_cast<ULONG_PTR>(iatThunk.u1.Function);

                        if (expectedAddr && actualAddr != expectedAddr) {
                            outRemoteAddr = actualAddr;
                            return true;
                        }
                    }
                }
            }
        }
        importAddr += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
    return false;
}


// Verifica se um endereço pertence a algum módulo carregado

bool ProcessScanner::AddressInAnyModule(HANDLE hProcess, ULONG_PTR addr) {
    HMODULE modules[1024] = {};
    DWORD needed = 0;
    if (!EnumProcessModules(hProcess, modules, sizeof(modules), &needed)) return false;

    DWORD count = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < count; i++) {
        MODULEINFO mi = {};
        if (GetModuleInformation(hProcess, modules[i], &mi, sizeof(mi))) {
            ULONG_PTR base = reinterpret_cast<ULONG_PTR>(mi.lpBaseOfDll);
            if (addr >= base && addr < base + mi.SizeOfImage)
                return true;
        }
    }
    return false;
}


// Scan de Threads

std::vector<ThreadResult> ProcessScanner::ScanThreads(DWORD pid, HANDLE hProcess) {
    std::vector<ThreadResult> results;
    if (!NtQueryInformationThread_) return results;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return results;

    THREADENTRY32 te = { sizeof(THREADENTRY32) };
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;

            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (!hThread) continue;

            ULONG_PTR startAddr = 0;
            NTSTATUS status = NtQueryInformationThread_(
                hThread,
                static_cast<THREADINFOCLASS>(ThreadQuerySetWin32StartAddress),
                &startAddr,
                sizeof(startAddr),
                nullptr
            );

            CloseHandle(hThread);

            if (NT_SUCCESS(status) && startAddr && !AddressInAnyModule(hProcess, startAddr)) {
                results.push_back({ startAddr });
            }
        } while (Thread32Next(hSnap, &te));
    }

    CloseHandle(hSnap);
    return results;
}


// Scan de Hooks

std::vector<HookResult> ProcessScanner::ScanHooks(HANDLE hProcess, DWORD pid) {
    std::vector<HookResult> results;

    HMODULE hRemoteNtdll = GetRemoteNtdll(hProcess);

    // Obtém o primeiro módulo (EXE principal) para IAT scan
    HMODULE firstModule = nullptr;
    {
        DWORD needed = 0;
        EnumProcessModules(hProcess, &firstModule, sizeof(firstModule), &needed);
    }

    for (const char* funcName : kFunctions) {
        // Endereço local da função
        ULONG_PTR localAddr = GetLocalFuncAddress(funcName);
        if (!localAddr) continue;

        // Calcula endereço remoto com base no offset da ntdll local
        HMODULE hLocalNtdll = GetModuleHandleA("ntdll.dll");
        ULONG_PTR localBase = reinterpret_cast<ULONG_PTR>(hLocalNtdll);
        ULONG_PTR offset = localAddr - localBase;
        ULONG_PTR remoteAddr = reinterpret_cast<ULONG_PTR>(hRemoteNtdll) + offset;

        //  Inline Hook
        std::string hookType;
        if (CheckInlineHook(hProcess, remoteAddr, hookType)) {
            results.push_back({ funcName, hookType });
            continue; // já detectado, não precisa verificar outros tipos
        }

        //  EAT Hook
        if (CheckEATHook(hProcess, hRemoteNtdll, funcName)) {
            results.push_back({ funcName, "EAT" });
            continue;
        }

        // IAT Hook
        ULONG_PTR iatRemote = 0;
        if (firstModule && CheckIATHook(hProcess, firstModule, funcName, iatRemote)) {
            results.push_back({ funcName, "IAT" });
        }
    }

    return results;
}


// Scan completo de um processo

ProcessResult ProcessScanner::ScanProcess(DWORD pid, const std::string& name) {
    ProcessResult result;
    result.pid = pid;
    result.name = name;

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        pid
    );

    if (!hProcess) return result;

    result.hooks = ScanHooks(hProcess, pid);
    result.strangeThreads = ScanThreads(pid, hProcess);

    CloseHandle(hProcess);
    return result;
}


// Impressão de resultados

void ProcessScanner::PrintResult(const ProcessResult& res) {
    bool suspicious = !res.hooks.empty() || !res.strangeThreads.empty();
    if (!suspicious) return;

    std::cout
        << COL_RED << "[!] " << COL_WHITE << "Processo: "
        << COL_YELLOW << res.name
        << COL_GRAY << " [PID: " << res.pid << "]"
        << COL_RESET << "\n";

    if (!res.hooks.empty()) {
        std::cout << COL_CYAN << "    [>] " << COL_WHITE << "função hookada\n" << COL_RESET;
        for (const auto& h : res.hooks) {
            std::cout
                << COL_GRAY << "         - " << COL_MAGENTA << h.funcName
                << COL_GRAY << " (" << COL_RED << h.hookType << COL_GRAY << ")"
                << COL_RESET << "\n";
        }
    }

    if (!res.strangeThreads.empty()) {
        std::cout << COL_GREEN << "    [+] " << COL_WHITE << "thread estranha\n" << COL_RESET;
        for (const auto& t : res.strangeThreads) {
            std::cout
                << COL_GRAY << "         - "
                << COL_YELLOW << HexAddr(t.startAddress)
                << COL_RESET << "\n";
        }
    }

    std::cout << "\n";
}


// Ponto de entrada do scan

void ProcessScanner::Run() {
    // Habilita ANSI no terminal Windows
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hOut, &mode);
    SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    // Banner
    std::cout
        << COL_CYAN
        << " ___                              ____\n"
        << "|  _ \\ _ __ ___   ___ ___  ___ / ___|  ___ __ _ _ __  _ __   ___ _ __\n"
        << "| |_) | '__/ _ \\ / __/ _ \\/ __|\\___ \\ / __/ _` | '_ \\| '_ \\ / _ \\ '__|\n"
        << "|  __/| | | (_) | (_|  __/\\__ \\ ___) | (_| (_| | | | | | | |  __/ |\n"
        << "|_|   |_|  \\___/ \\___\\___||___/|____/ \\___\\__,_|_| |_|_| |_|\\___|_|\n"
        << COL_GRAY << "                    Read-Only Process Hook & Thread Scanner\n"
        << COL_RESET << "\n";

    std::cout << COL_GRAY << "[*] Iniciando enumeração de processos...\n\n" << COL_RESET;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        std::cerr << COL_RED << "[-] Falha ao criar snapshot de processos.\n" << COL_RESET;
        return;
    }

    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
    int scanned = 0;
    int flagged = 0;

    if (Process32FirstW(hSnap, &pe)) {
        do {
            // Converte nome wide → narrow
            char nameBuf[MAX_PATH] = {};
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, nameBuf, MAX_PATH, nullptr, nullptr);
            std::string procName(nameBuf);

            // Pula o processo do próprio scanner
            if (pe.th32ProcessID == GetCurrentProcessId()) continue;

            ProcessResult res = ScanProcess(pe.th32ProcessID, procName);
            scanned++;

            bool suspicious = !res.hooks.empty() || !res.strangeThreads.empty();
            if (suspicious) {
                PrintResult(res);
                flagged++;
            }

        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);

    // Sumário
    std::cout
        << COL_GRAY << "-----------------------------------------\n"
        << COL_WHITE << " Processos escaneados : " << COL_CYAN << scanned << "\n"
        << COL_WHITE << " Processos suspeitos  : " << (flagged > 0 ? COL_RED : COL_GREEN) << flagged << "\n"
        << COL_RESET << "\n";
}
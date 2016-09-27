
#define _CRT_SECURE_NO_WARNINGS

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <exception>
#include <stdexcept>
#include <string>
#include <sstream>

#define _WIN32_LEAN_AND_MEAN

#define WINVER 0x0601
#define _WIN32_WINNT 0x0601

#include <Windows.h>
#include "resource.h"

class BgTaskException : public std::exception {
private:
    const DWORD error_code;
    const std::wstring task;
public:

    explicit BgTaskException(const wchar_t* task, const DWORD error_code) :
        task(task),
        error_code(error_code)
    {}

    DWORD GetErrorCode() const {
        return error_code;
    }

    const wchar_t* GetTask() const {
        return task.c_str();
    }
};

void get_error_message(wchar_t** message, const DWORD error_code)
{
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        error_code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (wchar_t*)message,
        0, NULL);
}

void messagebox_error(const wchar_t* task, const DWORD last_error_code)
{
    wchar_t buffer[1024] = { 0 };

    wchar_t* friendly_error_msg = nullptr;
    get_error_message(&friendly_error_msg, last_error_code);
    swprintf_s(buffer, L"Unable to %s. Error code %d: %s", task, last_error_code, friendly_error_msg);

    MessageBoxW(NULL, buffer, L"Background Task", MB_OK | MB_ICONERROR);
    HeapFree(GetProcessHeap(), 0, (void*)friendly_error_msg);
    return;
}

void run_task_hide_window(const wchar_t* application,
    const int argc,
    const wchar_t** params)
{

    HCRYPTPROV crypto_provider;
    if (!CryptAcquireContext(&crypto_provider, NULL, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    {
        DWORD error_code = GetLastError();
        throw BgTaskException(L"run CryptAcquireContext", error_code);
        return;
    }

    uint32_t random_number = 0;
    if (!CryptGenRandom(crypto_provider, sizeof(random_number), (BYTE*)&random_number))
    {
        DWORD error_code = GetLastError();
        CryptReleaseContext(crypto_provider, 0);
        throw BgTaskException(L"run CryptGenRandom", error_code);
        return;
    }

    std::wstringstream cmdline;

    if (wcsstr(application, L" ") != NULL)
    {
        cmdline << L"\"" << application << L"\"";
    }
    else
    {
        cmdline << application;
    }

    if (params != nullptr)
    {

        int count = 0;
        while (count < argc)
        {
            cmdline << L" ";
            const wchar_t* param = params[count];
            if (wcsstr(param, L" ") != NULL)
            {
                cmdline << L"\"" << param << L"\"";
            }
            else
            {
                cmdline << param;
            }

            count++;
        }
    }

    size_t cmdline_len = cmdline.str().size();
    wchar_t* cmdline_buffer = (wchar_t*)calloc(cmdline_len + 1, sizeof(wchar_t));
    wchar_t *cmdline_buffer_ptr_copy = cmdline_buffer;
    wcscpy(cmdline_buffer, cmdline.str().c_str());

    wchar_t job_object_name[256] = { 0 };
    swprintf_s(job_object_name, L"bgtask-jo-%u", random_number);

    HANDLE job_object = CreateJobObjectW(NULL, job_object_name);
    if (job_object == nullptr || job_object == INVALID_HANDLE_VALUE)
    {
        DWORD error_code = GetLastError();
        free(cmdline_buffer);
        CryptReleaseContext(crypto_provider, 0);
        throw BgTaskException(L"run CreateJobObjectW", error_code);
        return;
    }

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION obj_info = {};
    obj_info.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job_object,
        JobObjectExtendedLimitInformation,
        &obj_info, sizeof(obj_info)))
    {
        DWORD error_code = GetLastError();
        free(cmdline_buffer);
        CloseHandle(job_object);
        CryptReleaseContext(crypto_provider, 0);
        throw BgTaskException(L"run SetInformationJobObject", error_code);
        return;
    }

    HANDLE io_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
    if (io_port == nullptr || io_port == INVALID_HANDLE_VALUE)
    {
        DWORD error_code = GetLastError();
        free(cmdline_buffer);
        CloseHandle(job_object);
        CryptReleaseContext(crypto_provider, 0);
        throw BgTaskException(L"run CreateIoCompletionPort", error_code);
        return;
    }

    JOBOBJECT_ASSOCIATE_COMPLETION_PORT port;
    port.CompletionKey = job_object;
    port.CompletionPort = io_port;
    if (!SetInformationJobObject(job_object,
        JobObjectAssociateCompletionPortInformation,
        &port, sizeof(port))) {
        DWORD error_code = GetLastError();
        free(cmdline_buffer);
        CloseHandle(job_object);
        CloseHandle(io_port);
        CryptReleaseContext(crypto_provider, 0);
        throw BgTaskException(L"run SetInformationJobObject", error_code);
        return;
    }

    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFO si = { 0 };
    si.wShowWindow = SW_HIDE;
    si.dwFlags = STARTF_USESHOWWINDOW;

    if (!CreateProcess(application,
        cmdline_buffer,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi))
    {
        DWORD error_code = GetLastError();
        free(cmdline_buffer);
        CloseHandle(job_object);
        CloseHandle(io_port);
        CryptReleaseContext(crypto_provider, 0);
        throw BgTaskException(L"run CreateProcessW", error_code);
        return;
    }

    if (!AssignProcessToJobObject(job_object, pi.hProcess)) {
        DWORD error_code = GetLastError();
        free(cmdline_buffer);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(job_object);
        CloseHandle(io_port);
        CryptReleaseContext(crypto_provider, 0);
        throw BgTaskException(L"run AssignProcessToJobObject", error_code);
        return;
    }

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    // https://blogs.msdn.microsoft.com/oldnewthing/20130405-00/?p=4743
    DWORD completion_code;
    ULONG_PTR completion_key;
    LPOVERLAPPED overlapped;
    while (1)
    {
        GetQueuedCompletionStatus(io_port, &completion_code, &completion_key, &overlapped, 250);

        if ((HANDLE)completion_key == job_object) {
            if (completion_code == JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO)
            {

                break;
            }
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION job_accounting;
            QueryInformationJobObject(job_object, JobObjectBasicAccountingInformation,
                &job_accounting, sizeof(job_accounting), 0);
            if (job_accounting.ActiveProcesses == 0)
            {
                break;
            }
        }
    }
   
    CloseHandle(job_object);

    CryptReleaseContext(crypto_provider, 0);
    free(cmdline_buffer_ptr_copy);

    return;
}




int WINAPI wWinMain(HINSTANCE hInstance, 
    HINSTANCE hPrevInstance, 
    PWSTR pCmdLine, 
    int nCmdShow)
{
    int argc = 0;
    wchar_t** argv = nullptr;

    argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    if (argv == nullptr)
    {
        DWORD error_code = GetLastError();
        messagebox_error(L"run CommandLineToArgvW", error_code);
        exit(-1);
    }

    if (argc <= 2 || _wcsicmp(argv[1], L"help") == 0)
    {
        MessageBoxW(NULL, L"Too few arguments to run task.\n\nSyntax is\n\n" \
            L"background-task.exe [hidecommand] task <parameters>", L"Background-Task", 
            MB_OK | MB_ICONINFORMATION);
        exit(-2);
    }

    const wchar_t* cmd = argv[1];

    const wchar_t* app = argv[2];
    const wchar_t** params = nullptr;
    int argc_params = 0;
    if (argc > 3) {
        params = const_cast<const wchar_t**>(&argv[3]);
        argc_params = argc - 3;
    }

    bool display_alternative_desktop = false;
    if (_wcsicmp(cmd, L"hidecommand") == 0) {

        DWORD background_error = 0;
        try {
            run_task_hide_window(app, argc_params, params);
        }
        catch (BgTaskException& e)
        {
            messagebox_error(e.GetTask(), e.GetErrorCode());
            exit(-4);
        }
    }
    else
    {
        wchar_t buffer[256] = { 0 };
        swprintf_s(buffer, L"Sorry, the command %s is invalid. Try \"help\" or no arguments for help.", cmd);
        MessageBoxW(NULL, buffer, L"Background Task", MB_OK | MB_ICONWARNING);
        exit(-3);
    }
    exit(0);
}
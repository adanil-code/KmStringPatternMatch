/*
* Windows Kernel String Pattern Match Engine
* Copyright 2026 Alexander Danileiko
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at:
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* This software is provided on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
* OF ANY KIND, either express or implied.
*/

// -------------------------------------------------------------------------------------
// KmStringPatternMatchDrv.cpp
// Kernel Mode Wrapper 
// -------------------------------------------------------------------------------------
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <intrin.h>

#include "KmStringPatternTest.h"

#define DRIVER_TAG 'pmSK'

#define MAX_LOG_LINE 512

PCHAR          g_pLogBuffer        = NULL;
size_t         g_cbLogBufferMax    = 1024 * 1024;
size_t         g_cbLogBufferOffset = 0;
FAST_MUTEX     g_LogMutex;

VOID 
RecordLog(_In_ _Printf_format_string_ PCSTR pszFormat, ...)
{
    va_list args;
    va_start(args, pszFormat);

    char szLine[MAX_LOG_LINE];
    NTSTATUS status = RtlStringCbVPrintfA(szLine, sizeof(szLine), pszFormat, args);
    
    if (NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "%s", szLine);

        ExAcquireFastMutex(&g_LogMutex);
        
        if (g_pLogBuffer)
        {
            size_t cbLen = 0;
            RtlStringCbLengthA(szLine, MAX_LOG_LINE, &cbLen);
            
            if (g_cbLogBufferOffset + cbLen < g_cbLogBufferMax)
            {
                RtlCopyMemory(g_pLogBuffer + g_cbLogBufferOffset, szLine, cbLen);
                g_cbLogBufferOffset += cbLen;
                g_pLogBuffer[g_cbLogBufferOffset] = '\0';
            }
        }
        
        ExReleaseFastMutex(&g_LogMutex);
    }

    va_end(args);
}

VOID FlushLogToFile()
{
    PAGED_CODE();

    if (!g_pLogBuffer || g_cbLogBufferOffset == 0)
    {
        return;
    }

    UNICODE_STRING    uniName;
    OBJECT_ATTRIBUTES objAttr;
    
    RtlInitUnicodeString(&uniName, L"\\SystemRoot\\Temp\\KmStringPatternMatchPerf.txt");
    InitializeObjectAttributes(&objAttr, &uniName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE          hFile;
    IO_STATUS_BLOCK ioStatusBlock;
    
    NTSTATUS ntStatus = ZwCreateFile(&hFile,
                                     FILE_APPEND_DATA,
                                     &objAttr,
                                     &ioStatusBlock,
                                     NULL,
                                     FILE_ATTRIBUTE_NORMAL,
                                     0,
                                     FILE_OPEN_IF,
                                     FILE_SYNCHRONOUS_IO_NONALERT,
                                     NULL,
                                     0);

    if (NT_SUCCESS(ntStatus))
    {
        ZwWriteFile(hFile, NULL, NULL, NULL, &ioStatusBlock, g_pLogBuffer, (ULONG)g_cbLogBufferOffset, NULL, NULL);
        ZwClose(hFile);
    }
}

#define LOG_INFO(...)      RecordLog(__VA_ARGS__)
#define LOG_ERR(...)       RecordLog(__VA_ARGS__)
#define COMPILER_BARRIER() _ReadWriteBarrier()

volatile LONG g_lAbortTests = 0;
PETHREAD      g_pMasterBenchmarkThread = NULL;

TEST_SUITE_CONFIG g_TestConfig = { TRUE, TRUE };

VOID DriverUnload(_In_ PDRIVER_OBJECT pDriverObject)
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(pDriverObject);

    InterlockedExchange(&g_lAbortTests, 1);

    if (g_pMasterBenchmarkThread != NULL)
    {
        KeWaitForSingleObject(g_pMasterBenchmarkThread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(g_pMasterBenchmarkThread);
        g_pMasterBenchmarkThread = NULL;
    }

    if (g_pLogBuffer)
    {
        ExFreePoolWithTag(g_pLogBuffer, DRIVER_TAG);
        g_pLogBuffer = NULL;
    }

    LOG_INFO("[SPM_TEST] *** Driver Unloaded Safely.\n");
}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT pDriverObject, _In_ PUNICODE_STRING pRegistryPath);
#pragma alloc_text(INIT, DriverEntry)

extern "C" NTSTATUS 
DriverEntry(_In_ PDRIVER_OBJECT  pDriverObject, 
            _In_ PUNICODE_STRING pRegistryPath)
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(pRegistryPath);

    ExInitializeFastMutex(&g_LogMutex);

    g_pLogBuffer = (PCHAR)ExAllocatePool2(POOL_FLAG_PAGED, g_cbLogBufferMax, DRIVER_TAG);
    if (g_pLogBuffer)
    {
        g_pLogBuffer[0]     = '\0';
        g_cbLogBufferOffset = 0;
    }

    pDriverObject->DriverUnload = DriverUnload;

    HANDLE   hThread;
    NTSTATUS ntStatus = PsCreateSystemThread(&hThread, 
                                             THREAD_ALL_ACCESS, 
                                             NULL, 
                                             NULL, 
                                             NULL, 
                                             (PKSTART_ROUTINE)RunTests, 
                                             &g_TestConfig);

    if (NT_SUCCESS(ntStatus))
    {
        ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, NULL, KernelMode, (PVOID*)&g_pMasterBenchmarkThread, NULL);
        ZwClose(hThread);
    }

    return STATUS_SUCCESS;
}
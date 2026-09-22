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
// KmStringPatternMatchUm.cpp
// User Mode Wrapper Application
// -------------------------------------------------------------------------------------
#include "ntddk.h"

// -------------------------------------------------------------------------------------
// Logging Setup & CPU Barriers
// -------------------------------------------------------------------------------------
#undef LOG_INFO
#undef LOG_ERR
#define LOG_INFO(...)      do { printf(__VA_ARGS__); fflush(stdout); } while(0)
#define LOG_ERR(...)       do { printf(__VA_ARGS__); fflush(stdout); } while(0)

#ifndef COMPILER_BARRIER
#define COMPILER_BARRIER() _ReadWriteBarrier()
#endif

inline VOID FlushLogToFile()
{}

// -------------------------------------------------------------------------------------
// Globals
// -------------------------------------------------------------------------------------
volatile LONG g_lAbortTests = 0;
PETHREAD      g_pMasterBenchmarkThread = NULL;

#include "KmStringPatternTest.h"

TEST_SUITE_CONFIG g_TestConfig = { TRUE, TRUE };

// -------------------------------------------------------------------------------------
// User-Mode Entry Point
// -------------------------------------------------------------------------------------
int main()
{
    LOG_INFO("[SPM_TEST] *** User-Mode Main Called.\n");
    LOG_INFO("[SPM_TEST] Performance tests running with UM Threading / Memory Emulation.\n\n");

    HANDLE   hThread;
    NTSTATUS ntStatus = PsCreateSystemThread(&hThread,
                                             0,
                                             NULL,
                                             NULL,
                                             NULL,
                                             (PKSTART_ROUTINE)RunTests,
                                             &g_TestConfig);

    if (NT_SUCCESS(ntStatus))
    {
        ntStatus = ObReferenceObjectByHandle(hThread, 0, NULL, 0, (PVOID*)&g_pMasterBenchmarkThread, NULL);
        ZwClose(hThread);

        if (g_pMasterBenchmarkThread != NULL)
        {
            KeWaitForSingleObject(g_pMasterBenchmarkThread, Executive, KernelMode, FALSE, NULL);
            ObDereferenceObject(g_pMasterBenchmarkThread);
            g_pMasterBenchmarkThread = NULL;
        }
    }

    LOG_INFO("[SPM_TEST] *** User-Mode Test Application Exited Safely.\n");
    return 0;
}
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
// Unified Test Logic for KmStringPatternMatch (Kernel & User Mode)
// -------------------------------------------------------------------------------------
#pragma once
#include "KmStringPatternMatch.h"

#ifndef DRIVER_TAG
#define DRIVER_TAG 'pmSK'
#endif

#ifndef LOG_INFO
extern VOID RecordLog(_In_ _Printf_format_string_ PCSTR pszFormat, ...);
#define LOG_INFO(...) RecordLog(__VA_ARGS__)
#endif

#ifndef LOG_ERR
extern VOID RecordLog(_In_ _Printf_format_string_ PCSTR pszFormat, ...);
#define LOG_ERR(...) RecordLog(__VA_ARGS__)
#endif

#ifndef COMPILER_BARRIER
#define COMPILER_BARRIER() _ReadWriteBarrier()
#endif

extern volatile LONG g_lAbortTests;

VOID FlushLogToFile();

#define MAX_TEST_THREADS 32

// Configuration structure allowing callers to selectively run modules
struct TEST_SUITE_CONFIG
{
    BOOLEAN bRunCorrectness; // Flag to execute the functional correctness test suite
    BOOLEAN bRunPerformance; // Flag to execute the high-throughput performance test suite
};

// Context tracking state for individual test worker threads
struct TEST_WORKER_CONTEXT
{
    ULONG          ulThreadId;   // Unique identifier assigned to the worker thread
    PKEVENT        pStartEvent;  // Kernel event used to synchronize thread startup
    volatile LONG* plStopFlag;   // Shared flag signaling all threads to safely terminate
    PVOID          pUserContext; // Opaque pointer to user-defined test state data
};

typedef VOID (*PTEST_WORKER_FUNC)(_Inout_ TEST_WORKER_CONTEXT* pContext);

// Manager handling thread pooling and synchronization
struct TEST_THREAD_MANAGER
{
    PETHREAD            pThreads[MAX_TEST_THREADS];     // Array of kernel thread object pointers
    TEST_WORKER_CONTEXT Contexts[MAX_TEST_THREADS];     // Pre-allocated contexts for each worker
    ULONG               ulThreadCount;                  // Total number of actively running threads
    KEVENT              StartEvent;                     // Master event to unblock all workers simultaneously
    volatile LONG       lStopFlag;                      // Master termination signal flag for the pool
};

// -------------------------------------------------------------------------------------
// String Length Helpers abstracting char/WCHAR native operations
// -------------------------------------------------------------------------------------
inline size_t KStringLength(_In_z_ const char* __restrict s)
{
    return strlen(s);
}
inline size_t KStringLength(_In_z_ const wchar_t* __restrict s)
{
    return wcslen(s);
}

// -------------------------------------------------------------------------------------
// Initializes and starts a pool of worker threads synchronized on an event.
// Used to saturate the CPU and memory bus during high-throughput performance testing.
// -------------------------------------------------------------------------------------
VOID StartThreads(_Inout_  TEST_THREAD_MANAGER* pMgr,
                  _In_     ULONG                ulCount,
                  _In_     PTEST_WORKER_FUNC    pFunc,
                  _In_opt_ PVOID                pUserContext)
{
    PAGED_CODE();

    if (ulCount > MAX_TEST_THREADS) [[unlikely]]
    {
        ulCount = MAX_TEST_THREADS;
    }

    pMgr->ulThreadCount = ulCount;
    pMgr->lStopFlag = 0;

    KeInitializeEvent(&pMgr->StartEvent, NotificationEvent, FALSE);

    for (ULONG ulIndex = 0; ulIndex < ulCount; ++ulIndex)
    {
        pMgr->Contexts[ulIndex].ulThreadId = ulIndex;
        pMgr->Contexts[ulIndex].pStartEvent = &pMgr->StartEvent;
        pMgr->Contexts[ulIndex].plStopFlag = &pMgr->lStopFlag;
        pMgr->Contexts[ulIndex].pUserContext = pUserContext;

        HANDLE hThread;
        NTSTATUS ntStatus = PsCreateSystemThread(&hThread,
                                                 0,
                                                 NULL,
                                                 NULL,
                                                 NULL,
                                                 (PKSTART_ROUTINE)pFunc,
                                                 &pMgr->Contexts[ulIndex]);

        if (NT_SUCCESS(ntStatus)) [[likely]]
        {
            ntStatus = ObReferenceObjectByHandle(hThread,
                                                 0,
                                                 NULL,
                                                 KernelMode,
                                                 (PVOID*)&pMgr->pThreads[ulIndex],
                                                 NULL);

            if (NT_SUCCESS(ntStatus)) [[likely]]
            {
                KeSetPriorityThread(pMgr->pThreads[ulIndex], 15);
                ZwClose(hThread);
            }
            else
            {
                pMgr->pThreads[ulIndex] = NULL;
                InterlockedExchange(&pMgr->lStopFlag, 1);
                InterlockedExchange(&g_lAbortTests, 1);

                KeSetEvent(&pMgr->StartEvent, IO_NO_INCREMENT, FALSE);
                KeWaitForSingleObject(hThread, Executive, KernelMode, FALSE, NULL);
                ZwClose(hThread);
            }
        }
        else
        {
            pMgr->pThreads[ulIndex] = NULL;
        }
    }

    KeSetEvent(&pMgr->StartEvent, IO_NO_INCREMENT, FALSE);
}

// -------------------------------------------------------------------------------------
// Signals threads to stop and waits for them to terminate safely.
// -------------------------------------------------------------------------------------
VOID StopAndWaitThreads(_Inout_ TEST_THREAD_MANAGER* pMgr,
                        _In_    int                  nSleepSeconds)
{
    PAGED_CODE();

    if (nSleepSeconds > 0)
    {
        int nIterations = nSleepSeconds * 100;

        for (int nIndex = 0; nIndex < nIterations; ++nIndex)
        {
            if (InterlockedCompareExchange(&g_lAbortTests, 0, 0)) [[unlikely]]
            {
                break;
            }

            LARGE_INTEGER liDelay;
            liDelay.QuadPart = -100000LL;
            KeDelayExecutionThread(KernelMode, FALSE, &liDelay);
        }
    }

    InterlockedExchange(&pMgr->lStopFlag, 1);

    for (ULONG ulIndex = 0; ulIndex < pMgr->ulThreadCount; ++ulIndex)
    {
        if (pMgr->pThreads[ulIndex] != NULL)
        {
            KeWaitForSingleObject(pMgr->pThreads[ulIndex], Executive, KernelMode, FALSE, NULL);
            ObDereferenceObject(pMgr->pThreads[ulIndex]);
        }
    }
}

// -------------------------------------------------------------------------------------
// SPM Target Context
// -------------------------------------------------------------------------------------
struct PatternContext
{
    ULONG ulPatternId; // Unique identifier linked to the matched pattern rule
};

// -------------------------------------------------------------------------------------
// Validates initialization and simultaneously checks multi-match and single-match results.
// Templated to uniformly support char and WCHAR pipelines.
// -------------------------------------------------------------------------------------
template <typename TChar>
BOOLEAN RunSingleCorrectnessTest(_In_ const TChar* __restrict psText,
                                 _In_ const TChar* __restrict psPattern,
                                 _In_ UCHAR                   ucScope,
                                 _In_ BOOLEAN                 bShouldMatch,
                                 _In_ BOOLEAN                 bCaseInsensitive,
                                 _In_ const char*             pszTestName)
{
    PAGED_CODE();

    if (InterlockedCompareExchange(&g_lAbortTests, 0, 0)) [[unlikely]]
    {
        return FALSE;
    }

    KmStringPatternMatch<PatternContext, TChar> Spm(bCaseInsensitive);
    PatternContext ctx = {100};

    if (!NT_SUCCESS(Spm.AddPattern(psPattern, static_cast<UINT32>(KStringLength(psPattern)), static_cast<WILD_CARD_SCOPE>(ucScope), kstd::move(ctx)))) [[unlikely]]
    {
        LOG_ERR("[SPM_TEST] [!] %s - AddPattern Failed\n", pszTestName);
        return FALSE;
    }

    KVector<PatternContext*> matchedCtxAll;
    NTSTATUS status = Spm.Search(psText, static_cast<UINT32>(KStringLength(psText)), matchedCtxAll);
    BOOLEAN bMatchedAll = NT_SUCCESS(status) && (matchedCtxAll.Size() > 0);

    PatternContext* pMatchedFirst = nullptr;
    BOOLEAN bMatchedFirst = Spm.Search(psText, static_cast<UINT32>(KStringLength(psText)), &pMatchedFirst);

    if (bMatchedAll == bShouldMatch && bMatchedFirst == bShouldMatch) [[likely]]
    {
        LOG_INFO("[SPM_TEST] [+] PASS: %s\n", pszTestName);
        return TRUE;
    }

    LOG_ERR("[SPM_TEST] [!] FAIL: %s (Expected %d, Got MatchAll: %d, MatchFirst: %d)\n", pszTestName, bShouldMatch, bMatchedAll, bMatchedFirst);
    return FALSE;
}

// -------------------------------------------------------------------------------------
// Validates overlapping rules to ensure MatchFirst properly extracts a single context.
// -------------------------------------------------------------------------------------
template <typename TChar>
BOOLEAN RunMultiPatternCorrectnessTest(_In_ const TChar* __restrict psPattern1,
                                       _In_ const TChar* __restrict psPattern2,
                                       _In_ const TChar* __restrict psText,
                                       _In_ BOOLEAN                 bCaseInsensitive)
{
    PAGED_CODE();

    KmStringPatternMatch<PatternContext, TChar> Spm(bCaseInsensitive);
    PatternContext ctx1 = {1};
    PatternContext ctx2 = {2};

    if (!NT_SUCCESS(Spm.AddPattern(psPattern1, static_cast<UINT32>(KStringLength(psPattern1)), SCOPE_DEFAULT, kstd::move(ctx1)))) [[unlikely]]
    {
        return FALSE;
    }

    if (!NT_SUCCESS(Spm.AddPattern(psPattern2, static_cast<UINT32>(KStringLength(psPattern2)), SCOPE_DEFAULT, kstd::move(ctx2)))) [[unlikely]]
    {
        return FALSE;
    }

    KVector<PatternContext*> results;
    NTSTATUS status = Spm.Search(psText, static_cast<UINT32>(KStringLength(psText)), results);
    BOOLEAN bAll = NT_SUCCESS(status) && (results.Size() > 0);

    PatternContext* pFirstRes = nullptr;
    BOOLEAN bFirst = Spm.Search(psText, static_cast<UINT32>(KStringLength(psText)), &pFirstRes);

    if (bAll && results.Size() == 2 && bFirst && pFirstRes && (pFirstRes->ulPatternId == 1 || pFirstRes->ulPatternId == 2)) [[likely]]
    {
        LOG_INFO("[SPM_TEST] [+] PASS: Multi-Pattern MatchAll & MatchFirst Overlap\n");
        return TRUE;
    }

    LOG_ERR("[SPM_TEST] [!] FAIL: Multi-Pattern MatchAll & MatchFirst Overlap\n");
    return FALSE;
}

// -------------------------------------------------------------------------------------
// Actually matches several overlapping patterns concurrently and validates results.
// -------------------------------------------------------------------------------------
template <typename TChar>
BOOLEAN RunMatchAllSeveralPatternsTest(_In_ const TChar* __restrict pat1,
                                       _In_ const TChar* __restrict pat2,
                                       _In_ const TChar* __restrict pat3,
                                       _In_ const TChar* __restrict pat4,
                                       _In_ const TChar* __restrict text,
                                       _In_ BOOLEAN                 bCaseInsensitive)
{
    PAGED_CODE();

    KmStringPatternMatch<PatternContext, TChar> Spm(bCaseInsensitive);
    PatternContext ctx1 = {10};
    PatternContext ctx2 = {20};
    PatternContext ctx3 = {30};
    PatternContext ctx4 = {40};

    if (!NT_SUCCESS(Spm.AddPattern(pat1, static_cast<UINT32>(KStringLength(pat1)), SCOPE_DEFAULT, kstd::move(ctx1)))) [[unlikely]]
    {
        return FALSE;
    }

    if (!NT_SUCCESS(Spm.AddPattern(pat2, static_cast<UINT32>(KStringLength(pat2)), SCOPE_DEFAULT, kstd::move(ctx2)))) [[unlikely]]
    {
        return FALSE;
    }

    if (!NT_SUCCESS(Spm.AddPattern(pat3, static_cast<UINT32>(KStringLength(pat3)), SCOPE_DEFAULT, kstd::move(ctx3)))) [[unlikely]]
    {
        return FALSE;
    }

    if (!NT_SUCCESS(Spm.AddPattern(pat4, static_cast<UINT32>(KStringLength(pat4)), SCOPE_DEFAULT, kstd::move(ctx4)))) [[unlikely]]
    {
        return FALSE;
    }

    KVector<PatternContext*> results;
    NTSTATUS status = Spm.Search(text, static_cast<UINT32>(KStringLength(text)), results);
    BOOLEAN bAll = NT_SUCCESS(status) && (results.Size() > 0);

    if (bAll && (results.Size() == 3)) [[likely]]
    {
        BOOLEAN bHas1 = FALSE, bHas2 = FALSE, bHas4 = FALSE;

        for (SIZE_T i = 0; i < results.Size(); i++)
        {
            if (results[i]->ulPatternId == 10)
            {
                bHas1 = TRUE;
            }

            if (results[i]->ulPatternId == 20)
            {
                bHas2 = TRUE;
            }

            if (results[i]->ulPatternId == 40)
            {
                bHas4 = TRUE;
            }
        }

        if (bHas1 && bHas2 && bHas4)
        {
            LOG_INFO("[SPM_TEST] [+] PASS: MatchAll Successfully Resolved Several Overlapping Patterns\n");
            return TRUE;
        }
    }

    LOG_ERR("[SPM_TEST] [!] FAIL: MatchAll Failed to Resolve Multiple Expected Patterns\n");
    return FALSE;
}

// -------------------------------------------------------------------------------------
// Validates the engine correctly handles queries when zero patterns are registered,
// executing the early O(1) fast-fail branch.
// -------------------------------------------------------------------------------------
template <typename TChar>
BOOLEAN RunEmptyEngineTest(_In_ const TChar* __restrict psText,
                           _In_ BOOLEAN                 bCaseInsensitive)
{
    PAGED_CODE();

    KmStringPatternMatch<PatternContext, TChar> Spm(bCaseInsensitive);

    PatternContext* pMatchedFirst = nullptr;
    BOOLEAN bMatchedFirst = Spm.Search(psText, static_cast<UINT32>(KStringLength(psText)), &pMatchedFirst);

    if (!bMatchedFirst) [[likely]]
    {
        LOG_INFO("[SPM_TEST] [+] PASS: Empty Engine Fast-Fail\n");
        return TRUE;
    }

    LOG_ERR("[SPM_TEST] [!] FAIL: Empty Engine Fast-Fail (Unexpected Match)\n");
    return FALSE;
}

// -------------------------------------------------------------------------------------
// Validates explicit engine state reset via Clear(), ensuring memory arenas 
// and vectors safely flush state outside of normal destruction.
// -------------------------------------------------------------------------------------
template <typename TChar>
BOOLEAN RunClearLifecycleTest(_In_ const TChar* __restrict psPattern,
                              _In_ const TChar* __restrict psText,
                              _In_ BOOLEAN                 bCaseInsensitive)
{
    PAGED_CODE();

    KmStringPatternMatch<PatternContext, TChar> Spm(bCaseInsensitive);
    PatternContext ctx = { 100 };

    if (!NT_SUCCESS(Spm.AddPattern(psPattern, static_cast<UINT32>(KStringLength(psPattern)), SCOPE_DEFAULT, kstd::move(ctx)))) [[unlikely]]
    {
        return FALSE;
    }

    PatternContext* pMatched = nullptr;
    if (!Spm.Search(psText, static_cast<UINT32>(KStringLength(psText)), &pMatched)) [[unlikely]]
    {
        return FALSE;
    }

    Spm.Clear();

    if (!Spm.Search(psText, static_cast<UINT32>(KStringLength(psText)), &pMatched)) [[likely]]
    {
        LOG_INFO("[SPM_TEST] [+] PASS: Engine Clear Lifecycle\n");
        return TRUE;
    }

    LOG_ERR("[SPM_TEST] [!] FAIL: Engine Clear Lifecycle (Ghost Match)\n");
    return FALSE;
}

// -------------------------------------------------------------------------------------
// Macros dynamically wrapping string literals based on the character type (char vs WCHAR)
// -------------------------------------------------------------------------------------
#define WIDEN_STRING(x) L##x
#define NARROW_STRING(x) x

// Master execution macro preventing code duplication for exhaustive correctness validation
#define EXECUTE_CORRECTNESS_SUITE(CharType, STR)                                                                                                                               \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("file.txt"), STR("file.txt"), 0, TRUE, TRUE, "Exact Literal Match"));                                                     \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("file.txt"), STR("*.txt"), 0, TRUE, TRUE, "Wildcard Prefix Match"));                                                      \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("prefix_file.txt"), STR("prefix*"), 0, TRUE, TRUE, "Wildcard Suffix Match"));                                             \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("my_cool_file.txt"), STR("*cool*"), 0, TRUE, TRUE, "Wildcard Middle Match"));                                             \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("a"), STR("?"), 0, TRUE, TRUE, "Single Any (?) Match"));                                                                  \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("ab"), STR("?"), 0, FALSE, TRUE, "Single Any (?) Mismatch on Length"));                                                   \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("abc"), STR("a?c"), 0, TRUE, TRUE, "Single Any (?) Middle"));                                                             \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("Upper.TXT"), STR("upper.txt"), 0, TRUE, TRUE, "Case Insensitivity Check (Match)"));                                      \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("C:\\Temp\\Sub\\file.txt"), STR("C:\\*\\file.txt"), 0, TRUE, TRUE, "Wildcard Default Scope (Allows Slash)"));             \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("C:\\Temp\\Sub\\file.txt"), STR("C:\\*\\file.txt"), 1, FALSE, TRUE, "Wildcard Slash Scope (Blocks Slash)"));              \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("Upper.TXT"), STR("upper.txt"), 0, FALSE, FALSE, "Case Sensitivity Check (Mismatch)"));                                   \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("ExactCase.TXT"), STR("ExactCase.TXT"), 0, TRUE, FALSE, "Case Sensitivity Check (Exact Match)"));                         \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("ExactStringTestMatch"), STR("ExactStringTestMatch"), 0, TRUE, TRUE, "Exact String Check (Match)"));                      \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("ExactStringTestMatch"), STR("ExactStringMismatch"), 0, FALSE, TRUE, "Exact String Check (Mismatch)"));                   \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("a_z_test"), STR("A_Z_TEST"), 0, TRUE, TRUE, "SWAR Boundary Transformation ('a' and 'z')"));                              \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("`a{z`a{z"), STR("`A{Z`A{Z"), 0, TRUE, TRUE, "SWAR Adjacent Exclusion ('`' and '{')"));                                   \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("abcdefgh"), STR("ABCDEFGH"), 0, TRUE, TRUE, "SWAR Full Block Transformation"));                                          \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("!@#$[]{}"), STR("!@#$[]{}"), 0, TRUE, TRUE, "SWAR Full Block Exclusion"));                                               \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR(""), STR(""), 0, TRUE, TRUE, "Zero-Length Exact Match"));                                                                 \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR(""), STR("*"), 0, TRUE, TRUE, "Zero-Length Wildcard Match"));                                                             \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("a"), STR(""), 0, FALSE, TRUE, "Zero-Length Pattern Mismatch"));                                                          \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("a"), STR("a*"), 0, TRUE, TRUE, "Suffix Wildcard on Single Char"));                                                       \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("abcdef"), STR("a*f"), 0, TRUE, TRUE, "Boundary Wildcard Match"));                                                        \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("abcdef"), STR("a*z"), 0, FALSE, TRUE, "Boundary Wildcard Mismatch"));                                                    \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("abc"), STR("????"), 0, FALSE, TRUE, "Too Many Wildcards (?)"));                                                          \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("abc"), STR("??"), 0, FALSE, TRUE, "Too Few Wildcards (?)"));                                                             \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("a1b2c3d4"), STR("a?b?c?d?"), 0, TRUE, TRUE, "Alternating Wildcards (?)"));                                               \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("hello"), STR("**hello**"), 0, TRUE, TRUE, "Redundant Asterisks (*)"));                                                   \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("hello"), STR("*h*e*l*l*o*"), 0, TRUE, TRUE, "Scattered Asterisks (*)"));                                                 \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("C:\\Temp\\Sub\\test.txt"), STR("C:\\*\\*.txt"), 1, FALSE, TRUE, "Strict Path Wildcard Multiple Slashes (Slash Scope)")); \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("C:\\Temp\\Sub\\test.txt"), STR("C:\\*\\*.txt"), 0, TRUE, TRUE, "Path Wildcard Multiple Slashes (Default Scope)"));       \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("a*b"), STR("a|*b"), 0, TRUE, TRUE, "Escape Character (Escaped *)"));                                                     \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("a?b"), STR("a|?b"), 0, TRUE, TRUE, "Escape Character (Escaped ?)"));                                                     \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("a|b"), STR("a||b"), 0, TRUE, TRUE, "Escape Character (Escaped |)"));                                                     \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("a*b"), STR("a|?b"), 0, FALSE, TRUE, "Escape Character (Mismatch on Escaped)"));                                          \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("abc"), STR("a|*c"), 0, FALSE, TRUE, "Escape Character (Literal mismatch against wildcard)"));                            \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("abc|"), STR("abc|"), 0, TRUE, TRUE, "Escape Character (Dangling Escape)"));                                              \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("a|x"), STR("a|x"), 0, TRUE, TRUE, "Escape Character (Unrecognized Escape acts as literal)"));                            \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("a|*b"), STR("a|||*b"), 0, TRUE, TRUE, "Escape Character (Consecutive Interleaved Escapes)"));                            \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("A*B"), STR("a|*b"), 0, TRUE, TRUE, "Escape Character (Case-Insensitive Escaped Wildcard)"));                             \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("axb"), STR("a*?b"), 0, TRUE, TRUE, "Mixed Wildcards (*?) Match"));                                                       \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("ab"), STR("a*?b"), 0, FALSE, TRUE, "Mixed Wildcards (*?) Length Mismatch"));                                             \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("axyzb"), STR("a?*b"), 0, TRUE, TRUE, "Mixed Wildcards (?*) Match"));                                                     \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR(""), STR("?"), 0, FALSE, TRUE, "Single Any (?) against Empty String"));                                                   \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("a\\b"), STR("a?b"), 1, FALSE, TRUE, "Scope Slash blocks Single Any (?)"));                                               \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("short"), STR("muchlongerpattern"), 0, FALSE, TRUE, "Length Bounds Fast-Fail"));                                            \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("123456789"), STR("123456789"), 0, TRUE, FALSE, "SWAR Unaligned Tail Check (Match)"));                                    \
    CheckTest(RunSingleCorrectnessTest<CharType>(STR("123456789"), STR("123456780"), 0, FALSE, FALSE, "SWAR Unaligned Tail Check (Mismatch)"));                                \
    CheckTest(RunEmptyEngineTest<CharType>(STR("FastExitCheck"), TRUE));                                                                                                       \
    CheckTest(RunClearLifecycleTest<CharType>(STR("flush.txt"), STR("flush.txt"), TRUE));                                                                                     \
    CheckTest(RunMultiPatternCorrectnessTest<CharType>(STR("*.txt"), STR("file.txt"), STR("file.txt"), TRUE));                                                                 \
    CheckTest(RunMatchAllSeveralPatternsTest<CharType>(STR("*.txt"), STR("test.*"), STR("*.log"), STR("te*xt"), STR("test.txt"), TRUE));

// -------------------------------------------------------------------------------------
// Validates truth table against multiple wildcard constraints for both types.
// -------------------------------------------------------------------------------------
VOID RunAllCorrectnessTests()
{
    PAGED_CODE();

    ULONG ulPassed = 0;
    ULONG ulFailed = 0;

    auto CheckTest = [&](BOOLEAN bResult)
    {
        if (bResult) [[likely]]
        {
            ulPassed++;
        }
        else
        {
            ulFailed++;
        }
    };

    LOG_INFO("\n[SPM_TEST] --- Correctness Tests [WCHAR] ---\n");
    EXECUTE_CORRECTNESS_SUITE(WCHAR, WIDEN_STRING);

    LOG_INFO("\n[SPM_TEST] --- Correctness Tests [CHAR] ---\n");
    EXECUTE_CORRECTNESS_SUITE(CHAR, NARROW_STRING);

    if (ulFailed == 0) [[likely]]
    {
        LOG_INFO("\n[SPM_TEST] [+] ALL TESTS SUCCEEDED (%u passed)\n", ulPassed);
    }
    else
    {
        LOG_ERR("\n[SPM_TEST] [!] SOME TESTS FAILED (%u passed, %u failed)\n", ulPassed, ulFailed);
    }
}

// -------------------------------------------------------------------------------------
// Data packet fed into templated threaded performance workers.
// -------------------------------------------------------------------------------------
template <typename TChar>
struct PerfWorkerCtx
{
    KmStringPatternMatch<PatternContext, TChar>* pSpm;             // Pointer to the active string pattern matcher instance
    const TChar*                                 pText;            // Pointer to the target text buffer to search
    size_t                                       cchTextLen;       // Length of the text buffer in characters
    volatile LONG64                              llTotalOpsPerSec; // Pre-aggregated rate of operations across all threads
    LARGE_INTEGER                                liFreq;           // High-resolution clock frequency provided by orchestrator
    volatile LONG                                lStartFlag;       // Flag indicating the worker has formally started
    BOOLEAN                                      bUseMatchFirst;   // Toggles between MatchFirst and MatchAll modes
    BOOLEAN                                      bExpectMatch;     // Indicates whether a match is logically expected
    volatile LONG                                lTestFailed;      // Flag set if a correctness logic violation occurs
    volatile LONG                                lActualResult;    // Captures the erroneous boolean result on failure
};

// -------------------------------------------------------------------------------------
// Iteratively runs search operations in a tight loop to calculate throughput.
// Branches loop internally to prevent branch prediction overhead during measurement.
// Terminates loop and safely notifies orchestrator if an unexpected match logic failure occurs.
// -------------------------------------------------------------------------------------
template <typename TChar>
VOID PerfWorkerT(_Inout_ TEST_WORKER_CONTEXT* __restrict pCtx)
{
    PAGED_CODE();

    PerfWorkerCtx<TChar>* pWorkerCtx = (PerfWorkerCtx<TChar>*)pCtx->pUserContext;
    KeWaitForSingleObject(pCtx->pStartEvent, Executive, KernelMode, FALSE, NULL);

    UINT64 localOps = 0;
    BOOLEAN bAborted = FALSE;

    while (InterlockedCompareExchange(&pWorkerCtx->lStartFlag, 0, 0) == 0)
    {
        if (InterlockedCompareExchange(&g_lAbortTests, 0, 0)) [[unlikely]]
        {
            bAborted = TRUE;
            break;
        }

        YieldProcessor(); // mitigates thread start skew during metrics capture
    }

    if (!bAborted) [[likely]]
    {
        // 1. Capture exact start time immediately before the work loop
        LARGE_INTEGER liStart = KeQueryPerformanceCounter(NULL);

        if (pWorkerCtx->bUseMatchFirst)
        {
            PatternContext* pResult = nullptr;

            while (InterlockedCompareExchange(pCtx->plStopFlag, 0, 0) == 0 && 
                   InterlockedCompareExchange(&g_lAbortTests, 0, 0) == 0) [[likely]]
            {
                BOOLEAN bRet = pWorkerCtx->pSpm->Search(pWorkerCtx->pText, static_cast<UINT32>(pWorkerCtx->cchTextLen), &pResult);

                // Assert throughput correctness - instantly abort thread and flag for shutdown on logic failure
                if (bRet != pWorkerCtx->bExpectMatch) [[unlikely]]
                {
                    InterlockedExchange(&pWorkerCtx->lActualResult, bRet ? 1 : 0);
                    InterlockedExchange(&pWorkerCtx->lTestFailed, 1);
                    break;
                }

                localOps++;
                COMPILER_BARRIER();
            }
        }
        else
        {
            KVector<PatternContext*> Results;

            while (InterlockedCompareExchange(pCtx->plStopFlag, 0, 0) == 0 && 
                   InterlockedCompareExchange(&g_lAbortTests, 0, 0) == 0) [[likely]]
            {
                NTSTATUS status = pWorkerCtx->pSpm->Search(pWorkerCtx->pText, static_cast<UINT32>(pWorkerCtx->cchTextLen), Results);
                BOOLEAN bRet = NT_SUCCESS(status) && (Results.Size() > 0);

                // Assert throughput correctness - instantly abort thread and flag for shutdown on logic failure
                if (bRet != pWorkerCtx->bExpectMatch) [[unlikely]]
                {
                    InterlockedExchange(&pWorkerCtx->lActualResult, bRet ? 1 : 0);
                    InterlockedExchange(&pWorkerCtx->lTestFailed, 1);
                    break;
                }

                localOps++;
                COMPILER_BARRIER();
            }
        }

        // 2. Capture exact end time immediately after the stop flag is detected
        LARGE_INTEGER liEnd = KeQueryPerformanceCounter(NULL);

        // 3. Calculate this thread's exact ops/sec, completely excluding OS teardown overhead
        UINT64 localTicks = liEnd.QuadPart - liStart.QuadPart;
        
        if (localTicks > 0 && localOps > 0)
        {
            UINT64 localOpsPerSec = (localOps * pWorkerCtx->liFreq.QuadPart) / localTicks;
            InterlockedExchangeAdd64(&pWorkerCtx->llTotalOpsPerSec, (LONG64)localOpsPerSec);
        }
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

// -------------------------------------------------------------------------------------
// Orchestrates performance execution, spins up worker threads, calculates metrics.
// -------------------------------------------------------------------------------------
template <typename TChar>
BOOLEAN RunPerformanceTier(_In_ ULONG       ulPatternCount,
                           _In_ ULONG       ulTextLenChars,
                           _In_ BOOLEAN     bPathological,
                           _In_ BOOLEAN     bExpectMatch,
                           _In_ BOOLEAN     bCaseInsensitive,
                           _In_ const char* pszTestName,
                           _In_ const char* pszDescription,
                           _In_ const char* psPatternType,
                           _In_ const char* pszCharType)
{
    PAGED_CODE();

    if (InterlockedCompareExchange(&g_lAbortTests, 0, 0)) [[unlikely]]
    {
        return FALSE;
    }

    KmStringPatternMatch<PatternContext, TChar> Spm(bCaseInsensitive);
    BOOLEAN bTierSuccess = TRUE;

    const SIZE_T cbTextMap = static_cast<SIZE_T>(ulTextLenChars) * sizeof(TChar) + sizeof(TChar);
    TChar* pwsText = (TChar*)ExAllocatePool2(POOL_FLAG_PAGED, cbTextMap, DRIVER_TAG);

    if (!pwsText) [[unlikely]]
    {
        return FALSE;
    }

    for (ULONG i = 0; i < ulTextLenChars; i++)
    {
        if (bExpectMatch)
        {
            pwsText[i] = static_cast<TChar>('A' + (i % 26));
        }
        else
        {
            pwsText[i] = static_cast<TChar>('X'); // Forces negative matches
        }
    }

    // Inject a guaranteed match for Pattern 0 near the end of the text
    if (bExpectMatch && ulTextLenChars >= 16)
    {
        if (bPathological)
        {
            pwsText[ulTextLenChars - 4] = static_cast<TChar>('A');
            pwsText[ulTextLenChars - 3] = static_cast<TChar>('0');
            pwsText[ulTextLenChars - 2] = static_cast<TChar>('B');
        }
        else
        {
            pwsText[ulTextLenChars - 9] = static_cast<TChar>('S');
            pwsText[ulTextLenChars - 8] = static_cast<TChar>('Y');
            pwsText[ulTextLenChars - 7] = static_cast<TChar>('S');
            pwsText[ulTextLenChars - 6] = static_cast<TChar>('0');
            pwsText[ulTextLenChars - 5] = static_cast<TChar>('0');
            pwsText[ulTextLenChars - 4] = static_cast<TChar>('0');
            pwsText[ulTextLenChars - 3] = static_cast<TChar>('0');
            pwsText[ulTextLenChars - 2] = static_cast<TChar>('B');
        }
    }

    pwsText[ulTextLenChars] = static_cast<TChar>('\0');

    TChar* pStrArray = (TChar*)ExAllocatePool2(POOL_FLAG_PAGED, ulPatternCount * 64 * sizeof(TChar), DRIVER_TAG);

    if (!pStrArray) [[unlikely]]
    {
        ExFreePoolWithTag(pwsText, DRIVER_TAG);
        return FALSE;
    }

    for (ULONG i = 0; i < ulPatternCount; i++)
    {
        if (bPathological)
        {
            if constexpr (sizeof(TChar) == 1)
            {
                sprintf_s((char*)&pStrArray[i * 64], 64, "*A%dB*", (int)i);
            }
            else
            {
                swprintf_s((wchar_t*)&pStrArray[i * 64], 64, L"*A%dB*", (int)i);
            }
        }
        else
        {
            if constexpr (sizeof(TChar) == 1)
            {
                sprintf_s((char*)&pStrArray[i * 64], 64, "SYS%04d*B*", (int)i);
            }
            else
            {
                swprintf_s((wchar_t*)&pStrArray[i * 64], 64, L"SYS%04d*B*", (int)i);
            }
        }

        PatternContext ctx = {i};

        if (!NT_SUCCESS(Spm.AddPattern(&pStrArray[i * 64], static_cast<UINT32>(KStringLength(&pStrArray[i * 64])), SCOPE_DEFAULT, kstd::move(ctx)))) [[unlikely]]
        {
            ExFreePoolWithTag(pStrArray, DRIVER_TAG);
            ExFreePoolWithTag(pwsText, DRIVER_TAG);
            return FALSE;
        }
    }

    LOG_INFO("\n[SPM_TEST] --- Perf Test [%s]: %s [%u Patterns | Text: %u Chars] ---\n", pszCharType, pszTestName, ulPatternCount, ulTextLenChars);
    LOG_INFO("[SPM_TEST]      %s\n", pszDescription);
    LOG_INFO("[SPM_TEST]      Pattern Type: %s\n", psPatternType);
    LOG_INFO("[SPM_TEST]      ------------------------------------------------------------------------------------\n");
    LOG_INFO("[SPM_TEST]      %-18s | %-15s | %-15s | %-15s\n", "Engine Mode", "Throughput", "Ops/sec", "Latency/Op");
    LOG_INFO("[SPM_TEST]      ------------------------------------------------------------------------------------\n");

    LARGE_INTEGER liFreq;
    KeQueryPerformanceCounter(&liFreq);

    auto RunMode = [&](BOOLEAN bMatchFirst, const char* label) -> BOOLEAN
    {
        if (InterlockedCompareExchange(&g_lAbortTests, 0, 0)) [[unlikely]]
        {
            return FALSE;
        }

        PerfWorkerCtx<TChar> Ctx = {0};
        Ctx.pSpm = &Spm;
        Ctx.pText = pwsText;
        Ctx.cchTextLen = ulTextLenChars;
        Ctx.liFreq = liFreq;
        Ctx.llTotalOpsPerSec = 0;
        Ctx.bUseMatchFirst = bMatchFirst;
        Ctx.bExpectMatch = bExpectMatch;
        Ctx.lTestFailed = 0;

        TEST_THREAD_MANAGER* pMgr = (TEST_THREAD_MANAGER*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(TEST_THREAD_MANAGER), DRIVER_TAG);

        if (pMgr) [[likely]]
        {
            StartThreads(pMgr, 1, PerfWorkerT<TChar>, &Ctx);

            LARGE_INTEGER liDelay;
            liDelay.QuadPart = -2000000LL;
            KeDelayExecutionThread(KernelMode, FALSE, &liDelay);

            InterlockedExchange(&Ctx.lStartFlag, 1);
            
            // Wait for threads to clean up (time taken here no longer corrupts the math)
            StopAndWaitThreads(pMgr, 2);            

            if (Ctx.lTestFailed) [[unlikely]]
            {
                LOG_ERR("[SPM_TEST]      %-18s | [!] FAILED: Unexpected Result (Expected %d, Actual %ld)\n", label, bExpectMatch, Ctx.lActualResult);
                // Flag global suite termination - perf metrics are strictly dependent on correctness validation
                InterlockedExchange(&g_lAbortTests, 1);
                ExFreePoolWithTag(pMgr, DRIVER_TAG);
                return FALSE;
            }
            else
            {
                // Retrieve the purely isolated ops/sec from the threads
                UINT64 opsPerSec = static_cast<UINT64>(Ctx.llTotalOpsPerSec);
                
                // Calculate Physical Stream Ingestion Bandwidth
                UINT64 bytesPerOp = static_cast<UINT64>(ulTextLenChars) * sizeof(TChar);
                UINT64 bytesPerSec = opsPerSec * bytesPerOp;
                UINT64 mbWhole = bytesPerSec / (1024ULL * 1024ULL);

                // High precision latency calculation factoring in true thread parallelism
                UINT64 totalPs = opsPerSec > 0 ? ((1000000000000ULL * (pMgr->ulThreadCount > 0 ? pMgr->ulThreadCount : 1)) / opsPerSec) : 0;
                UINT64 usWhole = totalPs / 1000000;
                UINT64 usFrac = (totalPs % 1000000) / 100;

                // Format with two decimal fraction places if throughput is below 1 MB/s
                if (mbWhole < 1)
                {
                    UINT64 mbFrac = ((bytesPerSec % (1024ULL * 1024ULL)) * 100ULL) / (1024ULL * 1024ULL);
                    LOG_INFO("[SPM_TEST]      %-18s | %7llu.%02llu MB/s | %15llu | %9llu.%04llu us\n", label, mbWhole, mbFrac, opsPerSec, usWhole, usFrac);
                }
                else
                {
                    LOG_INFO("[SPM_TEST]      %-18s | %10llu MB/s | %15llu | %9llu.%04llu us\n", label, mbWhole, opsPerSec, usWhole, usFrac);
                }

                ExFreePoolWithTag(pMgr, DRIVER_TAG);
                return TRUE;
            }
        }

        return FALSE;
    };

    if (RunMode(FALSE, "MatchAll")) [[likely]]
    {
        RunMode(TRUE, "MatchFirst");
    }
    else
    {
        bTierSuccess = FALSE;
    }

    ExFreePoolWithTag(pStrArray, DRIVER_TAG);
    ExFreePoolWithTag(pwsText, DRIVER_TAG);

    return bTierSuccess;
}

// -------------------------------------------------------------------------------------
// Benchmarks realistic kernel file path matching scenarios.
// -------------------------------------------------------------------------------------
template <typename TChar>
BOOLEAN RunRealisticPathPerformanceTier(_In_ ULONG       ulPatternCount,
                                        _In_ BOOLEAN     bExpectMatch,
                                        _In_ BOOLEAN     bCaseInsensitive,
                                        _In_ const char* pszTestName,
                                        _In_ const char* pszDescription,
                                        _In_ const char* psPatternType,
                                        _In_ const char* pszCharType)
{
    PAGED_CODE();

    if (InterlockedCompareExchange(&g_lAbortTests, 0, 0)) [[unlikely]]
    {
        return FALSE;
    }

    KmStringPatternMatch<PatternContext, TChar> Spm(bCaseInsensitive);
    BOOLEAN bTierSuccess = TRUE;

    TChar* pStrArray = (TChar*)ExAllocatePool2(POOL_FLAG_PAGED, ulPatternCount * 128 * sizeof(TChar), DRIVER_TAG);

    if (!pStrArray) [[unlikely]]
    {
        return FALSE;
    }

    for (ULONG i = 0; i < ulPatternCount; i++)
    {
        TChar* pCurPat = &pStrArray[i * 128];

        if (i % 4 == 0)
        {
            if constexpr (sizeof(TChar) == 1)
            {
                sprintf_s((char*)pCurPat, 128, "\\Device\\HarddiskVolume2\\Program Files\\App%u\\*\\crypt.exe", (int)i);
            }
            else
            {
                swprintf_s((wchar_t*)pCurPat, 128, L"\\Device\\HarddiskVolume2\\Program Files\\App%u\\*\\crypt.exe", (int)i);
            }
        }
        else if (i % 4 == 1)
        {
            if constexpr (sizeof(TChar) == 1)
            {
                sprintf_s((char*)pCurPat, 128, "\\Device\\HarddiskVolume2\\Windows\\System32\\module_%u.dll", (int)i);
            }
            else
            {
                swprintf_s((wchar_t*)pCurPat, 128, L"\\Device\\HarddiskVolume2\\Windows\\System32\\module_%u.dll", (int)i);
            }
        }
        else if (i % 4 == 2)
        {
            if constexpr (sizeof(TChar) == 1)
            {
                sprintf_s((char*)pCurPat, 128, "\\Device\\HarddiskVolume2\\Users\\*\\AppData\\Roaming\\payload_%u.exe", (int)i);
            }
            else
            {
                swprintf_s((wchar_t*)pCurPat, 128, L"\\Device\\HarddiskVolume2\\Users\\*\\AppData\\Roaming\\payload_%u.exe", (int)i);
            }
        }
        else
        {
            if constexpr (sizeof(TChar) == 1)
            {
                sprintf_s((char*)pCurPat, 128, "\\Device\\HarddiskVolume2\\Temp\\malware_%u.tmp", (int)i);
            }
            else
            {
                swprintf_s((wchar_t*)pCurPat, 128, L"\\Device\\HarddiskVolume2\\Temp\\malware_%u.tmp", (int)i);
            }
        }

        PatternContext ctx = {i};

        if (!NT_SUCCESS(Spm.AddPattern(pCurPat, static_cast<UINT32>(KStringLength(pCurPat)), SCOPE_DEFAULT, kstd::move(ctx)))) [[unlikely]]
        {
            ExFreePoolWithTag(pStrArray, DRIVER_TAG);
            return FALSE;
        }
    }

    // Change App42 to App0 to ensure (0 % 4 == 0) guarantees generation of a matching pattern
    const TChar* pwszTargetPath;

    if constexpr (sizeof(TChar) == 1)
    {
        pwszTargetPath = bExpectMatch
                             ? (const TChar*)"\\Device\\HarddiskVolume2\\Program Files\\App0\\bin\\crypt.exe"
                             : (const TChar*)"\\Device\\HarddiskVolume2\\Program Files\\SafeApp\\bin\\clean.exe";
    }
    else
    {
        pwszTargetPath = bExpectMatch
                             ? (const TChar*)L"\\Device\\HarddiskVolume2\\Program Files\\App0\\bin\\crypt.exe"
                             : (const TChar*)L"\\Device\\HarddiskVolume2\\Program Files\\SafeApp\\bin\\clean.exe";
    }

    size_t cchPathLen = KStringLength(pwszTargetPath);

    LOG_INFO("\n[SPM_TEST] --- Perf Test [%s]: %s [%u Patterns | Text: %u Chars] ---\n", pszCharType, pszTestName, ulPatternCount, static_cast<ULONG>(cchPathLen));
    LOG_INFO("[SPM_TEST]      %s\n", pszDescription);
    LOG_INFO("[SPM_TEST]      Pattern Type: %s\n", psPatternType);
    LOG_INFO("[SPM_TEST]      ------------------------------------------------------------------------------------\n");
    LOG_INFO("[SPM_TEST]      %-18s | %-15s | %-15s | %-15s\n", "Engine Mode", "Throughput", "Ops/sec", "Latency/Op");
    LOG_INFO("[SPM_TEST]      ------------------------------------------------------------------------------------\n");

    LARGE_INTEGER liFreq;
    KeQueryPerformanceCounter(&liFreq);

    auto RunMode = [&](BOOLEAN bMatchFirst, const char* label) -> BOOLEAN
    {
        if (InterlockedCompareExchange(&g_lAbortTests, 0, 0)) [[unlikely]]
        {
            return FALSE;
        }

        PerfWorkerCtx<TChar> Ctx = {0};
        Ctx.pSpm = &Spm;
        Ctx.pText = pwszTargetPath;
        Ctx.cchTextLen = cchPathLen;
        Ctx.liFreq = liFreq;
        Ctx.llTotalOpsPerSec = 0;
        Ctx.bUseMatchFirst = bMatchFirst;
        Ctx.bExpectMatch = bExpectMatch;
        Ctx.lTestFailed = 0;

        TEST_THREAD_MANAGER* pMgr = (TEST_THREAD_MANAGER*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(TEST_THREAD_MANAGER), DRIVER_TAG);

        if (pMgr) [[likely]]
        {
            StartThreads(pMgr, 1, PerfWorkerT<TChar>, &Ctx);

            LARGE_INTEGER liDelay;
            liDelay.QuadPart = -2000000LL;
            KeDelayExecutionThread(KernelMode, FALSE, &liDelay);

            InterlockedExchange(&Ctx.lStartFlag, 1);
            
            // Wait for threads to clean up (time taken here no longer corrupts the math)
            StopAndWaitThreads(pMgr, 2);            

            if (Ctx.lTestFailed) [[unlikely]]
            {
                LOG_ERR("[SPM_TEST]      %-18s | [!] FAILED: Unexpected Result (Expected %d, Actual %ld)\n", label, bExpectMatch, Ctx.lActualResult);
                InterlockedExchange(&g_lAbortTests, 1);

                ExFreePoolWithTag(pMgr, DRIVER_TAG);
                return FALSE;
            }
            else
            {
                // Retrieve the purely isolated ops/sec from the threads
                UINT64 opsPerSec = static_cast<UINT64>(Ctx.llTotalOpsPerSec);
                
                // Calculate Physical Stream Ingestion Bandwidth
                UINT64 bytesPerOp = static_cast<UINT64>(cchPathLen) * sizeof(TChar);
                UINT64 bytesPerSec = opsPerSec * bytesPerOp;
                UINT64 mbWhole = bytesPerSec / (1024ULL * 1024ULL);

                // High precision latency calculation factoring in true thread parallelism
                UINT64 totalPs = opsPerSec > 0 ? ((1000000000000ULL * (pMgr->ulThreadCount > 0 ? pMgr->ulThreadCount : 1)) / opsPerSec) : 0;
                UINT64 usWhole = totalPs / 1000000;
                UINT64 usFrac = (totalPs % 1000000) / 100;

                // Format with two decimal fraction places if throughput is below 1 MB/s
                if (mbWhole < 1)
                {
                    UINT64 mbFrac = ((bytesPerSec % (1024ULL * 1024ULL)) * 100ULL) / (1024ULL * 1024ULL);
                    LOG_INFO("[SPM_TEST]      %-18s | %7llu.%02llu MB/s | %15llu | %9llu.%04llu us\n", label, mbWhole, mbFrac, opsPerSec, usWhole, usFrac);
                }
                else
                {
                    LOG_INFO("[SPM_TEST]      %-18s | %10llu MB/s | %15llu | %9llu.%04llu us\n", label, mbWhole, opsPerSec, usWhole, usFrac);
                }

                ExFreePoolWithTag(pMgr, DRIVER_TAG);
                return TRUE;
            }
        }

        return FALSE;
    };

    if (RunMode(FALSE, "MatchAll")) [[likely]]
    {
        RunMode(TRUE, "MatchFirst");
    }
    else
    {
        bTierSuccess = FALSE;
    }

    ExFreePoolWithTag(pStrArray, DRIVER_TAG);

    return bTierSuccess;
}

// -------------------------------------------------------------------------------------
// Validates complex meaningful strings surrounded by wildcard operators.
// -------------------------------------------------------------------------------------
template <typename TChar>
BOOLEAN RunMeaningfulTextPerformanceTier(_In_ ULONG       ulPatternCount,
                                         _In_ ULONG       ulTextLenChars,
                                         _In_ BOOLEAN     bExpectMatch,
                                         _In_ BOOLEAN     bCaseInsensitive,
                                         _In_ const char* pszTestName,
                                         _In_ const char* pszDescription,
                                         _In_ const char* psPatternType,
                                         _In_ const char* pszCharType)
{
    PAGED_CODE();

    if (InterlockedCompareExchange(&g_lAbortTests, 0, 0)) [[unlikely]]
    {
        return FALSE;
    }

    KmStringPatternMatch<PatternContext, TChar> Spm(bCaseInsensitive);
    BOOLEAN bTierSuccess = TRUE;

    // Meaningful prose context to exercise realistic string density dynamically selected by char size
    const TChar* pwszMeaningfulText;
    if constexpr (sizeof(TChar) == 1)
    {
        pwszMeaningfulText = (const TChar*)"The Windows Kernel memory manager employs aggressive demand paging and lookaside lists to satisfy pool allocations efficiently. ";
    }
    else
    {
        pwszMeaningfulText = (const TChar*)L"The Windows Kernel memory manager employs aggressive demand paging and lookaside lists to satisfy pool allocations efficiently. ";
    }

    size_t cchSnippetLen = KStringLength(pwszMeaningfulText);

    TChar* pwsText = (TChar*)ExAllocatePool2(POOL_FLAG_PAGED, (ulTextLenChars + 1) * sizeof(TChar), DRIVER_TAG);

    if (!pwsText) [[unlikely]]
    {
        return FALSE;
    }

    for (ULONG i = 0; i < ulTextLenChars; i++)
    {
        pwsText[i] = pwszMeaningfulText[i % cchSnippetLen];
    }

    pwsText[ulTextLenChars] = static_cast<TChar>('\0');

    TChar* pStrArray = (TChar*)ExAllocatePool2(POOL_FLAG_PAGED, ulPatternCount * 128 * sizeof(TChar), DRIVER_TAG);

    if (!pStrArray) [[unlikely]]
    {
        ExFreePoolWithTag(pwsText, DRIVER_TAG);
        return FALSE;
    }

    for (ULONG i = 0; i < ulPatternCount; i++)
    {
        if (bExpectMatch)
        {
            if constexpr (sizeof(TChar) == 1)
            {
                sprintf_s((char*)&pStrArray[i * 128], 128, "*allocation*%u*", (int)i);
            }
            else
            {
                swprintf_s((wchar_t*)&pStrArray[i * 128], 128, L"*allocation*%u*", (int)i);
            }
        }
        else
        {
            if constexpr (sizeof(TChar) == 1)
            {
                sprintf_s((char*)&pStrArray[i * 128], 128, "*random*notfound*%u*", (int)i);
            }
            else
            {
                swprintf_s((wchar_t*)&pStrArray[i * 128], 128, L"*random*notfound*%u*", (int)i);
            }
        }

        // Ensure at least one known good pattern matches if we expect a match
        if (bExpectMatch && i == ulPatternCount - 1)
        {
            if constexpr (sizeof(TChar) == 1)
            {
                sprintf_s((char*)&pStrArray[i * 128], 128, "*allocation*");
            }
            else
            {
                swprintf_s((wchar_t*)&pStrArray[i * 128], 128, L"*allocation*");
            }
        }

        PatternContext ctx = {i};

        if (!NT_SUCCESS(Spm.AddPattern(&pStrArray[i * 128], static_cast<UINT32>(KStringLength(&pStrArray[i * 128])), SCOPE_DEFAULT, kstd::move(ctx)))) [[unlikely]]
        {
            ExFreePoolWithTag(pStrArray, DRIVER_TAG);
            ExFreePoolWithTag(pwsText, DRIVER_TAG);
            return FALSE;
        }
    }

    LOG_INFO("\n[SPM_TEST] --- Perf Test [%s]: %s [%u Patterns | Text: %u Chars] ---\n", pszCharType, pszTestName, ulPatternCount, ulTextLenChars);
    LOG_INFO("[SPM_TEST]      %s\n", pszDescription);
    LOG_INFO("[SPM_TEST]      Pattern Type: %s\n", psPatternType);
    LOG_INFO("[SPM_TEST]      ------------------------------------------------------------------------------------\n");
    LOG_INFO("[SPM_TEST]      %-18s | %-15s | %-15s | %-15s\n", "Engine Mode", "Throughput", "Ops/sec", "Latency/Op");
    LOG_INFO("[SPM_TEST]      ------------------------------------------------------------------------------------\n");

    LARGE_INTEGER liFreq;
    KeQueryPerformanceCounter(&liFreq);

    auto RunMode = [&](BOOLEAN bMatchFirst, const char* label) -> BOOLEAN
    {
        if (InterlockedCompareExchange(&g_lAbortTests, 0, 0)) [[unlikely]]
        {
            return FALSE;
        }

        PerfWorkerCtx<TChar> Ctx = {0};
        Ctx.pSpm = &Spm;
        Ctx.pText = pwsText;
        Ctx.cchTextLen = ulTextLenChars;
        Ctx.liFreq = liFreq;
        Ctx.llTotalOpsPerSec = 0;
        Ctx.bUseMatchFirst = bMatchFirst;
        Ctx.bExpectMatch = bExpectMatch;
        Ctx.lTestFailed = 0;

        TEST_THREAD_MANAGER* pMgr = (TEST_THREAD_MANAGER*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(TEST_THREAD_MANAGER), DRIVER_TAG);

        if (pMgr) [[likely]]
        {
            StartThreads(pMgr, 1, PerfWorkerT<TChar>, &Ctx);

            LARGE_INTEGER liDelay;
            liDelay.QuadPart = -2000000LL;
            KeDelayExecutionThread(KernelMode, FALSE, &liDelay);

            InterlockedExchange(&Ctx.lStartFlag, 1);
            
            // Wait for threads to clean up (time taken here no longer corrupts the math)
            StopAndWaitThreads(pMgr, 2);            

            if (Ctx.lTestFailed) [[unlikely]]
            {
                LOG_ERR("[SPM_TEST]      %-18s | [!] FAILED: Unexpected Result (Expected %d, Actual %ld)\n", label, bExpectMatch, Ctx.lActualResult);
                InterlockedExchange(&g_lAbortTests, 1);

                ExFreePoolWithTag(pMgr, DRIVER_TAG);
                return FALSE;
            }
            else
            {
                // Retrieve the purely isolated ops/sec from the threads
                UINT64 opsPerSec = static_cast<UINT64>(Ctx.llTotalOpsPerSec);
                
                // Calculate Physical Stream Ingestion Bandwidth
                UINT64 bytesPerOp = static_cast<UINT64>(ulTextLenChars) * sizeof(TChar);
                UINT64 bytesPerSec = opsPerSec * bytesPerOp;
                UINT64 mbWhole = bytesPerSec / (1024ULL * 1024ULL);

                // High precision latency calculation factoring in true thread parallelism
                UINT64 totalPs = opsPerSec > 0 ? ((1000000000000ULL * (pMgr->ulThreadCount > 0 ? pMgr->ulThreadCount : 1)) / opsPerSec) : 0;
                UINT64 usWhole = totalPs / 1000000;
                UINT64 usFrac = (totalPs % 1000000) / 100;

                // Format with two decimal fraction places if throughput is below 1 MB/s
                if (mbWhole < 1)
                {
                    UINT64 mbFrac = ((bytesPerSec % (1024ULL * 1024ULL)) * 100ULL) / (1024ULL * 1024ULL);
                    LOG_INFO("[SPM_TEST]      %-18s | %7llu.%02llu MB/s | %15llu | %9llu.%04llu us\n", label, mbWhole, mbFrac, opsPerSec, usWhole, usFrac);
                }
                else
                {
                    LOG_INFO("[SPM_TEST]      %-18s | %10llu MB/s | %15llu | %9llu.%04llu us\n", label, mbWhole, opsPerSec, usWhole, usFrac);
                }

                ExFreePoolWithTag(pMgr, DRIVER_TAG);
                return TRUE;
            }
        }

        return FALSE;
    };

    if (RunMode(FALSE, "MatchAll")) [[likely]]
    {
        RunMode(TRUE, "MatchFirst");
    }
    else
    {
        bTierSuccess = FALSE;
    }

    ExFreePoolWithTag(pStrArray, DRIVER_TAG);
    ExFreePoolWithTag(pwsText, DRIVER_TAG);

    return bTierSuccess;
}

// -------------------------------------------------------------------------------------
// Benchmarks purely exact string matching with no wildcards.
// -------------------------------------------------------------------------------------
template <typename TChar>
BOOLEAN RunExactStringPerformanceTier(_In_ ULONG       ulPatternCount,
                                      _In_ ULONG       ulTextLenChars,
                                      _In_ BOOLEAN     bExpectMatch,
                                      _In_ BOOLEAN     bCaseInsensitive,
                                      _In_ const char* pszTestName,
                                      _In_ const char* pszDescription,
                                      _In_ const char* psPatternType,
                                      _In_ const char* pszCharType)
{
    PAGED_CODE();

    if (InterlockedCompareExchange(&g_lAbortTests, 0, 0)) [[unlikely]]
    {
        return FALSE;
    }

    KmStringPatternMatch<PatternContext, TChar> Spm(bCaseInsensitive);
    BOOLEAN bTierSuccess = TRUE;

    const SIZE_T cbTextMap = static_cast<SIZE_T>(ulTextLenChars) * sizeof(TChar) + sizeof(TChar);
    TChar* pwsText = (TChar*)ExAllocatePool2(POOL_FLAG_PAGED, cbTextMap, DRIVER_TAG);

    if (!pwsText) [[unlikely]]
    {
        return FALSE;
    }

    for (ULONG i = 0; i < ulTextLenChars; i++)
    {
        pwsText[i] = static_cast<TChar>('A' + (i % 26));
    }

    pwsText[ulTextLenChars] = static_cast<TChar>('\0');

    const SIZE_T cbPatternArray = static_cast<SIZE_T>(ulPatternCount) * cbTextMap;
    TChar* pStrArray = (TChar*)ExAllocatePool2(POOL_FLAG_PAGED, cbPatternArray, DRIVER_TAG);

    if (!pStrArray) [[unlikely]]
    {
        ExFreePoolWithTag(pwsText, DRIVER_TAG);
        return FALSE;
    }

    for (ULONG i = 0; i < ulPatternCount; i++)
    {
        TChar* pCurPat = &pStrArray[i * (ulTextLenChars + 1)];

        memcpy(pCurPat, pwsText, cbTextMap);

        if (!bExpectMatch || i != (ulPatternCount - 1))
        {
            if (ulTextLenChars > 0)
            {
                pCurPat[ulTextLenChars / 2] = static_cast<TChar>('X');
            }
        }

        PatternContext ctx = {i};

        if (!NT_SUCCESS(Spm.AddPattern(pCurPat, static_cast<UINT32>(KStringLength(pCurPat)), SCOPE_DEFAULT, kstd::move(ctx)))) [[unlikely]]
        {
            ExFreePoolWithTag(pStrArray, DRIVER_TAG);
            ExFreePoolWithTag(pwsText, DRIVER_TAG);
            return FALSE;
        }
    }

    LOG_INFO("\n[SPM_TEST] --- Perf Test [%s]: %s [%u Patterns | Text: %u Chars] ---\n", pszCharType, pszTestName, ulPatternCount, ulTextLenChars);
    LOG_INFO("[SPM_TEST]      %s\n", pszDescription);
    LOG_INFO("[SPM_TEST]      Pattern Type: %s\n", psPatternType);
    LOG_INFO("[SPM_TEST]      ------------------------------------------------------------------------------------\n");
    LOG_INFO("[SPM_TEST]      %-18s | %-15s | %-15s | %-15s\n", "Engine Mode", "Throughput", "Ops/sec", "Latency/Op");
    LOG_INFO("[SPM_TEST]      ------------------------------------------------------------------------------------\n");

    LARGE_INTEGER liFreq;
    KeQueryPerformanceCounter(&liFreq);

    auto RunMode = [&](BOOLEAN bMatchFirst, const char* label) -> BOOLEAN
    {
        if (InterlockedCompareExchange(&g_lAbortTests, 0, 0)) [[unlikely]]
        {
            return FALSE;
        }

        PerfWorkerCtx<TChar> Ctx = {0};
        Ctx.pSpm = &Spm;
        Ctx.pText = pwsText;
        Ctx.cchTextLen = ulTextLenChars;
        Ctx.liFreq = liFreq;
        Ctx.llTotalOpsPerSec = 0;
        Ctx.bUseMatchFirst = bMatchFirst;
        Ctx.bExpectMatch = bExpectMatch;
        Ctx.lTestFailed = 0;

        TEST_THREAD_MANAGER* pMgr = (TEST_THREAD_MANAGER*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(TEST_THREAD_MANAGER), DRIVER_TAG);

        if (pMgr) [[likely]]
        {
            StartThreads(pMgr, 1, PerfWorkerT<TChar>, &Ctx);

            LARGE_INTEGER liDelay;
            liDelay.QuadPart = -2000000LL;
            KeDelayExecutionThread(KernelMode, FALSE, &liDelay);

            InterlockedExchange(&Ctx.lStartFlag, 1);
            
            // Wait for threads to clean up (time taken here no longer corrupts the math)
            StopAndWaitThreads(pMgr, 2);            

            if (Ctx.lTestFailed) [[unlikely]]
            {
                LOG_ERR("[SPM_TEST]      %-18s | [!] FAILED: Unexpected Result (Expected %d, Actual %ld)\n", label, bExpectMatch, Ctx.lActualResult);
                InterlockedExchange(&g_lAbortTests, 1);

                ExFreePoolWithTag(pMgr, DRIVER_TAG);
                return FALSE;
            }
            else
            {
                // Retrieve the purely isolated ops/sec from the threads
                UINT64 opsPerSec = static_cast<UINT64>(Ctx.llTotalOpsPerSec);
                
                // Calculate Physical Stream Ingestion Bandwidth
                UINT64 bytesPerOp = static_cast<UINT64>(ulTextLenChars) * sizeof(TChar);
                UINT64 bytesPerSec = opsPerSec * bytesPerOp;
                UINT64 mbWhole = bytesPerSec / (1024ULL * 1024ULL);

                // High precision latency calculation factoring in true thread parallelism
                UINT64 totalPs = opsPerSec > 0 ? ((1000000000000ULL * (pMgr->ulThreadCount > 0 ? pMgr->ulThreadCount : 1)) / opsPerSec) : 0;
                UINT64 usWhole = totalPs / 1000000;
                UINT64 usFrac = (totalPs % 1000000) / 100;

                // Format with two decimal fraction places if throughput is below 1 MB/s
                if (mbWhole < 1)
                {
                    UINT64 mbFrac = ((bytesPerSec % (1024ULL * 1024ULL)) * 100ULL) / (1024ULL * 1024ULL);
                    LOG_INFO("[SPM_TEST]      %-18s | %7llu.%02llu MB/s | %15llu | %9llu.%04llu us\n", label, mbWhole, mbFrac, opsPerSec, usWhole, usFrac);
                }
                else
                {
                    LOG_INFO("[SPM_TEST]      %-18s | %10llu MB/s | %15llu | %9llu.%04llu us\n", label, mbWhole, opsPerSec, usWhole, usFrac);
                }

                ExFreePoolWithTag(pMgr, DRIVER_TAG);
                return TRUE;
            }
        }

        return FALSE;
    };

    if (RunMode(FALSE, "MatchAll")) [[likely]]
    {
        RunMode(TRUE, "MatchFirst");
    }
    else
    {
        bTierSuccess = FALSE;
    }

    ExFreePoolWithTag(pStrArray, DRIVER_TAG);
    ExFreePoolWithTag(pwsText, DRIVER_TAG);

    return bTierSuccess;
}

// -------------------------------------------------------------------------------------
// Unified helper wrapping boilerplate execution of performance tiers for any text base.
// -------------------------------------------------------------------------------------
template <typename TChar>
VOID ExecutePerformanceTiers(_Inout_ ULONG&      ulPassed,
                             _Inout_ ULONG&      ulFailed,
                             _In_    const char* pszCharType)
{
    auto CheckTest = [&](BOOLEAN bResult)
    {
        // If the global abort flag is set due to a catastrophic perf test logic failure, exit the block.
        if (InterlockedCompareExchange(&g_lAbortTests, 0, 0)) [[unlikely]]
        {
            return;
        }

        if (bResult) [[likely]]
        {
            ulPassed++;
        }
        else
        {
            ulFailed++;
        }
    };

    CheckTest(RunPerformanceTier<TChar>(10, 512, TRUE, TRUE, TRUE, "Small Pathological", "Evaluates throughput against a saturated set of short pathological wildcard rules.", "Pathological (*A%dB*)", pszCharType));

    CheckTest(RunPerformanceTier<TChar>(100, 10240, TRUE, TRUE, TRUE, "Medium Pathological", "Evaluates throughput against a saturated set of medium pathological wildcard rules.", "Pathological (*A%dB*)", pszCharType));

    CheckTest(RunPerformanceTier<TChar>(1000, 102400, TRUE, TRUE, TRUE, "Large Pathological", "Evaluates throughput against a saturated set of long pathological wildcard rules.", "Pathological (*A%dB*)", pszCharType));

    CheckTest(RunPerformanceTier<TChar>(100, 10240, TRUE, FALSE, TRUE, "Negative Mismatch", "Tests engine behavior when no patterns match the target string.", "Pathological (*A%dB*)", pszCharType));

    CheckTest(RunRealisticPathPerformanceTier<TChar>(10, TRUE, TRUE, "Realistic Paths", "Benchmarks against a small set of typical kernel file paths.", "File Paths (\\Device\\...)", pszCharType));

    CheckTest(RunRealisticPathPerformanceTier<TChar>(100, TRUE, TRUE, "Realistic Paths", "Benchmarks against a medium set of typical kernel file paths.", "File Paths (\\Device\\...)", pszCharType));

    CheckTest(RunRealisticPathPerformanceTier<TChar>(1000, TRUE, TRUE, "Realistic Paths", "Benchmarks against a massive set of typical kernel file paths.", "File Paths (\\Device\\...)", pszCharType));

    CheckTest(RunRealisticPathPerformanceTier<TChar>(10000, TRUE, TRUE, "Realistic Paths", "Benchmarks against a massive set of typical kernel file paths.", "File Paths (\\Device\\...)", pszCharType));

    CheckTest(RunRealisticPathPerformanceTier<TChar>(1000, FALSE, TRUE, "Negative Paths", "Tests engine behavior when no paths match the target.", "File Paths (\\Device\\...)", pszCharType));

    CheckTest(RunMeaningfulTextPerformanceTier<TChar>(100, 1024, TRUE, TRUE, "Meaningful Text", "Simulates 1KB real-world prose with multi-wildcard boundaries.", "Prose Boundaries (*xxx*)", pszCharType));

    CheckTest(RunMeaningfulTextPerformanceTier<TChar>(100, 10240, TRUE, TRUE, "Meaningful Text", "Simulates 10KB real-world prose with multi-wildcard boundaries.", "Prose Boundaries (*xxx*)", pszCharType));

    CheckTest(RunMeaningfulTextPerformanceTier<TChar>(100, 102400, TRUE, TRUE, "Meaningful Text", "Simulates 100KB real-world prose with multi-wildcard boundaries.", "Prose Boundaries (*xxx*)", pszCharType));

    CheckTest(RunMeaningfulTextPerformanceTier<TChar>(100, 102400, FALSE, TRUE, "Meaningful Negative", "Tests mismatch behavior on 100KB real-world prose context.", "Prose Boundaries (*xxx*)", pszCharType));

    CheckTest(RunMeaningfulTextPerformanceTier<TChar>(100, 102400, TRUE, FALSE, "Case-Sensitive Prose", "Simulates 100KB prose utilizing raw character evaluations.", "Prose Boundaries (*xxx*)", pszCharType));

    CheckTest(RunExactStringPerformanceTier<TChar>(10, 128, TRUE, TRUE, "Exact String", "Simulates 128-char text with exact string matching.", "Exact Literal (No Wildcards)", pszCharType));

    CheckTest(RunExactStringPerformanceTier<TChar>(100, 128, TRUE, TRUE, "Exact String", "Simulates 128-char text with exact string matching.", "Exact Literal (No Wildcards)", pszCharType));

    CheckTest(RunExactStringPerformanceTier<TChar>(1000, 128, TRUE, TRUE, "Exact String", "Simulates 128-char text with exact string matching.", "Exact Literal (No Wildcards)", pszCharType));

    CheckTest(RunExactStringPerformanceTier<TChar>(10000, 128, TRUE, TRUE, "Exact String", "Simulates 128-char text with exact string matching.", "Exact Literal (No Wildcards)", pszCharType));

    CheckTest(RunExactStringPerformanceTier<TChar>(100, 128, TRUE, FALSE, "Exact String Negative", "Tests mismatch behavior on 128-char exact string context.", "Exact Literal (No Wildcards)", pszCharType));

    CheckTest(RunExactStringPerformanceTier<TChar>(10, 256, TRUE, TRUE, "Exact String", "Simulates 256-char text with exact string matching.", "Exact Literal (No Wildcards)", pszCharType));

    CheckTest(RunExactStringPerformanceTier<TChar>(100, 256, TRUE, TRUE, "Exact String", "Simulates 256-char text with exact string matching.", "Exact Literal (No Wildcards)", pszCharType));

    CheckTest(RunExactStringPerformanceTier<TChar>(1000, 256, TRUE, TRUE, "Exact String", "Simulates 256-char text with exact string matching.", "Exact Literal (No Wildcards)", pszCharType));
    
    CheckTest(RunExactStringPerformanceTier<TChar>(10000, 256, TRUE, TRUE, "Exact String", "Simulates 256-char text with exact string matching.", "Exact Literal (No Wildcards)", pszCharType));

    CheckTest(RunExactStringPerformanceTier<TChar>(100, 256, FALSE, TRUE, "Exact String Negative", "Tests mismatch behavior on 256-char exact string context.", "Exact Literal (No Wildcards)", pszCharType));
}

// -------------------------------------------------------------------------------------
// Orchestrates all performance test tiers for both char strings.
// -------------------------------------------------------------------------------------
VOID RunAllPerformanceTests()
{
    PAGED_CODE();

    LOG_INFO("\n[SPM_TEST] =========================================================================================\n");
    LOG_INFO("[SPM_TEST] --- Performance Tests (Throughput) ---\n");
    LOG_INFO("[SPM_TEST] =========================================================================================\n");

    ULONG ulPassed = 0;
    ULONG ulFailed = 0;

    ExecutePerformanceTiers<WCHAR>(ulPassed, ulFailed, "WCHAR");
    ExecutePerformanceTiers<CHAR>(ulPassed, ulFailed, "CHAR");

    if (InterlockedCompareExchange(&g_lAbortTests, 0, 0)) [[unlikely]]
    {
        LOG_ERR("\n[SPM_TEST] [!] PERFORMANCE SUITE ABORTED DUE TO CRITICAL THREAD LOGIC FAILURE\n");
    }
    else if (ulFailed == 0) [[likely]]
    {
        LOG_INFO("\n[SPM_TEST] [+] ALL PERFORMANCE TESTS SUCCEEDED (%u passed)\n", ulPassed);
    }
    else
    {
        LOG_ERR("\n[SPM_TEST] [!] SOME PERFORMANCE TESTS FAILED (%u passed, %u failed)\n", ulPassed, ulFailed);
    }
}

// -------------------------------------------------------------------------------------
// Main routine that bootstraps all correctness checks and triggers performance evaluation.
// -------------------------------------------------------------------------------------
VOID RunTests(_In_opt_ PVOID pContext)
{
    PAGED_CODE();

    TEST_SUITE_CONFIG* pConfig = (TEST_SUITE_CONFIG*)pContext;

    KeSetPriorityThread(KeGetCurrentThread(), 2);

    LOG_INFO("\n[SPM_TEST] =========================================================================================\n");
    LOG_INFO("[SPM_TEST]          KMSTRINGPATTERNMATCH UNIFIED TEST SUITE\n");
    LOG_INFO("[SPM_TEST] =========================================================================================\n");

    // Correctness checks are always prioritized before executing expensive bandwidth operations
    if (pConfig && pConfig->bRunCorrectness) [[likely]]
    {
        RunAllCorrectnessTests();
    }

    if (pConfig && pConfig->bRunPerformance) [[likely]]
    {
        RunAllPerformanceTests();
    }

    LOG_INFO("\n[SPM_TEST] --- All Tests Finished ---\n\n");

    FlushLogToFile();
    PsTerminateSystemThread(STATUS_SUCCESS);
}
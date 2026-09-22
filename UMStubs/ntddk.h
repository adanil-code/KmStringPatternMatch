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

#pragma once
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <malloc.h>
#include <cwctype>

// Bring in Windows UM APIs to mock KM concurrency and atomic stubs
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>

// -------------------------------------------------------------------------------------
// Core Types & Constants
// -------------------------------------------------------------------------------------
typedef int32_t  NTSTATUS;
typedef uint64_t UINT64;
typedef uint64_t ULONG64;
typedef uint64_t POOL_FLAGS;
// ULONG, SIZE_T, UCHAR, BOOLEAN, LONG, LONG64 are inherently provided by <windows.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                0x00000000
#endif
#ifndef STATUS_INSUFFICIENT_RESOURCES
#define STATUS_INSUFFICIENT_RESOURCES 0xC000009A
#endif
#ifndef STATUS_QUOTA_EXCEEDED
#define STATUS_QUOTA_EXCEEDED         0xC0000044
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status)            (((NTSTATUS)(Status)) >= 0)
#endif

#define POOL_FLAG_UNINITIALIZED       0x0000000200000000ull
#define POOL_FLAG_CACHE_ALIGNED       0x0000000400000000ull
#define POOL_FLAG_PAGED               0x0000000800000000ull
#define POOL_FLAG_NON_PAGED           0x0000020000000000ull

// -------------------------------------------------------------------------------------
// Environment & IRQL Mocks
// -------------------------------------------------------------------------------------
#define PAGED_CODE()
#define COMPILER_BARRIER()            _ReadWriteBarrier()
#define KeGetCurrentIrql()            0
#define DISPATCH_LEVEL                2
#define PASSIVE_LEVEL                 0

// -------------------------------------------------------------------------------------
// Logging & Assertions
// -------------------------------------------------------------------------------------
#define ASSERTMSG(msg, exp) \
    do { \
        if (!(exp)) { \
            std::cerr << "ASSERTION FAILED: " << msg << '\n'; \
            std::abort(); \
        } \
    } while (0)

#define LOG_INFO(...) printf(__VA_ARGS__)
#define LOG_ERR(...)  printf(__VA_ARGS__)

// -------------------------------------------------------------------------------------
// Memory Management Stubs
// -------------------------------------------------------------------------------------

//--------------------------------------------------------------------------------
// Allocates memory from the kernel pool. Uses aligned UM malloc as a stub.
//--------------------------------------------------------------------------------
inline void* ExAllocatePool2(_In_ POOL_FLAGS Flags,
                             _In_ SIZE_T     Size,
                             _In_ ULONG      Tag)
{
    UNREFERENCED_PARAMETER(Tag);
    
    // Determine requested alignment: 64 bytes for CACHE_ALIGNED, standard 16 bytes otherwise
    SIZE_T alignment = (Flags & POOL_FLAG_CACHE_ALIGNED) ? 64 : 16;
    
    // Use _aligned_malloc universally so that _aligned_free can safely be used in ExFreePoolWithTag
    void* p = _aligned_malloc(Size, alignment);    
    if (p != nullptr)
    {
        // ExAllocatePool2 zero-initializes memory by default unless explicitly opted out
        if ((Flags & POOL_FLAG_UNINITIALIZED) == 0)
        {
            std::memset(p, 0, Size);
        }
    }
    
    return p;
}

//--------------------------------------------------------------------------------
// Frees previously allocated kernel pool memory.
//--------------------------------------------------------------------------------
inline void ExFreePoolWithTag(_In_ void* Ptr,
                              _In_ ULONG Tag)
{
    UNREFERENCED_PARAMETER(Tag);
    
    if (Ptr != nullptr)
    {
        _aligned_free(Ptr);
    }
}

// Clear UM macros to prevent collision C2365 before generating KM function mocks
#undef RtlZeroMemory
#undef RtlCopyMemory
#undef RtlMoveMemory

//--------------------------------------------------------------------------------
// Fills a block of memory with zeros.
//--------------------------------------------------------------------------------
inline void RtlZeroMemory(_Out_writes_bytes_all_(Size) void*  Dest,
                          _In_                         SIZE_T Size) 
{ 
    std::memset(Dest, 0, Size); 
}

//--------------------------------------------------------------------------------
// Copies memory from source to destination (non-overlapping).
//--------------------------------------------------------------------------------
inline void RtlCopyMemory(_Out_writes_bytes_all_(Size) void*       Dest,
                          _In_reads_bytes_(Size)       const void* Src,
                          _In_                         SIZE_T      Size) 
{ 
    std::memcpy(Dest, Src, Size); 
}

//--------------------------------------------------------------------------------
// Moves memory from source to destination, supporting overlapping buffers.
//--------------------------------------------------------------------------------
inline void RtlMoveMemory(_Out_writes_bytes_all_(Size) void*       Dest,
                          _In_reads_bytes_(Size)       const void* Src,
                          _In_                         SIZE_T      Size) 
{ 
    std::memmove(Dest, Src, Size); 
}

//--------------------------------------------------------------------------------
// Converts a wide character to its uppercase equivalent.
//--------------------------------------------------------------------------------
inline WCHAR RtlUpcaseUnicodeChar(_In_ WCHAR Char) 
{ 
    return (WCHAR)std::towupper(Char); 
}

//--------------------------------------------------------------------------------
// Converts a single-byte character to its uppercase equivalent.
//--------------------------------------------------------------------------------
inline CHAR RtlUpperChar(_In_ CHAR Char) 
{ 
    return (CHAR)std::toupper(Char); 
}

// -------------------------------------------------------------------------------------
// Concurrency & Threading Mocks (Bridged to User Mode Win32)
// -------------------------------------------------------------------------------------
typedef HANDLE PETHREAD;
typedef ULONG  KPRIORITY;
typedef ULONG  KPROCESSOR_MODE;
typedef ULONG  EVENT_TYPE;
typedef ULONG  KWAIT_REASON;
typedef void*  POBJECT_ATTRIBUTES;
typedef void*  PCLIENT_ID;

#define NotificationEvent    0
#define SynchronizationEvent 1
#define KernelMode           0
#define Executive            0
#define IO_NO_INCREMENT      0

typedef VOID (__stdcall *PKSTART_ROUTINE)(PVOID StartContext);

// Wrapping event handles in a distinct struct so C++ template resolution 
// can differentiate between waitable Objects and bare Handles.
struct KEVENT 
{
    HANDLE hEvent;
};
typedef KEVENT* PKEVENT;

//--------------------------------------------------------------------------------
// Initializes a kernel dispatcher event object.
//--------------------------------------------------------------------------------
inline VOID KeInitializeEvent(_Out_ PKEVENT    Event,
                              _In_  EVENT_TYPE Type,
                              _In_  BOOLEAN    State)
{
    Event->hEvent = CreateEventW(NULL, (Type == NotificationEvent), State, NULL);
}

//--------------------------------------------------------------------------------
// Sets an event to the signaled state.
//--------------------------------------------------------------------------------
inline VOID KeSetEvent(_Inout_ PKEVENT   Event,
                       _In_    KPRIORITY Increment,
                       _In_    BOOLEAN   Wait)
{
    UNREFERENCED_PARAMETER(Increment);
    UNREFERENCED_PARAMETER(Wait);
    SetEvent(Event->hEvent);
}

//--------------------------------------------------------------------------------
// Generic Dispatcher resolution for Thread Handles (blocks until signaled).
//--------------------------------------------------------------------------------
template <typename T>
inline NTSTATUS KeWaitForSingleObject(_In_     T               Object,
                                      _In_     KWAIT_REASON    WaitReason,
                                      _In_     KPROCESSOR_MODE WaitMode,
                                      _In_     BOOLEAN         Alertable,
                                      _In_opt_ PLARGE_INTEGER  Timeout)
{
    UNREFERENCED_PARAMETER(WaitReason);
    UNREFERENCED_PARAMETER(WaitMode);
    UNREFERENCED_PARAMETER(Alertable);

    DWORD dwMilliseconds = INFINITE;
    if (Timeout)
    {
        // KM Timeout is in 100-ns intervals. Negative means relative timeout.
        dwMilliseconds = (DWORD)(-Timeout->QuadPart / 10000LL);
    }
    
    WaitForSingleObject((HANDLE)Object, dwMilliseconds);
    return STATUS_SUCCESS;
}

//--------------------------------------------------------------------------------
// Disambiguation specialization specifically for Event structures.
//--------------------------------------------------------------------------------
template <>
inline NTSTATUS KeWaitForSingleObject<PKEVENT>(_In_     PKEVENT         Object,
                                               _In_     KWAIT_REASON    WaitReason,
                                               _In_     KPROCESSOR_MODE WaitMode,
                                               _In_     BOOLEAN         Alertable,
                                               _In_opt_ PLARGE_INTEGER  Timeout)
{
    UNREFERENCED_PARAMETER(WaitReason);
    UNREFERENCED_PARAMETER(WaitMode);
    UNREFERENCED_PARAMETER(Alertable);

    DWORD dwMilliseconds = INFINITE;
    if (Timeout)
    {
        dwMilliseconds = (DWORD)(-Timeout->QuadPart / 10000LL);
    }
    
    WaitForSingleObject(Object->hEvent, dwMilliseconds);
    return STATUS_SUCCESS;
}

//--------------------------------------------------------------------------------
// Spawns a dedicated system thread executing in kernel mode.
//--------------------------------------------------------------------------------
inline NTSTATUS PsCreateSystemThread(_Out_     PHANDLE            ThreadHandle,
                                     _In_      ULONG              DesiredAccess,
                                     _In_opt_  POBJECT_ATTRIBUTES ObjectAttributes,
                                     _In_opt_  HANDLE             ProcessHandle,
                                     _Out_opt_ PCLIENT_ID         ClientId,
                                     _In_      PKSTART_ROUTINE    StartRoutine,
                                     _In_opt_  PVOID              StartContext)
{
    UNREFERENCED_PARAMETER(DesiredAccess);
    UNREFERENCED_PARAMETER(ObjectAttributes);
    UNREFERENCED_PARAMETER(ProcessHandle);
    UNREFERENCED_PARAMETER(ClientId);

    *ThreadHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)StartRoutine, StartContext, 0, NULL);
    return (*ThreadHandle != NULL) ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
}

//--------------------------------------------------------------------------------
// Resolves a handle into its underlying kernel object pointer and references it.
//--------------------------------------------------------------------------------
inline NTSTATUS ObReferenceObjectByHandle(_In_      HANDLE          Handle,
                                          _In_      ULONG           DesiredAccess,
                                          _In_opt_  PVOID           ObjectType,
                                          _In_      KPROCESSOR_MODE AccessMode,
                                          _Out_     PVOID*          Object,
                                          _Out_opt_ PVOID           HandleInformation)
{
    UNREFERENCED_PARAMETER(DesiredAccess);
    UNREFERENCED_PARAMETER(ObjectType);
    UNREFERENCED_PARAMETER(AccessMode);
    UNREFERENCED_PARAMETER(HandleInformation);
    
    HANDLE hDup = NULL;
    if (DuplicateHandle(GetCurrentProcess(), Handle, GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS))
    {
        *Object = hDup;
        return STATUS_SUCCESS;
    }
    return STATUS_INSUFFICIENT_RESOURCES;
}

//--------------------------------------------------------------------------------
// Decrements the reference count of an object, potentially freeing it.
//--------------------------------------------------------------------------------
inline VOID ObDereferenceObject(_In_ PVOID Object)
{
    if (Object)
    {
        CloseHandle((HANDLE)Object);
    }
}

//--------------------------------------------------------------------------------
// Closes an open object handle.
//--------------------------------------------------------------------------------
inline NTSTATUS ZwClose(_In_ HANDLE Handle)
{
    if (Handle)
    {
        CloseHandle(Handle);
    }
    return STATUS_SUCCESS;
}

//--------------------------------------------------------------------------------
// Dynamically adjusts the base priority of a kernel thread.
//--------------------------------------------------------------------------------
inline VOID KeSetPriorityThread(_Inout_ PVOID     Thread,
                                _In_    KPRIORITY Priority)
{
    UNREFERENCED_PARAMETER(Priority);
    SetThreadPriority((HANDLE)Thread, THREAD_PRIORITY_HIGHEST);
}

//--------------------------------------------------------------------------------
// Delays execution of the current thread for the specified interval.
//--------------------------------------------------------------------------------
inline NTSTATUS KeDelayExecutionThread(_In_     KPROCESSOR_MODE WaitMode,
                                       _In_     BOOLEAN         Alertable,
                                       _In_opt_ PLARGE_INTEGER  Interval)
{
    UNREFERENCED_PARAMETER(WaitMode);
    UNREFERENCED_PARAMETER(Alertable);

    if (Interval && Interval->QuadPart < 0)
    {
        Sleep((DWORD)(-Interval->QuadPart / 10000LL));
    }
    return STATUS_SUCCESS;
}

//--------------------------------------------------------------------------------
// Retrieves the current value of the high-resolution performance counter.
//--------------------------------------------------------------------------------
inline LARGE_INTEGER KeQueryPerformanceCounter(_Out_opt_ PLARGE_INTEGER PerformanceFrequency)
{
    LARGE_INTEGER count;
    if (PerformanceFrequency)
    {
        QueryPerformanceFrequency(PerformanceFrequency);
    }

    QueryPerformanceCounter(&count);
    return count;
}

//--------------------------------------------------------------------------------
// Terminates the currently executing system thread.
//--------------------------------------------------------------------------------
inline VOID PsTerminateSystemThread(_In_ NTSTATUS ExitStatus)
{
    ExitThread((DWORD)ExitStatus);
}

//--------------------------------------------------------------------------------
// Returns a pointer to the currently executing thread object.
//--------------------------------------------------------------------------------
inline PVOID KeGetCurrentThread()
{
    return GetCurrentThread();
}
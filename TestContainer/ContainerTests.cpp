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

#include <iostream>
#include <iomanip>
#include <chrono>
#include <string>
#include <unordered_map>
#include <vector>
#include <deque>
#include <sstream>

#include "KVector.h"
#include "KDeque.h"
#include "KHashMap.h"

// Define assertion macro if not globally provided by the test framework
#ifndef ASSERTMSG
#define ASSERTMSG(msg, cond)                                                                     \
    do                                                                                           \
    {                                                                                            \
        if (!(cond)) [[unlikely]]                                                                \
        {                                                                                        \
            std::cerr << "\n[!] ASSERTION FAILED: " << (msg) << " | Line: " << __LINE__ << "\n"; \
            std::abort();                                                                        \
        }                                                                                        \
    } while (0)
#endif

// Macros to format test output steps
#define TEST_PHASE(name) std::cout << "  -> " << std::left << std::setw(58) << (name) << std::flush
#define TEST_PASS() std::cout << "[PASS]\n"

// ---------------------------------------------------------
// Helper Types for Testing
// ---------------------------------------------------------

//--------------------------------------------------------------------------------
// Non-trivial type to test loop-based shifts, destructors, and complex assignments.
// Evaluates correct memory lifecycle behaviors inside dynamic containers.
//--------------------------------------------------------------------------------
struct NonTrivial
{
    int Value1;
    int Value2;
    static int DestructorCount;

    NonTrivial() : Value1(0), Value2(0)
    {
    }

    NonTrivial(int V1, int V2) : Value1(V1), Value2(V2)
    {
    }

    ~NonTrivial()
    {
        DestructorCount++;
    }

    NonTrivial(const NonTrivial& Other)
    {
        Value1 = Other.Value1;
        Value2 = Other.Value2;
    }

    NonTrivial& operator=(const NonTrivial& Other)
    {
        Value1 = Other.Value1;
        Value2 = Other.Value2;
        return *this;
    }
};

int NonTrivial::DestructorCount = 0;

//--------------------------------------------------------------------------------
// Custom hasher to intentionally force extreme hash collisions.
// Used for validating linear SWAR probing and fallback mapping logic.
//--------------------------------------------------------------------------------
struct CollisionHash
{
    SIZE_T operator()(const UINT64& Key) const noexcept
    {
        (void)Key;
        return 0xDEADBEEF00000000ULL;
    }
};

//--------------------------------------------------------------------------------
// 128-bit structure to trigger the KDefaultHash 16-byte fast path.
//--------------------------------------------------------------------------------
struct alignas(16) Guid128
{
    UINT64 Part1;
    UINT64 Part2;

    bool operator==(const Guid128& Other) const
    {
        return Part1 == Other.Part1 && Part2 == Other.Part2;
    }
};

//--------------------------------------------------------------------------------
// 192-bit (24-byte) structure to trigger the KDefaultHash SWAR generic chunking
// loop for types that are not explicitly scalar or 16-byte boundaries.
//--------------------------------------------------------------------------------
struct ComplexKey
{
    UINT64 Part1;
    UINT64 Part2;
    UINT64 Part3;

    bool operator==(const ComplexKey& Other) const
    {
        return Part1 == Other.Part1 && Part2 == Other.Part2 && Part3 == Other.Part3;
    }
};

//--------------------------------------------------------------------------------
// 12-byte structure to trigger the KDefaultHash SWAR trailing byte block.
// Size is 12 bytes (12 & 7 != 0), guaranteeing the unaligned bitwise OR loop runs.
//--------------------------------------------------------------------------------
struct SwarTailKey
{
    UINT32 Part1;
    UINT32 Part2;
    UINT32 Part3;

    bool operator==(const SwarTailKey& Other) const
    {
        return Part1 == Other.Part1 && Part2 == Other.Part2 && Part3 == Other.Part3;
    }
};

// ---------------------------------------------------------
// Comprehensive Unit Tests
// ---------------------------------------------------------

//--------------------------------------------------------------------------------
// Executes all functional validation checks for the KVector container.
// Validates SVO limits, dynamic allocation, iterators, and edge cases.
//--------------------------------------------------------------------------------
void TestVectorCorrectness()
{
    std::cout << "\n[*] Running KVector Correctness Tests...\n";

    TEST_PHASE("Basic State and Element Pushing");
    KVector<int> intVec;
    // Ensure the default initialized state accurately represents an empty container
    ASSERTMSG("Vector must be initially empty", intVec.IsEmpty());
    ASSERTMSG("Vector size must be 0", intVec.Size() == 0);

    NTSTATUS status = intVec.PushBack(10);
    ASSERTMSG("PushBack failed", NT_SUCCESS(status));
    ASSERTMSG("First element mismatch", intVec[0] == 10);
    TEST_PASS();

    TEST_PHASE("Dynamic Growth and Capacity Scaling");
    // Push elements beyond the initial inline threshold to trigger reallocation
    for (int i = 1; i <= 10; i++)
    {
        intVec.PushBack(i * 10);
    }
    ASSERTMSG("Size mismatch after loop", intVec.Size() == 11);
    ASSERTMSG("Back element mismatch", intVec.Back() == 100);
    TEST_PASS();

    TEST_PHASE("Comprehensive Insertions (Memory Shifting)");
    // Test moving existing blocks of memory to accommodate central insertions
    status = intVec.Insert(intVec.begin() + 5, 999);
    ASSERTMSG("Mid-buffer insert failed", NT_SUCCESS(status));
    ASSERTMSG("Mid-buffer inserted element mismatch", intVec[5] == 999);

    status = intVec.Insert(intVec.begin(), 111);
    ASSERTMSG("Front insert failed", NT_SUCCESS(status));
    ASSERTMSG("Front element mismatch", intVec[0] == 111);

    status = intVec.Insert(intVec.end(), 555);
    ASSERTMSG("Back insert failed", NT_SUCCESS(status));
    ASSERTMSG("Back element mismatch", intVec.Back() == 555);

    // Verify insertion logic on a completely unallocated vector
    KVector<int> emptyVec;
    status = emptyVec.Insert(emptyVec.begin(), 777);
    ASSERTMSG("Empty vector insert failed", NT_SUCCESS(status));
    ASSERTMSG("Empty vector element mismatch", emptyVec[0] = 777);
    ASSERTMSG("Empty vector size mismatch", emptyVec.Size() == 1);
    TEST_PASS();

    TEST_PHASE("Vector Cloning");
    {
        KVector<int> sourceVec;
        sourceVec.PushBack(10);
        sourceVec.PushBack(20);
        sourceVec.PushBack(30);

        KVector<int> destVec;
        // Verify explicit deep copying properly copies elements into a new address space
        status = sourceVec.Clone(&destVec);
        ASSERTMSG("Clone failed", NT_SUCCESS(status));
        ASSERTMSG("Clone size mismatch", destVec.Size() == 3);
        ASSERTMSG("Clone content mismatch", destVec[1] == 20);

        // Modify clone to ensure strict deep-copy memory isolation
        destVec[1] = 99;
        ASSERTMSG("Clone memory overlapping (Source modified)", sourceVec[1] == 20);
        ASSERTMSG("Clone mutation failed", destVec[1] == 99);
    }
    TEST_PASS();

    TEST_PHASE("Data Access: Iterators & Const Correctness");
    int iteratorSum = 0;

    // Explicitly tests non-const begin() and end() pointer evaluation loop safety
    for (const auto& val : intVec)
    {
        iteratorSum += val;
    }

    ASSERTMSG("Iterator traversed incorrectly", iteratorSum > 0);

    // Explicitly test the const operator[] overload compilation constraint
    const KVector<int>& constVec = intVec;
    ASSERTMSG("Const vector read mismatch", constVec[0] == 111);

    // Explicitly test const iterators: const T* begin() const and const T* end() const
    int constIteratorSum = 0;
    for (const int* it = constVec.begin(); it != constVec.end(); ++it)
    {
        constIteratorSum += *it;
    }

    ASSERTMSG("Const iterator sum mismatch", constIteratorSum == iteratorSum);
    TEST_PASS();

    TEST_PHASE("SVO (Small Vector) & Move Semantics");
    {
        KVector<int> svoVec;
        // SVO Capacity is 2. Both pushes should remain inline without touching the allocator.
        svoVec.PushBack(1);
        svoVec.PushBack(2);

        KVector<int> movedVec(kstd::move(svoVec));
        ASSERTMSG("Move constructor failed to transfer SVO size", movedVec.Size() == 2);
        ASSERTMSG("Original vector size should be 0", svoVec.Size() == 0);

        KVector<int> dynamicVec;
        dynamicVec.Reserve(100);
        dynamicVec.PushBack(99);

        // Move Assignment triggering dynamic buffer cleanup and re-homing
        dynamicVec = kstd::move(movedVec);
        ASSERTMSG("Move assignment failed to overwrite dynamic buffer", dynamicVec.Size() == 2);
    }
    TEST_PASS();

    TEST_PHASE("Memory Lifecycle & Destructors (Non-Trivial Types)");
    NonTrivial::DestructorCount = 0;
    {
        KVector<NonTrivial> objVec;
        // Construct in-place to prevent temporary generation
        objVec.EmplaceBack(1, 2);

        NonTrivial nt(3, 4);
        objVec.PushBack(nt);

        // Force memory shift to validate copy/move behavior during insertions
        objVec.Insert(objVec.begin() + 1, NonTrivial(5, 6));
        objVec.Clear();
    }

    // Ensures Clear() correctly invokes explicit destructors for non-trivial array members
    ASSERTMSG("Destructors did not fire correctly", NonTrivial::DestructorCount > 0);
    TEST_PASS();

    TEST_PHASE("Non-Trivially Copyable Operations (Clone & Reserve)");
    {
        KVector<NonTrivial> ntVec;
        // Pushing 3 elements exceeds the default SvoCapacity (2), forcing dynamic pool allocation
        ntVec.PushBack(NonTrivial(10, 20));
        ntVec.PushBack(NonTrivial(30, 40));
        ntVec.PushBack(NonTrivial(50, 60));

        // Reserve forces reallocation, verifying the non-trivial kstd::move path
        NTSTATUS ntStatus = ntVec.Reserve(20);
        ASSERTMSG("Reserve failed on non-trivial type", NT_SUCCESS(ntStatus));
        ASSERTMSG("Reserve failed to preserve non-trivial elements", ntVec[2].Value1 == 50);

        // Clone forces placement-new copy construction
        KVector<NonTrivial> clonedVec;
        ntStatus = ntVec.Clone(&clonedVec);
        ASSERTMSG("Clone failed on non-trivial type", NT_SUCCESS(ntStatus));
        ASSERTMSG("Clone element mismatch", clonedVec[1].Value2 == 40);

        // Insert mid-buffer forces non-trivial element shifting (operator=)
        clonedVec.Insert(clonedVec.begin() + 1, NonTrivial(99, 99));
        ASSERTMSG("Insert failed to shift non-trivial type", clonedVec[2].Value1 == 30);
        ASSERTMSG("Insert placed wrong values", clonedVec[1].Value1 == 99);
    }
    TEST_PASS();

    TEST_PHASE("Edge Case: Dynamic-to-Dynamic Move Assignment");
    {
        KVector<int> vecDest, vecSource;
        // Reserve pushes both vectors out of the SVO inline buffer into distinct dynamic pools
        vecDest.Reserve(100);
        vecDest.PushBack(10);

        vecSource.Reserve(100);
        vecSource.PushBack(99);

        // Move source to dest, ensuring dest correctly frees its original dynamic buffer
        vecDest = kstd::move(vecSource);
        ASSERTMSG("Dynamic move assignment size mismatch", vecDest.Size() == 1);
        ASSERTMSG("Dynamic move assignment value mismatch", vecDest[0] == 99);
    }
    TEST_PASS();

    TEST_PHASE("Edge Case: Integer Overflow and Allocation Failures");
    {
        KVector<int> limitVec;

        // Trigger RtlSizeTMult overflow protection boundary checking
        NTSTATUS limitStatus = limitVec.Reserve(SIZE_MAX);
        bool isRejectedSafely = (limitStatus == STATUS_INTEGER_OVERFLOW || limitStatus == STATUS_INSUFFICIENT_RESOURCES);

        ASSERTMSG("Reserve failed to catch integer overflow or reject wrapped size", isRejectedSafely);

        // Trigger ExAllocatePool2 Out-Of-Memory (OOM) rejection.
        // We divide by sizeof(int) to bypass the integer overflow check,
        // forcing the OS allocator to attempt (and instantly fail) a multi-terabyte allocation.
        SIZE_T impossibleCapacity = (SIZE_MAX / sizeof(int)) - 1;
        limitStatus = limitVec.Reserve(impossibleCapacity);

        ASSERTMSG("Reserve failed to handle OOM cleanly", limitStatus == STATUS_INSUFFICIENT_RESOURCES);
    }
    TEST_PASS();
}

//--------------------------------------------------------------------------------
// Executes all functional validation checks for the KDeque container.
// Validates segmented allocations, contiguous limits, and memory clearing.
//--------------------------------------------------------------------------------
void TestDequeCorrectness()
{
    std::cout << "\n[*] Running KDeque Correctness Tests...\n";
    constexpr SIZE_T kSmallBlockSize = 4;
    KDeque<int, POOL_FLAG_NON_PAGED, kSmallBlockSize> deque;

    TEST_PHASE("Basic Emplace and Block Crossing");
    // Fills up the first block exactly to the limit
    for (int i = 0; i < 4; i++)
    {
        deque.EmplaceBack(i);
    }
    ASSERTMSG("Size mismatch", deque.Size() == 4);

    // Forces the deque to allocate and jump to the second memory block
    deque.EmplaceBack(4);
    ASSERTMSG("Cross-block read failed", deque[4] == 4);
    ASSERTMSG("Size mismatch after cross-block", deque.Size() == 5);
    TEST_PASS();

    TEST_PHASE("Back Element Access");
    deque.EmplaceBack(42);
    ASSERTMSG("Back element mismatch before update", deque.Back() == 42);

    // Mutate the final element directly via reference
    deque.Back() = 84;
    ASSERTMSG("Back element mismatch after update", deque.Back() == 84);
    TEST_PASS();

    TEST_PHASE("Data Access: Const Operator[]");
    const KDeque<int, POOL_FLAG_NON_PAGED, kSmallBlockSize>& constDeque = deque;
    ASSERTMSG("Const deque read mismatch across blocks", constDeque[4] == 4);
    TEST_PASS();

    TEST_PHASE("Max Quota Exhaustion limits");
    // Rapidly fill the entire array of pointers until the kMaxBlocks limit is hit
    for (int i = 6; i < 1024; i++)
    {
        deque.EmplaceBack(i);
    }

    ASSERTMSG("Size mismatch before exhaust", deque.Size() == 1024);

    NTSTATUS failureStatus = deque.EmplaceBack(1024);
    ASSERTMSG("Exceeding quota did not return correct status", failureStatus == STATUS_QUOTA_EXCEEDED);
    TEST_PASS();

    TEST_PHASE("Edge Case: Clean State after Exhaustion");
    deque.Clear();
    ASSERTMSG("Size not 0 after clear", deque.Size() == 0);

    // Validate we can safely resume usage without stale state interference
    failureStatus = deque.EmplaceBack(99);
    ASSERTMSG("Failed to emplace back after clear", NT_SUCCESS(failureStatus));
    TEST_PASS();
}

//--------------------------------------------------------------------------------
// Executes all functional validation checks for the KFlatHashMap container.
// Validates hashing paths, complex keys, SWAR mapping, and capacity dynamics.
//--------------------------------------------------------------------------------
void TestHashMapCorrectness()
{
    std::cout << "\n[*] Running KFlatHashMap Correctness Tests...\n";

    KFlatHashMap<UINT64, std::string> map;
    std::string* __restrict pVal = nullptr;

    TEST_PHASE("Edge Case: Unallocated Empty Map Read");
    // Validates fast-fail check for empty capacity mapping
    ASSERTMSG("Find on empty map should return nullptr", map.Find(999) == nullptr);
    TEST_PASS();

    TEST_PHASE("Reserve Pre-allocation");
    NTSTATUS status = map.Reserve(32);
    ASSERTMSG("Reserve failed on empty map", NT_SUCCESS(status));
    TEST_PASS();

    TEST_PHASE("Insert and Find Verification");
    map.GetOrInsert(100, &pVal);

    if (pVal != nullptr) [[likely]]
    {
        *pVal = "Apple";
    }

    // Verify key retention and data alignment
    std::string* __restrict found = map.Find(100);
    ASSERTMSG("Find failed on existing key", found != nullptr);
    ASSERTMSG("Found value mismatch", *found == "Apple");
    ASSERTMSG("Find matched on missing key", map.Find(200) == nullptr);
    TEST_PASS();

    TEST_PHASE("In-Place Value Modification (No Alloc)");
    std::string* __restrict existingVal = nullptr;
    // Ask for the exact same key to ensure we return the existing slot instead of duplicating
    map.GetOrInsert(100, &existingVal);
    ASSERTMSG("GetOrInsert returned a different pointer for existing key", existingVal == found);

    *existingVal = "Banana";
    ASSERTMSG("Value update failed", *map.Find(100) == "Banana");
    TEST_PASS();

    TEST_PHASE("Rehashing Integrity");
    for (UINT64 i = 1; i <= 10; i++)
    {
        map.GetOrInsert(i, &pVal);
    }

    // Ensures keys were successfully migrated into the new larger layout
    ASSERTMSG("Find failed after rehash", map.Find(5) != nullptr);
    TEST_PASS();

    TEST_PHASE("Hasher Optimization Paths (8, 16, 32, 128-bit)");

    auto testHash = [](auto key, const char* errorMsg)
    {
        KFlatHashMap<decltype(key), int> testMap;
        int* __restrict val = nullptr;
        testMap.GetOrInsert(key, &val);
        ASSERTMSG(errorMsg, testMap.Find(key) != nullptr);
    };

    // Test the Mix64 scalar paths and branchless fast paths based on key size
    testHash(static_cast<char>('A'), "8-bit hash failed");
    testHash(static_cast<short>(1234), "16-bit hash failed");
    testHash(static_cast<int>(12345678), "32-bit hash failed");
    testHash(Guid128{0xDEADBEEF, 0xBAADF00D}, "128-bit hash failed");
    TEST_PASS();

    TEST_PHASE("Complex Struct Key (SWAR Hash Chunking)");
    {
        // Tests the arbitrary length generic struct loop inside KDefaultHash
        KFlatHashMap<ComplexKey, int> complexMap;
        ComplexKey k1 = {0x111, 0x222, 0x333};
        ComplexKey k2 = {0x444, 0x555, 0x666};

        int* __restrict pComplexVal = nullptr;
        complexMap.GetOrInsert(k1, &pComplexVal);
        if (pComplexVal != nullptr) [[likely]]
        {
            *pComplexVal = 42;
        }

        complexMap.GetOrInsert(k2, &pComplexVal);
        if (pComplexVal != nullptr) [[likely]]
        {
            *pComplexVal = 84;
        }

        int* found1 = complexMap.Find(k1);
        ASSERTMSG("Complex key 1 lookup failed", found1 != nullptr && *found1 == 42);

        int* found2 = complexMap.Find(k2);
        ASSERTMSG("Complex key 2 lookup failed", found2 != nullptr && *found2 == 84);

        ComplexKey kMissing = {0x777, 0x888, 0x999};
        ASSERTMSG("Missing complex key found", complexMap.Find(kMissing) == nullptr);
    }
    TEST_PASS();

    TEST_PHASE("SWAR Tail Hash Chunking (Size % 8 != 0)");
    {
        // Tests the arbitrary length fallback loop for non-8-byte aligned tails
        KFlatHashMap<SwarTailKey, int> tailMap;
        SwarTailKey k1 = {1, 2, 3};
        SwarTailKey k2 = {4, 5, 6};

        int* __restrict pTailVal = nullptr;
        tailMap.GetOrInsert(k1, &pTailVal);
        if (pTailVal != nullptr) [[likely]]
        {
            *pTailVal = 100;
        }

        tailMap.GetOrInsert(k2, &pTailVal);
        if (pTailVal != nullptr) [[likely]]
        {
            *pTailVal = 200;
        }

        int* found1 = tailMap.Find(k1);
        ASSERTMSG("SWAR tail key 1 lookup failed", found1 != nullptr && *found1 == 100);

        int* found2 = tailMap.Find(k2);
        ASSERTMSG("SWAR tail key 2 lookup failed", found2 != nullptr && *found2 == 200);

        SwarTailKey kMissing = {7, 8, 9};
        ASSERTMSG("Missing SWAR tail key found", tailMap.Find(kMissing) == nullptr);
    }
    TEST_PASS();

    TEST_PHASE("Identity Hashers (2, 4, 8-byte and constraints)");
    {
        // Tests 16-bit identity passthrough
        KFlatHashMap<UINT16, int, KIdentityHash<UINT16>> mapIdentity16;
        int* __restrict vId16 = nullptr;
        mapIdentity16.GetOrInsert(static_cast<UINT16>(42), &vId16);
        ASSERTMSG("Identity hash (16-bit) failed", mapIdentity16.Find(static_cast<UINT16>(42)) != nullptr);

        // Tests 32-bit identity passthrough
        KFlatHashMap<UINT32, int, KIdentityHash<UINT32>> mapIdentity32;
        int* __restrict vId32 = nullptr;
        mapIdentity32.GetOrInsert(static_cast<UINT32>(0xDEADBEEF), &vId32);
        ASSERTMSG("Identity hash (32-bit) failed", mapIdentity32.Find(static_cast<UINT32>(0xDEADBEEF)) != nullptr);

        // Tests 64-bit identity passthrough
        KFlatHashMap<UINT64, int, KIdentityHash<UINT64>> mapIdentity64;
        int* __restrict vId64 = nullptr;
        mapIdentity64.GetOrInsert(0xABCDEF1234567890ULL, &vId64);
        ASSERTMSG("Identity hash (64-bit) failed", mapIdentity64.Find(0xABCDEF1234567890ULL) != nullptr);
    }
    TEST_PASS();

    TEST_PHASE("Precomputed Hasher Coverage");
    {
        KFlatHashMap<UINT64, int, KPrecomputedHash> mapPrecomputed;
        int* __restrict vPre = nullptr;

        // Insert multiple values to trigger rehashing and SWAR bucket alignment
        // with precomputed metadata mixing
        for (UINT64 i = 0; i < 100; i++)
        {
            UINT64 precomputedKey = (i << 32) | i;
            mapPrecomputed.GetOrInsert(precomputedKey, &vPre);
            if (vPre != nullptr) [[likely]]
            {
                *vPre = static_cast<int>(i);
            }
        }

        int* foundVal = mapPrecomputed.Find((50ULL << 32) | 50ULL);
        ASSERTMSG("Precomputed hash retrieval failed", foundVal != nullptr);
        ASSERTMSG("Precomputed hash value mismatch", *foundVal == 50);
    }
    TEST_PASS();

    TEST_PHASE("Extreme Hash Collision Fallbacks (SWAR Match)");
    // Validates the SWAR linear probe algorithm correctly cycles adjacent control bytes
    // when multiple items generate identically colliding hashes.
    KFlatHashMap<UINT64, int, CollisionHash> collisionMap;
    int* __restrict pColVal = nullptr;

    for (UINT64 i = 0; i < 12; i++)
    {
        collisionMap.GetOrInsert(i, &pColVal);

        if (pColVal != nullptr) [[likely]]
        {
            *pColVal = static_cast<int>(i) * 10;
        }
    }

    for (UINT64 i = 0; i < 12; i++)
    {
        int* __restrict val = collisionMap.Find(i);
        ASSERTMSG("Collision map value mismatch", *val == static_cast<int>(i) * 10);
    }
    TEST_PASS();

    TEST_PHASE("Iterator Operator->");
    KFlatHashMap<UINT64, std::string> iterMap;
    std::string* __restrict pIterStr = nullptr;
    iterMap.GetOrInsert(777, &pIterStr);

    if (pIterStr != nullptr) [[likely]]
    {
        *pIterStr = "Lucky";
    }

    auto it = iterMap.begin();
    ASSERTMSG("Iterator begin failed", it != iterMap.end());
    ASSERTMSG("Iterator operator-> key mismatch", it->Key == 777);
    ASSERTMSG("Iterator operator-> value mismatch", it->Value == "Lucky");

    // Modify via iterator
    it->Value = "Changed";
    ASSERTMSG("Iterator operator-> mutation failed", *iterMap.Find(777) == "Changed");
    TEST_PASS();

    TEST_PHASE("Data Access: Map Iterators");
    SIZE_T iterateCount = 0;

    for (auto& slot : collisionMap)
    {
        iterateCount++;
    }
    ASSERTMSG("Iterator count mismatch", iterateCount == 12);

    collisionMap.Clear();
    iterateCount = 0;

    // Iterator should yield 0 results since control bytes have been completely reset
    for (auto& slot : collisionMap)
    {
        iterateCount++;
    }

    ASSERTMSG("Iterator yielded elements after clear", iterateCount == 0);
    TEST_PASS();

    TEST_PHASE("Edge Case: Map Integer Overflow and Allocation Failures");
    {
        KFlatHashMap<UINT64, int> limitMap;

        // Trigger RtlSizeTAdd / RtlSizeTMult overflow protection during Rehash
        NTSTATUS limitStatus = limitMap.Reserve(SIZE_MAX);
        bool isRejectedSafely = (limitStatus == STATUS_INTEGER_OVERFLOW || limitStatus == STATUS_INSUFFICIENT_RESOURCES);
        ASSERTMSG("Reserve failed to catch integer overflow or reject wrapped size", isRejectedSafely);

        // Trigger ExAllocatePool2 Out-Of-Memory (OOM) rejection.
        // Bypasses the math overflow but requests an impossible amount of physical RAM.
        SIZE_T impossibleCapacity = SIZE_MAX >> 4;
        limitStatus = limitMap.Reserve(impossibleCapacity);
        ASSERTMSG("Map Reserve failed to handle OOM cleanly", limitStatus == STATUS_INSUFFICIENT_RESOURCES);
    }
    TEST_PASS();
}

// ---------------------------------------------------------
// Performance Benchmarks (Time-Bounded Comparison)
// ---------------------------------------------------------

struct BenchmarkResult
{
    UINT64 TotalOps;
    UINT64 DurationNs;
};

// Global variable to ensure Dead Code Elimination (DCE) does not strip away find/read return results
volatile long long g_BenchmarkDiscardSum = 0;

//--------------------------------------------------------------------------------
// Renders the tabular layout header for comparative benchmark runs.
//--------------------------------------------------------------------------------
void PrintComparisonTableHeader(const std::string& categoryTitle)
{
    std::cout << "\n" << std::string(108, '=') << "\n";
    std::cout << "  " << categoryTitle << "\n";
    std::cout << std::string(108, '=') << "\n";
    std::cout << "| " << std::left << std::setw(38) << "Operation"
              << " | " << std::left << std::setw(9) << "K-ns/Op"
              << " | " << std::left << std::setw(9) << "std-ns/Op"
              << " | " << std::left << std::setw(12) << "K-Ops/s"
              << " | " << std::left << std::setw(12) << "std-Ops/s"
              << " | " << std::left << std::setw(10) << "Diff (K)" << " |\n";
    std::cout << "|----------------------------------------|-----------|-----------|--------------|--------------|------------|\n";
}

//--------------------------------------------------------------------------------
// Core measurement harness that warms up the CPU instruction cache and measures
// throughput using flattened loop iteration patterns.
//--------------------------------------------------------------------------------
template <typename WorkLambda>
BenchmarkResult MeasureBenchmark(UINT64 opsPerChunk, WorkLambda work)
{
    // 100ms Warmup Phase to stabilize CPU clock frequencies (e.g. Turbo Boost) and pre-fetch cache lines.
    auto warmupStart = std::chrono::high_resolution_clock::now();

    while (true)
    {
        auto now = std::chrono::high_resolution_clock::now();

        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - warmupStart).count() >= 100) [[unlikely]]
        {
            break;
        }

        work();
    }

    // 2000ms Measurement Phase
    UINT64 totalOps = 0;
    auto start = std::chrono::high_resolution_clock::now();
    auto now = start;

    while (true)
    {
        now = std::chrono::high_resolution_clock::now();

        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count() >= 2000) [[unlikely]]
        {
            break;
        }

        work();
        totalOps += opsPerChunk;
    }

    UINT64 exactDurationNs = std::chrono::duration_cast<std::chrono::nanoseconds>(now - start).count();
    
    return { totalOps, exactDurationNs };
}

//--------------------------------------------------------------------------------
// Executes side-by-side performance measurements, formats standard deviations,
// calculates percentual superiority, and prints the aligned table row.
//--------------------------------------------------------------------------------
template <typename WorkK, typename WorkStd>
void RunComparisonBenchmark(const std::string& operation, UINT64 opsPerChunk, WorkK workK, WorkStd workStd)
{
    BenchmarkResult resK = MeasureBenchmark(opsPerChunk, workK);
    BenchmarkResult resStd = MeasureBenchmark(opsPerChunk, workStd);

    double kNsPerOp = 0.0, kOpsSec = 0.0;
    if (resK.TotalOps > 0 && resK.DurationNs > 0)
    {
        kNsPerOp = static_cast<double>(resK.DurationNs) / static_cast<double>(resK.TotalOps);
        kOpsSec = static_cast<double>(resK.TotalOps) / (static_cast<double>(resK.DurationNs) / 1000000000.0);
    }

    double stdNsPerOp = 0.0, stdOpsSec = 0.0;
    if (resStd.TotalOps > 0 && resStd.DurationNs > 0)
    {
        stdNsPerOp = static_cast<double>(resStd.DurationNs) / static_cast<double>(resStd.TotalOps);
        stdOpsSec = static_cast<double>(resStd.TotalOps) / (static_cast<double>(resStd.DurationNs) / 1000000000.0);
    }

    double diffPercent = 0.0;
    if (stdOpsSec > 0.0)
    {
        diffPercent = ((kOpsSec / stdOpsSec) - 1.0) * 100.0;
    }

    std::stringstream ssDiff;
    ssDiff << std::fixed << std::setprecision(1);
    if (diffPercent > 0.0)
    {
        ssDiff << "+";
    }
    ssDiff << diffPercent << "%";

    std::cout << "| " << std::left << std::setw(38) << operation
              << " | " << std::left << std::fixed << std::setprecision(2) << std::setw(9) << kNsPerOp
              << " | " << std::left << std::fixed << std::setprecision(2) << std::setw(9) << stdNsPerOp
              << " | " << std::left << std::fixed << std::setprecision(0) << std::setw(12) << kOpsSec
              << " | " << std::left << std::fixed << std::setprecision(0) << std::setw(12) << stdOpsSec
              << " | " << std::left << std::setw(10) << ssDiff.str() << " |\n";
}

//--------------------------------------------------------------------------------
// Helper to fully encapsulate hash map setup, cache warming, and raw iteration
// measurement back-to-back to prevent code duplication across scale factors.
//--------------------------------------------------------------------------------
void BenchmarkMapLookupsComparison(const std::string& sizeLabel, UINT64 mapSize, UINT64 chunkSize)
{
    // Setup KFlatHashMap
    KFlatHashMap<UINT64, int> mapK;
    mapK.Reserve(mapSize);
    int* __restrict pVal = nullptr;

    for (UINT64 i = 0; i < mapSize; i++)
    {
        mapK.GetOrInsert(i, &pVal);
        
        if (pVal != nullptr) [[likely]]
        {
            *pVal = static_cast<int>(i);
        }
    }

    // Setup std::unordered_map
    std::unordered_map<UINT64, int> mapStd;
    mapStd.reserve(mapSize);

    for (UINT64 i = 0; i < mapSize; i++)
    {
        mapStd.emplace(i, static_cast<int>(i));
    }

    UINT64 searchIndexK = 0;
    UINT64 searchIndexStd = 0;

    auto posK = [&]()
    {
        long long localSum = 0;
        for (UINT64 i = 0; i < chunkSize; i++)
        {
            int* found = mapK.Find(searchIndexK);
            if (found != nullptr)
            {
                localSum += *found;
            }

            if (++searchIndexK >= mapSize) [[unlikely]]
            {
                searchIndexK = 0;
            }
        }
        g_BenchmarkDiscardSum = localSum;
    };

    auto posStd = [&]()
    {
        long long localSum = 0;
        for (UINT64 i = 0; i < chunkSize; i++)
        {
            auto it = mapStd.find(searchIndexStd);
            if (it != mapStd.end())
            {
                localSum += it->second;
            }

            if (++searchIndexStd >= mapSize) [[unlikely]]
            {
                searchIndexStd = 0;
            }
        }
        g_BenchmarkDiscardSum = localSum;
    };

    RunComparisonBenchmark("Find Positives (" + sizeLabel + ")", chunkSize, posK, posStd);

    UINT64 negativeIndexK = mapSize;
    UINT64 negativeIndexStd = mapSize;

    auto negK = [&]()
    {
        long long localSum = 0;
        for (UINT64 i = 0; i < chunkSize; i++)
        {
            int* found = mapK.Find(negativeIndexK);
            if (found != nullptr)
            {
                localSum += *found;
            }
            
            negativeIndexK++;
        }
        g_BenchmarkDiscardSum = localSum;
    };

    auto negStd = [&]()
    {
        long long localSum = 0;
        for (UINT64 i = 0; i < chunkSize; i++)
        {
            auto it = mapStd.find(negativeIndexStd);
            if (it != mapStd.end())
            {
                localSum += it->second;
            }
            
            negativeIndexStd++;
        }
        g_BenchmarkDiscardSum = localSum;
    };

    RunComparisonBenchmark("Find Negatives (" + sizeLabel + ")", chunkSize, negK, negStd);
}

//--------------------------------------------------------------------------------
// Sequentially executes all high-throughput timing algorithms.
// Generates tabular readout displaying comparative raw operation rates.
//--------------------------------------------------------------------------------
void RunPerformanceTests()
{
    std::cout << "\n[*] Running Time-Bounded Performance Benchmarks (2.0s per test)...\n";

    constexpr UINT64 kChunkSize = 10000;

    // ---------------------------------------------------------------------------
    // 1. Vector Comparisons
    // ---------------------------------------------------------------------------
    PrintComparisonTableHeader("Vector (KVector vs std::vector)");

    KVector<int> vecAutoK;
    std::vector<int> vecAutoStd;

    auto pushBackAutoK = [&]()
    {
        vecAutoK.Clear();
        for (UINT64 i = 0; i < kChunkSize; i++)
        {
            vecAutoK.PushBack(static_cast<int>(i));
        }
    };

    auto pushBackAutoStd = [&]()
    {
        vecAutoStd.clear();
        for (UINT64 i = 0; i < kChunkSize; i++)
        {
            vecAutoStd.push_back(static_cast<int>(i));
        }
    };

    RunComparisonBenchmark("PushBack (Auto Grow, 10k Chunk)", kChunkSize, pushBackAutoK, pushBackAutoStd);

    KVector<int> vecResK;
    vecResK.Reserve(kChunkSize);
    std::vector<int> vecResStd;
    vecResStd.reserve(kChunkSize);

    auto pushBackResK = [&]()
    {
        vecResK.Clear();
        for (UINT64 i = 0; i < kChunkSize; i++)
        {
            vecResK.PushBack(static_cast<int>(i));
        }
    };

    auto pushBackResStd = [&]()
    {
        vecResStd.clear();
        for (UINT64 i = 0; i < kChunkSize; i++)
        {
            vecResStd.push_back(static_cast<int>(i));
        }
    };

    RunComparisonBenchmark("PushBack (Reserved, 10k Chunk)", kChunkSize, pushBackResK, pushBackResStd);

    KVector<int> vecReadK;
    vecReadK.Reserve(kChunkSize);
    std::vector<int> vecReadStd;
    vecReadStd.reserve(kChunkSize);

    for (UINT64 i = 0; i < kChunkSize; i++)
    {
        vecReadK.PushBack(static_cast<int>(i));
        vecReadStd.push_back(static_cast<int>(i));
    }

    auto seqReadK = [&]()
    {
        long long localSum = 0;
        for (const auto& val : vecReadK)
        {
            localSum += val;
        }
        g_BenchmarkDiscardSum = localSum;
    };

    auto seqReadStd = [&]()
    {
        long long localSum = 0;
        for (const auto& val : vecReadStd)
        {
            localSum += val;
        }
        g_BenchmarkDiscardSum = localSum;
    };

    RunComparisonBenchmark("Sequential Read (10k Chunk)", kChunkSize, seqReadK, seqReadStd);

    // ---------------------------------------------------------------------------
    // 2. Deque Comparisons
    // ---------------------------------------------------------------------------
    PrintComparisonTableHeader("Deque (KDeque vs std::deque)");

    KDeque<int, POOL_FLAG_NON_PAGED, 4096> dequeK;
    std::deque<int> dequeStd;

    auto emplaceDequeK = [&]()
    {
        dequeK.Clear();
        for (UINT64 i = 0; i < kChunkSize; i++)
        {
            dequeK.EmplaceBack(static_cast<int>(i));
        }
    };

    auto emplaceDequeStd = [&]()
    {
        dequeStd.clear();
        for (UINT64 i = 0; i < kChunkSize; i++)
        {
            dequeStd.emplace_back(static_cast<int>(i));
        }
    };

    RunComparisonBenchmark("EmplaceBack (10k Chunk)", kChunkSize, emplaceDequeK, emplaceDequeStd);

    KDeque<int, POOL_FLAG_NON_PAGED, 4096> dequeReadK;
    std::deque<int> dequeReadStd;

    for (UINT64 i = 0; i < kChunkSize; i++)
    {
        dequeReadK.EmplaceBack(static_cast<int>(i));
        dequeReadStd.emplace_back(static_cast<int>(i));
    }

    auto crossReadK = [&]()
    {
        long long localSum = 0;
        for (UINT64 i = 0; i < kChunkSize; i++)
        {
            localSum += dequeReadK[i];
        }
        g_BenchmarkDiscardSum = localSum;
    };

    auto crossReadStd = [&]()
    {
        long long localSum = 0;
        for (UINT64 i = 0; i < kChunkSize; i++)
        {
            localSum += dequeReadStd[i];
        }
        g_BenchmarkDiscardSum = localSum;
    };

    RunComparisonBenchmark("Cross-Block Read (10k Chunk)", kChunkSize, crossReadK, crossReadStd);

    // ---------------------------------------------------------------------------
    // 3. Hash Map Comparisons
    // ---------------------------------------------------------------------------
    PrintComparisonTableHeader("Hash Map (KFlatHashMap vs std::unordered_map)");

    KFlatHashMap<UINT64, int> mapAutoK;
    int* __restrict pMapVal = nullptr;
    std::unordered_map<UINT64, int> mapAutoStd;

    auto insertAutoK = [&]()
    {
        mapAutoK.Clear();
        for (UINT64 i = 0; i < kChunkSize; i++)
        {
            mapAutoK.GetOrInsert(i, &pMapVal);
        }
    };

    auto insertAutoStd = [&]()
    {
        mapAutoStd.clear();
        for (UINT64 i = 0; i < kChunkSize; i++)
        {
            mapAutoStd.emplace(i, 0);
        }
    };

    RunComparisonBenchmark("Insert (Auto Rehash, 10k Chunk)", kChunkSize, insertAutoK, insertAutoStd);

    KFlatHashMap<UINT64, int> mapResK;
    mapResK.Reserve(kChunkSize);
    std::unordered_map<UINT64, int> mapResStd;
    mapResStd.reserve(kChunkSize);

    auto insertResK = [&]()
    {
        mapResK.Clear();
        for (UINT64 i = 0; i < kChunkSize; i++)
        {
            mapResK.GetOrInsert(i, &pMapVal);
        }
    };

    auto insertResStd = [&]()
    {
        mapResStd.clear();
        for (UINT64 i = 0; i < kChunkSize; i++)
        {
            mapResStd.emplace(i, 0);
        }
    };

    RunComparisonBenchmark("Insert (Reserved Map, 10k Chunk)", kChunkSize, insertResK, insertResStd);

    BenchmarkMapLookupsComparison("100 Tiny Map", 100, kChunkSize);
    BenchmarkMapLookupsComparison("1k Light Map", 1000, kChunkSize);
    BenchmarkMapLookupsComparison("10k Medium Map", 10000, kChunkSize);
    BenchmarkMapLookupsComparison("100k Large Map", 100000, kChunkSize);
    BenchmarkMapLookupsComparison("1M Heavy Map", 1000000, kChunkSize);
    BenchmarkMapLookupsComparison("10M Massive Map", 10000000, kChunkSize);

    std::cout << "\n";
}

//--------------------------------------------------------------------------------
// User-mode test runner entrypoint. Triggers entire correctness and benchmark suite.
//--------------------------------------------------------------------------------
int main()
{
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);

    TestVectorCorrectness();
    TestDequeCorrectness();
    TestHashMapCorrectness();

    std::cout << "\n" << std::string(108, '=') << "\n";
    std::cout << "  [+] ALL CORRECTNESS TESTS PASSED SUCCESSFULLY\n";
    std::cout << std::string(108, '=') << "\n";

    RunPerformanceTests();

    return 0;
}
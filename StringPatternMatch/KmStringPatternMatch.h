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
#include <ntddk.h>

#include "KVector.h"
#include "KDeque.h"
#include "KHashMap.h"
#include "PlatformUtils.h"

// -------------------------------------------------------------------------------------------
// Hardware Intrinsic Macros (x64 / ARM64)
// -------------------------------------------------------------------------------------------
// Evaluates to a boolean indicating the original state of the bit, then sets it to 1.
#define SPM_BIT_TEST_AND_SET64(BitField, BitIndex) \
    _bittestandset64(reinterpret_cast<LONG64*>(&(BitField)), static_cast<LONG>(BitIndex))

// Evaluates to a boolean indicating the current state of the bit.
#define SPM_BIT_TEST64(BitField, BitIndex) \
    _bittest64(reinterpret_cast<const LONG64*>(&(BitField)), static_cast<LONG>(BitIndex))

// -------------------------------------------------------------------------------------------
// Memory Arena
// -------------------------------------------------------------------------------------------

// -------------------------------------------------------------------------------------------
// Linearly carves TChar blocks from a continuous backbuffer slab to prevent kernel pool 
// fragmentation.
// Eliminates 64-byte alignment padding, container metadata, and pool headers per string.
// String lifespan is permanently locked to the arena until Clear() is explicitly called.
//
// Template Parameters:
//   TChar    - The character type (e.g., WCHAR or CHAR) used for string allocation.
//   PoolType - The NT kernel pool flags indicating memory type (e.g., NonPaged).
//   PoolTag  - The 4-byte tag used for kernel memory tracking.
// -------------------------------------------------------------------------------------------
template <typename TChar = WCHAR, POOL_FLAGS PoolType = POOL_FLAG_NON_PAGED, ULONG PoolTag = 'arSK'>
class KStringArena
{
public:
    // Bookmark structure to support atomic memory transactions
    struct Bookmark
    {
        void*  TailSlab;
        SIZE_T UsedChars;
    };

private:
    // Memory slab acting as the continuous backbuffer
    struct Slab
    {
        Slab*  Next;      // Pointer to the next chained slab structure in the memory chain
        SIZE_T Capacity;  // Total character capacity available in this allocated slab
        SIZE_T Used;      // Number of characters currently committed and in use within this slab
        TChar  Buffer[1]; // Flexible array member containing the linear character data allocation
    };

    Slab* m_Head; // First allocated slab in the chain, representing the start of the memory block
    Slab* m_Tail; // Current active slab being used for new linear allocations

public:
    // -------------------------------------------------------------------------------------------
    // Default constructor initializing empty arena slab pointers.
    // -------------------------------------------------------------------------------------------
    KStringArena() noexcept : m_Head(nullptr), 
                              m_Tail(nullptr)
    {
    }

    // -------------------------------------------------------------------------------------------
    // Destructor ensuring all chained memory slabs are released.
    // -------------------------------------------------------------------------------------------
    ~KStringArena() noexcept
    {
        Clear();
    }

    // -------------------------------------------------------------------------------------------
    // Linearly carves out TChar blocks from a continuous backbuffer slab.
    //
    // Parameters:
    //   Length - The exact number of characters to allocate contiguous space for.
    //
    // Return:
    //   Pointer to the successfully allocated block, or nullptr if pool allocation fails.
    // -------------------------------------------------------------------------------------------
    TChar* Allocate(_In_ SIZE_T Length) noexcept
    {
        if (Length == 0) [[unlikely]]
        {
            return nullptr;
        }

        // Data-Oriented Arena Alignment: Ensure all carved buffers are aligned to 8 bytes 
        // to natively support fast SWAR block comparisons without hardware traps.
        constexpr SIZE_T charAlign     = 8 / sizeof(TChar);
        SIZE_T           alignedLength = (Length + (charAlign - 1)) & ~(charAlign - 1);

        if (m_Tail == nullptr || (m_Tail->Capacity - m_Tail->Used) < alignedLength)
        {
            SIZE_T bytesNeeded = alignedLength * sizeof(TChar);
            SIZE_T allocSize   = FIELD_OFFSET(Slab, Buffer) + bytesNeeded;
            
            // Fallback: Allocate a new slab (e.g., 4096 bytes) and append it to m_Tail
            if (allocSize < 4096)
            {
                allocSize = 4096;
            }

            SIZE_T capacity = (allocSize - FIELD_OFFSET(Slab, Buffer)) / sizeof(TChar);

            constexpr POOL_FLAGS allocFlags = PoolType | POOL_FLAG_UNINITIALIZED;
            Slab* pNewSlab = static_cast<Slab*>(ExAllocatePool2(allocFlags, allocSize, PoolTag));           
            if (pNewSlab == nullptr) [[unlikely]]
            {
                return nullptr;
            }

            pNewSlab->Next     = nullptr;
            pNewSlab->Capacity = capacity;
            pNewSlab->Used     = 0;

            if (m_Tail != nullptr)
            {
                m_Tail->Next = pNewSlab;
            }
            else
            {
                m_Head = pNewSlab;
            }

            m_Tail = pNewSlab;
        }

        TChar* pMemory = &m_Tail->Buffer[m_Tail->Used];
        m_Tail->Used += alignedLength; // Consume the properly aligned footprint
        
        return pMemory;
    }

    // -------------------------------------------------------------------------------------------
    // Captures the current memory state to rollback incomplete multi-allocation transactions.
    // -------------------------------------------------------------------------------------------
    Bookmark GetBookmark() const noexcept
    {
        return { m_Tail, m_Tail != nullptr ? m_Tail->Used : 0 };
    }

    // -------------------------------------------------------------------------------------------
    // Rolls back the memory state to the provided bookmark, freeing newly allocated slabs.
    // -------------------------------------------------------------------------------------------
    void RevertBookmark(_In_ Bookmark mark) noexcept
    {
        Slab* markSlab = static_cast<Slab*>(mark.TailSlab);

        if (m_Tail == markSlab)
        {
            if (m_Tail != nullptr)
            {
                m_Tail->Used = mark.UsedChars;
            }
        }
        else
        {
            Slab* pCurrent = markSlab != nullptr ? markSlab->Next : m_Head;
            
            while (pCurrent != nullptr)
            {
                Slab* pNext = pCurrent->Next;
                ExFreePoolWithTag(pCurrent, PoolTag);
                pCurrent = pNext;
            }

            m_Tail = markSlab;
            
            if (m_Tail != nullptr)
            {
                m_Tail->Next = nullptr;
                m_Tail->Used = mark.UsedChars;
            }
            else
            {
                m_Head = nullptr;
            }
        }
    }

    // -------------------------------------------------------------------------------------------
    // Resets the arena and releases all allocated pool slabs back to the system.
    // -------------------------------------------------------------------------------------------
    void Clear() noexcept
    {
        Slab* pCurrent = m_Head;
        
        while (pCurrent != nullptr)
        {
            Slab* pNext = pCurrent->Next;
            ExFreePoolWithTag(pCurrent, PoolTag);
            pCurrent = pNext;
        }
        
        m_Head = nullptr;
        m_Tail = nullptr;
    }
};

// -------------------------------------------------------------------------------------------
// Enumerations
// -------------------------------------------------------------------------------------------

// Defines the boundary behavior of the wildcard matching.
// SCOPE_PATH_SEGMENT restricts wildcard '*' and '?' from crossing directory boundaries.
enum WILD_CARD_SCOPE : UINT8
{
    SCOPE_DEFAULT      = 0, // Wildcards can freely cross path separator boundaries
    SCOPE_PATH_SEGMENT = 1  // Wildcards halt expansion upon encountering a path separator
};

namespace KmStringPatternMatchDetail
{
    // -------------------------------------------------------------------------------------------
    // Cross-Platform 64x64 -> 128-bit Scalar Mixer
    // Breaks execution dependency chains while providing bit good avalanche.
    //
    // Parameters:
    //   A - The first 64-bit integer to mix.
    //   B - The second 64-bit integer (typically a prime) to mix.
    //
    // Return:
    //   The 64-bit folded result of the 128-bit multiplication.
    // -------------------------------------------------------------------------------------------
    inline UINT64 Mix64(_In_ UINT64 A,
                        _In_ UINT64 B) noexcept
    {
#if defined(_M_X64) || defined(_M_AMD64)
        UINT64 high;
        UINT64 low = _umul128(A, B, &high);
        return low ^ high;
#elif defined(_M_ARM64)
        UINT64 high = __umulh(A, B);
        UINT64 low = A * B;
        return low ^ high;
#else
        // Fallback for 32-bit architectures
        UINT64 AL = static_cast<UINT32>(A);
        UINT64 AH = A >> 32;
        UINT64 BL = static_cast<UINT32>(B);
        UINT64 BH = B >> 32;

        UINT64 LL = AL * BL;
        UINT64 HL = AH * BL;
        UINT64 LH = AL * BH;
        UINT64 HH = AH * BH;

        UINT64 cross = (LL >> 32) + static_cast<UINT32>(HL) + static_cast<UINT32>(LH);
        UINT64 upper = (HL >> 32) + (LH >> 32) + (cross >> 32) + HH;
        UINT64 lower = (cross << 32) | static_cast<UINT32>(LL);

        return lower ^ upper;
#endif
    }

    // -------------------------------------------------------------------------------------------
    // Determines if a character is a path separator natively for the target OS.
    // Used exclusively when SCOPE_PATH_SEGMENT is active to halt wildcard expansion.
    //
    // Parameters:
    //   c - The character being evaluated during the string iteration.
    //
    // Return:
    //   True if the character matches the defined path separator ('\'), false otherwise.
    // -------------------------------------------------------------------------------------------
    template <typename TChar>
    inline bool IsPathSeparator(_In_ TChar c) noexcept
    {
        return c == static_cast<TChar>('\\');
    }

    // -------------------------------------------------------------------------------------------
    // Zero-extends characters to UINT64 to prevent sign extension issues with signed 8-bit char types.
    //
    // Parameters:
    //   c - The character being promoted to a 64-bit unsigned integer.
    //
    // Return:
    //   The 64-bit zero-extended value of the input character.
    // -------------------------------------------------------------------------------------------
    template <typename TChar>
    inline UINT64 CharToUint64(_In_ TChar c) noexcept
    {
        if constexpr (sizeof(TChar) == 1)
        {
            return static_cast<UINT64>(static_cast<unsigned char>(c));
        }
        else
        {
            return static_cast<UINT64>(c);
        }
    }

    // -------------------------------------------------------------------------------------------
    // Safely uppercases a character inline.
    // Differentiates at compile-time between 8-bit ANSI and 16-bit Unicode.
    //
    // Parameters:
    //   c - The original character to be converted.
    //
    // Return:
    //   The uppercase equivalent of the character, or the original character if unmappable.
    // -------------------------------------------------------------------------------------------
    template <typename TChar>
    inline TChar ToUpperFast(_In_ TChar c) noexcept
    {
        if constexpr (sizeof(TChar) == 1)
        {
            // Pure inline evaluation for 8-bit characters.
            // Bypasses RtlUpperChar entirely for DISPATCH_LEVEL safety.
            unsigned char uc = static_cast<unsigned char>(c);
            return static_cast<TChar>(uc - ((uc >= 'a' && uc <= 'z') << 5));
        }
        else
        {
            // Fast-path inline ASCII check for 16-bit WCHAR
            if (c <= 127)
            {
                return c - ((c >= L'a' && c <= L'z') << 5);
            }

#if DBG
            // Case-insensitive Unicode translation requires system locales mapped at PASSIVE_LEVEL or APC_LEVEL.
            ASSERTMSG("Case-insensitive Match called at DISPATCH_LEVEL or above", KeGetCurrentIrql() < DISPATCH_LEVEL);
#endif

            return static_cast<TChar>(RtlUpcaseUnicodeChar(static_cast<WCHAR>(c)));
        }
    }

    // -------------------------------------------------------------------------------------------
    // Checks if an entire 64-bit SWAR block is entirely ASCII.
    // Enables bypassing RtlUpcaseUnicodeChar evaluation for pure English paths.
    //
    // Parameters:
    //   w - The 64-bit block of characters.
    //
    // Return:
    //   True if every character in the block falls within the standard ASCII range.
    // -------------------------------------------------------------------------------------------
    template <typename TChar>
    inline bool IsAsciiSWAR(_In_ UINT64 w) noexcept
    {
        if constexpr (sizeof(TChar) == 1)
        {
            return (w & 0x8080808080808080ULL) == 0;
        }
        else
        {
            return (w & 0xFF80FF80FF80FF80ULL) == 0;
        }
    }

    // -------------------------------------------------------------------------------------------
    // Case-folds a fully ASCII 64-bit SWAR block inline via bitwise arithmetic.
    // WARNING: Callers must guarantee IsAsciiSWAR(w) is true prior to invocation to prevent 
    // destructive boundary arithmetic faults on higher-order code points.
    //
    // Parameters:
    //   w - The 64-bit block of purely ASCII characters.
    //
    // Return:
    //   The 64-bit block with all a-z characters converted to uppercase.
    // -------------------------------------------------------------------------------------------
    template <typename TChar>
    inline UINT64 ToUpperSWAR(_In_ UINT64 w) noexcept
    {
        if constexpr (sizeof(TChar) == 1)
        {
            UINT64 NotUnderA = w + 0x1F1F1F1F1F1F1F1FULL;
            UINT64 NotOverZ = 0xFAFAFAFAFAFAFAFAULL - w;
            UINT64 IsLower = NotUnderA & NotOverZ & 0x8080808080808080ULL;

            return w - ((IsLower >> 2) & 0x2020202020202020ULL);
        }
        else
        {
            UINT64 NotUnderA = w + 0x7F9F7F9F7F9F7F9FULL;
            UINT64 NotOverZ = 0x807A807A807A807AULL - w;
            UINT64 IsLower = NotUnderA & NotOverZ & 0x8000800080008000ULL;

            return w - ((IsLower >> 10) & 0x0020002000200020ULL);
        }
    }

    // -------------------------------------------------------------------------------------------
    // Scalar WyHash-style block hasher. Processes 8 bytes concurrently using unaligned loads.
    // Explicitly omits final avalanche mixing to natively support rolling incremental hashes.
    //
    // Parameters:
    //   sText    - Pointer to the text buffer to be hashed.
    //   cchText  - The length of the text in characters.
    //   PrevHash - The base hash seed or accumulation value.
    //
    // Return:
    //   The computed 64-bit hash representing the provided text buffer.
    // -------------------------------------------------------------------------------------------
    template <typename TChar>
    inline UINT64 CalculateHash(_In_reads_(cchText) const TChar* __restrict sText,
                                _In_                UINT32                  cchText,
                                _In_                UINT64                  PrevHash) noexcept
    {
        constexpr UINT64 kPrime = 0x8bb84b93962eacc9ULL;

        UINT64 hash   = PrevHash;        
        SIZE_T chunks = (static_cast<SIZE_T>(cchText) * sizeof(TChar)) / 8;
        SIZE_T i = 0;

        for (; i < chunks; i++)
        {
            UINT64 w;            
            memcpy(&w, sText + (i * (8 / sizeof(TChar))), sizeof(UINT64));
            hash = Mix64(hash ^ w, kPrime);
        }

        UINT32 remainingChars = cchText - static_cast<UINT32>(chunks * (8 / sizeof(TChar)));
        if (remainingChars > 0)
        {
            UINT64 tail = 0;
            const TChar* pTail = sText + (chunks * (8 / sizeof(TChar)));

            for (UINT32 j = 0; j < remainingChars; j++)
            {
                tail |= (CharToUint64(pTail[j]) << (j * sizeof(TChar) * 8));
            }

            hash = Mix64(hash ^ tail, kPrime);
        }

        return hash;
    }
};

// -------------------------------------------------------------------------------------------
// Main Class Definition
// -------------------------------------------------------------------------------------------
// KmStringPatternMatch is a high-performance, lock-free string matching engine.
// The algorithm utilizes a hash-existence filter for O(1) prefix rejection, 
// overlapping 64-bit SWAR (SIMD Within A Register) chunking for literal comparisons,
// and a non-recursive, fast-forwarding state machine for wildcard evaluation.
// 
// Supported Pattern Operators:
//  * : Matches zero or more characters.
//  ? : Matches exactly one character.
//  | : Escape character (e.g., "|*" matches a literal asterisk).
//
// Scoping Rules:
//  When configured with SCOPE_PATH_SEGMENT, wildcard expansion ('*' and '?') will 
//  strictly halt upon encountering a native path separator ('\').
//
// Casing Rules:
//  Case-insensitive matching for 8-bit char strings is explicitly limited 
//  to ASCII (a-z -> A-Z) to guarantee safe execution at high IRQLs without locales.
//
// Template Parameters:
//   TContext - The user-defined context payload type returned upon successful matches.
//   TChar    - The character type of the patterns and targets (WCHAR or CHAR).
//   PoolType - The NT kernel pool flags used for internal data structures.
// -------------------------------------------------------------------------------------------
template <typename TContext, typename TChar = WCHAR, POOL_FLAGS PoolType = POOL_FLAG_NON_PAGED>
class KmStringPatternMatch
{
private:
    // Represents a slice of literal or wildcard text mapped in the pattern arena.
    struct PatternString
    {
        const TChar* Buffer; // Pointer to arena-backed character storage mapped from KStringArena
        UINT32       Length; // Overall character count of this specific string slice
    };

    // Tracks pattern metadata, prefixes, suffixes, and contextual payload index.
    struct PatternEntry
    {
        PatternString    LiteralPrefix;          // Initial exact literal prefix for hash mapping bounds
        PatternString    WildcardSuffix;         // Remaining pattern suffix containing wildcard operators
        PatternString    TailAnchor;             // Anchored trailing literal segment (if any)
        UINT32           Id;                     // Unique incremental identifier for this pattern record
        UINT32           ContextIndex;           // Offset index pointing to the user payload in m_ContextArena
        UINT16           MinWildcardMatchLength; // Minimum required character length for the wildcard suffix
        WILD_CARD_SCOPE  Scope;                  // Wildcard traversal scope boundary (e.g., SCOPE_PATH_SEGMENT)
        TChar            FirstLiteralChar;       // Fast-filter anchor character for slow-path evaluation paths
    };

    // Number of TChar characters packed into a single 64-bit SWAR block (4 for WCHAR, 8 for char).
    static constexpr UINT32 kCharsPerBlock = static_cast<UINT32>(sizeof(UINT64) / sizeof(TChar));

public:
    // -------------------------------------------------------------------------------------------
    // Initializes the pattern matcher with case sensitivity configuration.
    //
    // Parameters:
    //   bCaseInsensitive - True to evaluate strings without case sensitivity, false for exact match.
    // -------------------------------------------------------------------------------------------
    KmStringPatternMatch(_In_ bool bCaseInsensitive = false) noexcept;
    
    // -------------------------------------------------------------------------------------------
    // Destroys the pattern matcher, freeing all internal resources.
    // -------------------------------------------------------------------------------------------
    ~KmStringPatternMatch() noexcept = default;

    // -------------------------------------------------------------------------------------------
    // Registers a pattern, parsing out literal prefixes and caching contexts in the arena.
    //
    // Parameters:
    //   sPattern       - Pointer to the character array defining the wildcard pattern.
    //   cchPattern     - The length of the pattern in characters.
    //   WildScope      - The boundary scope to apply for wildcard operators.
    //   PatternContext - The user-defined context payload mapped to this specific pattern.
    //
    // Return:
    //   NTSTATUS indicating success, or STATUS_INSUFFICIENT_RESOURCES on memory allocation failure.
    // -------------------------------------------------------------------------------------------
    NTSTATUS AddPattern(_In_reads_(cchPattern) const TChar* __restrict sPattern,
                        _In_                   UINT32                  cchPattern,
                        _In_                   WILD_CARD_SCOPE         WildScope,
                        _Inout_                TContext&&              PatternContext);

    // -------------------------------------------------------------------------------------------
    // Searches for the first matching pattern context against the provided target text.
    //
    // Parameters:
    //   sText          - Pointer to the target text buffer to be evaluated.
    //   cchText        - The length of the target text in characters.
    //   PatternContext - Out-pointer receiving the matched payload context on success.
    //
    // Return:
    //   True if a match was found and PatternContext populated, false otherwise.
    // -------------------------------------------------------------------------------------------
    bool Search(_In_reads_(cchText)       const TChar* __restrict sText,
                _In_                      UINT32                  cchText,
                _Outptr_result_maybenull_ TContext**              PatternContext) const noexcept;

    // -------------------------------------------------------------------------------------------
    // Searches and collects all matching pattern contexts against the provided target text.
    //
    // Parameters:
    //   sText           - Pointer to the target text buffer to be evaluated.
    //   cchText         - The length of the target text in characters.
    //   PatternContexts - Vector receiving all context payloads that successfully matched.
    //
    // Return:
    //   NTSTATUS indicating success or vector growth allocation failures during the search.
    // -------------------------------------------------------------------------------------------
    NTSTATUS Search(_In_reads_(cchText) const TChar* __restrict             sText,
                    _In_                UINT32                              cchText,
                    _Out_               KVector<TContext*, PoolType>&       PatternContexts) const noexcept;

    // -------------------------------------------------------------------------------------------
    // Flushes all patterns, hash buckets, and memory arenas, resetting the engine to empty.
    // -------------------------------------------------------------------------------------------
    void Clear() noexcept;

private:
    // -------------------------------------------------------------------------------------------
    // Evaluates whether a given pattern's literal prefix matches the target text segment.
    // Utilizes 64-bit SWAR block comparisons with strict aliasing safe memory loads.
    //
    // Parameters:
    //   pattern   - The pattern entry containing the literal prefix to evaluate.
    //   sText     - Pointer to the target text buffer segment.
    //   cchLength - The length of the prefix in characters to compare.
    //
    // Return:
    //   True if the prefix completely matches the text segment, false otherwise.
    // -------------------------------------------------------------------------------------------
    template <bool IsCaseInsensitive>
    inline bool EvaluatePrefixMatch(_In_ const PatternEntry&                      pattern,
                                    _In_reads_(cchLength) const TChar* __restrict sText, 
                                    _In_                  UINT32                  cchLength) const noexcept;

    // -------------------------------------------------------------------------------------------
    // Evaluates whether a given pattern's anchored tail matches the end of the target text.
    // Utilizes 64-bit SWAR block comparisons with O(1) early rejection.
    //
    // Parameters:
    //   pattern - The pattern entry containing the tail anchor.
    //   sText   - Pointer to the target text buffer.
    //   cchText - Total character length of the target text.
    //
    // Return:
    //   True if the tail anchor matches or is empty, false otherwise.
    // -------------------------------------------------------------------------------------------
    template <bool IsCaseInsensitive>
    inline bool EvaluateTailMatch(_In_ const PatternEntry&                    pattern,
                                  _In_reads_(cchText) const TChar* __restrict sText,
                                  _In_ UINT32                                 cchText) const noexcept;

    // -------------------------------------------------------------------------------------------
    // Evaluates the wildcard suffix of a pattern against the remaining target text.
    // Routes the comparison to the appropriate wildcard state machine specialization.
    //
    // Parameters:
    //   pattern - The pattern entry containing the wildcard suffix.
    //   sText   - Pointer to the remaining unmatched text segment.
    //   cchText - Character length of the remaining text.
    //
    // Return:
    //   True if the wildcard suffix matches the remaining text, false otherwise.
    // -------------------------------------------------------------------------------------------
    template <bool IsCaseInsensitive>
    inline bool EvaluatePatternSuffix(_In_ const PatternEntry&                    pattern, 
                                      _In_reads_(cchText) const TChar* __restrict sText, 
                                      _In_                UINT32                  cchText) const noexcept;

    // -------------------------------------------------------------------------------------------
    // Evaluates all registered slow-path patterns (patterns beginning with wildcard operators).
    //
    // Parameters:
    //   sText     - Pointer to the target text buffer to be evaluated.
    //   cchText   - The length of the target text in characters.
    //   Collector - Functor executing context assignment when a match is found.
    //
    // Return:
    //   True if the early exit condition in the collector is met, false otherwise.
    // -------------------------------------------------------------------------------------------
    template <bool IsCaseInsensitive, typename F>
    inline bool ProcessSlowPath(_In_reads_(cchText) const TChar* __restrict sText,
                                _In_                UINT32                  cchText, 
                                _In_                F&                      Collector) const noexcept;

    // -------------------------------------------------------------------------------------------
    // Core pattern evaluation engine iterating through length filters and hash buckets.
    //
    // Parameters:
    //   sText     - Pointer to the target text.
    //   cchText   - Character length of the target text.
    //   Collector - Functor executing context assignment when a match is found.
    //
    // Return:
    //   True if the early exit condition in the collector is met, false otherwise.
    // -------------------------------------------------------------------------------------------
    template <bool IsCaseInsensitive, typename F>
    bool SearchInternal(_In_reads_(cchText) const TChar* __restrict sText, 
                        _In_                UINT32                  cchText, 
                        _In_                F&&                     Collector) const noexcept;

    // -------------------------------------------------------------------------------------------
    // Non-recursive wildcard state machine with fast-forward search optimization.
    //
    // Parameters:
    //   sPattern           - Pointer to the wildcard suffix of the pattern.
    //   cchPattern         - Character length of the wildcard suffix.
    //   sText              - Pointer to the remaining unmatched text segment.
    //   cchText            - Character length of the remaining text.
    //   remainingMinLength - Minimum matching characters required by the remaining pattern states.
    //
    // Return:
    //   True if the wildcard suffix wholly matches the remaining text, false otherwise.
    // -------------------------------------------------------------------------------------------
    template <bool IsCaseInsensitive, bool LimitWildScope>
    bool WildCardMatch(_In_reads_(cchPattern) const TChar* __restrict sPattern,
                       _In_                   UINT32                  cchPattern,
                       _In_reads_(cchText)    const TChar* __restrict sText,
                       _In_                   UINT32                  cchText,
                       _In_                   UINT32                  remainingMinLength) const noexcept;

private:
    UINT32 m_nPatternCount;         // Total number of registered patterns currently in the engine
    UINT32 m_nGlobalMinMatchLength; // Global minimum required character length across all registered patterns
    bool   m_bWildCardPresent;      // True if any registered pattern contains wildcard operators
    bool   m_bCaseInsensitive;      // True if matches are evaluated case-insensitively
    UINT64 m_HashFilter[8];         // 512-bit hash-existence filter bitmap array

    KVector<UINT32, PoolType>     m_LengthVec;    // Sorted unique literal prefix lengths
    KStringArena<TChar, PoolType> m_StringArena;  // Linear arena storing persistent pattern strings
    KDeque<TContext, PoolType>    m_ContextArena; // Flat storage preserving contextual payloads
    
    KFlatHashMap<UINT64, KVector<PatternEntry, PoolType>, KPrecomputedHash, PoolType> m_HashMap;      // Prefix hash map mapping literal prefix hashes to pattern arrays
    KVector<PatternEntry, PoolType>                                                   m_SlowPathList; // List of patterns starting immediately with wildcards

    static constexpr TChar kStar     = static_cast<TChar>('*'); // Wildcard operator matching zero or more characters
    static constexpr TChar kQuestion = static_cast<TChar>('?'); // Wildcard operator matching exactly one character
    static constexpr TChar kEscape   = static_cast<TChar>('|'); // Escape operator for literal pattern parsing
};

// Convenience typedef aliases for char and WCHAR instances.
template <typename TContext, POOL_FLAGS PoolType = POOL_FLAG_NON_PAGED>
using KmStringPatternMatchW = KmStringPatternMatch<TContext, WCHAR, PoolType>;

template <typename TContext, POOL_FLAGS PoolType = POOL_FLAG_NON_PAGED>
using KmStringPatternMatchA = KmStringPatternMatch<TContext, CHAR, PoolType>;

// -------------------------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------------------------

// -------------------------------------------------------------------------------------------
// Initializes the pattern matcher with case sensitivity configuration.
//
// Parameters:
//   bCaseInsensitive - True to evaluate strings without case sensitivity, false for exact match.
// -------------------------------------------------------------------------------------------
template <typename TContext, typename TChar, POOL_FLAGS PoolType>
KmStringPatternMatch<TContext, TChar, PoolType>::KmStringPatternMatch(_In_ bool bCaseInsensitive) noexcept : m_nPatternCount(0),
                                                                                                             m_nGlobalMinMatchLength(MAXUINT32),
                                                                                                             m_bWildCardPresent(false), 
                                                                                                             m_bCaseInsensitive(bCaseInsensitive),
                                                                                                             m_HashFilter{0}
{
}

// -------------------------------------------------------------------------------------------
// Registers a pattern, parsing out literal prefixes and caching contexts in the arena.
//
// Parameters:
//   sPattern      - Pointer to the character array defining the wildcard pattern.
//   cchPattern     - The length of the pattern in characters.
//   WildScope      - The boundary scope to apply for wildcard operators.
//   PatternContext - The user-defined context payload mapped to this specific pattern.
//
// Return:
//   NTSTATUS indicating success, or STATUS_INSUFFICIENT_RESOURCES on memory allocation failure.
// -------------------------------------------------------------------------------------------
template <typename TContext, typename TChar, POOL_FLAGS PoolType>
NTSTATUS KmStringPatternMatch<TContext, TChar, PoolType>::AddPattern(_In_reads_(cchPattern) const TChar* __restrict sPattern,
                                                                     _In_                   UINT32                  cchPattern,
                                                                     _In_                   WILD_CARD_SCOPE         WildScope,
                                                                     _Inout_                TContext&&              PatternContext)
{
    // Guard against integer overflow triggering kernel pool corruption during arena buffer allocation
    if (cchPattern > (MAXULONG_PTR - 4096) / sizeof(TChar)) [[unlikely]]
    {
        return STATUS_INVALID_PARAMETER;
    }

    // Guard against exceeding the maximum capacity of the context arena.
    // KDeque is segmented into a maximum of 256 blocks, with a default capacity of 512 elements per block.
    constexpr UINT32 kMaxPatterns = 256 * 512; // 131,072

    if (m_nPatternCount >= kMaxPatterns)
    {
        return STATUS_QUOTA_EXCEEDED;
    }

    NTSTATUS status;
    TChar*   pStableBuffer = nullptr;
    
    // Begin atomic transaction to prevent memory leaks on later failure paths
    auto bookmark = m_StringArena.GetBookmark();

    // Phase 1 parsing: Disassociate pattern raw length from normalized, unescaped literal prefix lengths
    UINT32 prefixRawLen       = 0;
    UINT32 prefixUnescapedLen = 0;
    
    while (prefixRawLen < cchPattern)
    {
        TChar c = sPattern[prefixRawLen];
        if (c == kStar || c == kQuestion)
        {
            break;
        }
        
        if (c == kEscape) [[unlikely]]
        {
            if (prefixRawLen + 1 < cchPattern)
            {
                TChar nextChar = sPattern[prefixRawLen + 1];
                if (nextChar == kStar || nextChar == kQuestion || nextChar == kEscape)
                {
                    prefixRawLen       += 2;
                    prefixUnescapedLen += 1;
                    continue;
                }
            }
            
            // Unrecognized escape sequence treated directly as literal character
            prefixRawLen       += 1;
            prefixUnescapedLen += 1;
            continue;
        }
        
        prefixRawLen       += 1;
        prefixUnescapedLen += 1;
    }

    UINT32 cchWildPart = cchPattern - prefixRawLen;

    if (cchPattern > 0)
    {
        // Allocate buffer matching the unescaped literal prefix length + raw wildcard suffix
        pStableBuffer = m_StringArena.Allocate(prefixUnescapedLen + cchWildPart);
        
        if (pStableBuffer == nullptr) [[unlikely]]
        {
            m_StringArena.RevertBookmark(bookmark);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        UINT32 dstIdx = 0;
        UINT32 srcIdx = 0;

        // Populate the unescaped literal prefix
        while (srcIdx < prefixRawLen)
        {
            TChar c = sPattern[srcIdx];
            
            if (c == kEscape && srcIdx + 1 < prefixRawLen) [[unlikely]]
            {
                TChar nextChar = sPattern[srcIdx + 1];
                if (nextChar == kStar || nextChar == kQuestion || nextChar == kEscape)
                {
                    pStableBuffer[dstIdx++] = m_bCaseInsensitive ? KmStringPatternMatchDetail::ToUpperFast(nextChar) : nextChar;
                    srcIdx += 2;
                    continue;
                }
            }
            
            pStableBuffer[dstIdx++] = m_bCaseInsensitive ? KmStringPatternMatchDetail::ToUpperFast(c) : c;
            srcIdx++;
        }

        // Copy raw wildcard suffix verbatim to maintain operator layout for the state machine
        for (UINT32 i = 0; i < cchWildPart; i++)
        {
            TChar c = sPattern[prefixRawLen + i];
            pStableBuffer[dstIdx++] = m_bCaseInsensitive ? KmStringPatternMatchDetail::ToUpperFast(c) : c;
        }
    }

    // Minimum match length calculation for the SUFFIX
    UINT32 suffixMinLength = 0;
    for (UINT32 i = 0; i < cchWildPart; ++i)
    {
        TChar c = pStableBuffer[prefixUnescapedLen + i];
        if (c == kEscape && i + 1 < cchWildPart)
        {
            TChar nextChar = pStableBuffer[prefixUnescapedLen + i + 1];
            if (nextChar == kStar || nextChar == kQuestion || nextChar == kEscape)
            {
                suffixMinLength++;
                i++;
                continue;
            }
        }

        if (c != kStar)
        {
            suffixMinLength++;
        }
    }

    // Tail Anchoring: Parse forward to safely extract the trailing literal segment after the final wildcard
    UINT32 lastWildcardEnd = 0;
    const TChar* pWildSuffix = (cchWildPart > 0) ? (pStableBuffer + prefixUnescapedLen) : nullptr;

    for (UINT32 i = 0; i < cchWildPart; ++i)
    {
        TChar c = pWildSuffix[i];
        if (c == kEscape && i + 1 < cchWildPart)
        {
            TChar nextChar = pWildSuffix[i + 1];
            if (nextChar == kStar || nextChar == kQuestion || nextChar == kEscape)
            {
                i++; // Safely skip the escaped character
                continue;
            }
        }
        
        if (c == kStar || c == kQuestion)
        {
            lastWildcardEnd = i + 1;
        }
    }

    UINT32 tailStart = lastWildcardEnd;
    UINT32 tailUnescapedLen = 0;

    for (UINT32 i = tailStart; i < cchWildPart; ++i)
    {
        TChar c = pWildSuffix[i];
        if (c == kEscape && i + 1 < cchWildPart)
        {
            TChar nextChar = pWildSuffix[i + 1];
            if (nextChar == kStar || nextChar == kQuestion || nextChar == kEscape)
            {
                tailUnescapedLen++;
                i++;
                continue;
            }
        }

        tailUnescapedLen++;
    }

    TChar* pTailBuffer = nullptr;
    if (tailUnescapedLen > 0)
    {
        pTailBuffer = m_StringArena.Allocate(tailUnescapedLen);
        if (pTailBuffer == nullptr) [[unlikely]]
        {
            m_StringArena.RevertBookmark(bookmark);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        UINT32 dstTailIdx = 0;
        for (UINT32 i = tailStart; i < cchWildPart; ++i)
        {
            TChar c = pWildSuffix[i];
            if (c == kEscape && i + 1 < cchWildPart)
            {
                TChar nextChar = pWildSuffix[i + 1];
                if (nextChar == kStar || nextChar == kQuestion || nextChar == kEscape)
                {
                    pTailBuffer[dstTailIdx++] = nextChar; // Case normalized in pStableBuffer copy
                    i++;
                    continue;
                }
            }

            pTailBuffer[dstTailIdx++] = c;
        }
    }

    // Since KDeque lacks PopBack(), we commit the context. 
    // If subsequent allocations fail, the context payload is orphaned but the large string slabs are rolled back safely.
    status = m_ContextArena.EmplaceBack(kstd::move(PatternContext));    
    if (!NT_SUCCESS(status)) [[unlikely]]
    {
        m_StringArena.RevertBookmark(bookmark);
        return status;
    }

    UINT32 ctxIndex = static_cast<UINT32>(m_ContextArena.Size() - 1);

    PatternEntry newEntry;
    newEntry.LiteralPrefix.Buffer   = pStableBuffer;
    newEntry.LiteralPrefix.Length   = prefixUnescapedLen;
    newEntry.TailAnchor.Buffer      = pTailBuffer;
    newEntry.TailAnchor.Length      = tailUnescapedLen;
    newEntry.Id                     = ++m_nPatternCount;
    newEntry.ContextIndex           = ctxIndex;
    newEntry.MinWildcardMatchLength = static_cast<UINT16>(suffixMinLength);
    newEntry.Scope                  = WildScope;
    newEntry.FirstLiteralChar       = 0;

    UINT32 requiredLength = prefixUnescapedLen + suffixMinLength;
    if (requiredLength < m_nGlobalMinMatchLength)
    {
        m_nGlobalMinMatchLength = requiredLength;
    }

    if (cchWildPart != 0)
    {
        newEntry.WildcardSuffix.Buffer = pStableBuffer + prefixUnescapedLen;
        newEntry.WildcardSuffix.Length = cchWildPart;
        m_bWildCardPresent             = true;
    }
    else
    {
        newEntry.WildcardSuffix.Buffer = nullptr;
        newEntry.WildcardSuffix.Length = 0;
    }

    // Isolate patterns beginning immediately with a wildcard to prevent hash map collisions 
    if (prefixUnescapedLen == 0)
    {
        for (UINT32 i = 0; i < cchWildPart; i++)
        {
            TChar c = newEntry.WildcardSuffix.Buffer[i];
            
            // Advance cache if the character is an explicitly escaped wildcard operator
            if (c == kEscape && i + 1 < cchWildPart) [[unlikely]]
            {
                TChar nextChar = newEntry.WildcardSuffix.Buffer[i + 1];

                if (nextChar == kStar || nextChar == kQuestion || nextChar == kEscape)
                {
                    newEntry.FirstLiteralChar = nextChar;
                    break;
                }
                else
                {
                    newEntry.FirstLiteralChar = c;
                    break;
                }
            }
            else if (c != kStar && c != kQuestion)
            {
                newEntry.FirstLiteralChar = c;
                break;
            }
        }
        
        status = m_SlowPathList.PushBack(newEntry);
        if (!NT_SUCCESS(status)) [[unlikely]]
        {
            m_StringArena.RevertBookmark(bookmark);
            return status;
        }
        
        return STATUS_SUCCESS;
    }

    // Hash logic circumvents double-uppercasing penalty since pStableBuffer is already case normalized
    UINT64 hash = KmStringPatternMatchDetail::CalculateHash(pStableBuffer, prefixUnescapedLen, 0);

    UINT32* itLength = m_LengthVec.begin();
    
    for (; itLength != m_LengthVec.end(); ++itLength)
    {
        if (*itLength >= prefixUnescapedLen)
        {
            break;
        }
    }

    if (itLength == m_LengthVec.end() || *itLength != prefixUnescapedLen)
    {
        status = m_LengthVec.Insert(itLength, prefixUnescapedLen);
        if (!NT_SUCCESS(status)) [[unlikely]]
        {
            m_StringArena.RevertBookmark(bookmark);
            return status;
        }
    }

    KVector<PatternEntry, PoolType>* pBucket = nullptr;
    status = m_HashMap.GetOrInsert(hash, &pBucket);
    if (!NT_SUCCESS(status)) [[unlikely]]
    {
        m_StringArena.RevertBookmark(bookmark);
        return status;
    }

    status = pBucket->PushBack(newEntry);
    if (!NT_SUCCESS(status)) [[unlikely]]
    {
        m_StringArena.RevertBookmark(bookmark);
        return status;
    }

    // Distribute bits via shifted segment map across the 512-bit array
    // Defers hash-existence filter mutation until the entire insertion transaction is guaranteed to succeed
    SPM_BIT_TEST_AND_SET64(m_HashFilter[(hash >> 6) & 7], hash & 63);

    return STATUS_SUCCESS;
}

// -------------------------------------------------------------------------------------------
// Flushes all patterns, hash buckets, and memory arenas, resetting the engine to empty.
// -------------------------------------------------------------------------------------------
template <typename TContext, typename TChar, POOL_FLAGS PoolType>
void KmStringPatternMatch<TContext, TChar, PoolType>::Clear() noexcept
{
    m_HashMap.Clear();
    m_SlowPathList.Clear();
    m_LengthVec.Clear();
    m_StringArena.Clear();
    m_ContextArena.Clear();

    m_nPatternCount         = 0;
    m_nGlobalMinMatchLength = MAXUINT32;
    m_bWildCardPresent      = false;
    
    for (int i = 0; i < 8; i++)
    {
        m_HashFilter[i] = 0;
    }
}

// -------------------------------------------------------------------------------------------
// Searches for the first matching pattern context against the provided target text.
//
// Parameters:
//   sText          - Pointer to the target text buffer to be evaluated.
//   cchText        - The length of the target text in characters.
//   PatternContext - Out-pointer receiving the matched payload context on success.
//
// Return:
//   True if a match was found and PatternContext populated, false otherwise.
// -------------------------------------------------------------------------------------------
template <typename TContext, typename TChar, POOL_FLAGS PoolType>
bool KmStringPatternMatch<TContext, TChar, PoolType>::Search(_In_reads_(cchText)       const TChar* __restrict sText,
                                                             _In_                      UINT32                  cchText,
                                                             _Outptr_result_maybenull_ TContext**              PatternContext) const noexcept
{
    *PatternContext = nullptr;

    auto collector = [&](const TContext* pContext) -> bool
    {
        *PatternContext = const_cast<TContext*>(pContext);
        return true; 
    };

    if (m_bCaseInsensitive)
    {
        return SearchInternal<true>(sText, cchText, collector);
    }
    else
    {
        return SearchInternal<false>(sText, cchText, collector);
    }
}

// -------------------------------------------------------------------------------------------
// Searches and collects all matching pattern contexts against the provided target text.
//
// Parameters:
//   sText           - Pointer to the target text buffer to be evaluated.
//   cchText         - The length of the target text in characters.
//   PatternContexts - Vector receiving all context payloads that successfully matched.
//
// Return:
//   NTSTATUS indicating success or vector growth allocation failures during the search.
// -------------------------------------------------------------------------------------------
template <typename TContext, typename TChar, POOL_FLAGS PoolType>
NTSTATUS KmStringPatternMatch<TContext, TChar, PoolType>::Search(_In_reads_(cchText) const TChar* __restrict             sText,
                                                                 _In_                UINT32                              cchText,
                                                                 _Out_               KVector<TContext*, PoolType>&       PatternContexts) const noexcept
{
    PatternContexts.Clear();

    NTSTATUS outStatus = STATUS_SUCCESS;

    auto collector = [&](const TContext* pContext) -> bool
    {
        NTSTATUS status = PatternContexts.PushBack(const_cast<TContext*>(pContext));
        
        if (!NT_SUCCESS(status)) [[unlikely]]
        {
            outStatus = status;
            return true; 
        }
        
        return false; 
    };

    if (m_bCaseInsensitive)
    {
        SearchInternal<true>(sText, cchText, collector);
    }
    else
    {
        SearchInternal<false>(sText, cchText, collector);
    }
    
    return outStatus;
}

// -------------------------------------------------------------------------------------------
// Evaluates whether a given pattern's literal prefix matches the target text segment.
// Utilizes 64-bit SWAR block comparisons with strict aliasing safe memory loads.
//
// Parameters:
//   pattern   - The pattern entry containing the literal prefix to evaluate.
//   sText     - Pointer to the target text buffer segment.
//   cchLength - The length of the prefix in characters to compare.
//
// Return:
//   True if the prefix completely matches the text segment, false otherwise.
// -------------------------------------------------------------------------------------------
template <typename TContext, typename TChar, POOL_FLAGS PoolType>
template <bool IsCaseInsensitive>
inline bool KmStringPatternMatch<TContext, TChar, PoolType>::EvaluatePrefixMatch(_In_ const PatternEntry&                      pattern, 
                                                                                 _In_reads_(cchLength) const TChar* __restrict sText, 
                                                                                 _In_                  UINT32                  cchLength) const noexcept
{    
    auto Read64Safe = [](const void* ptr) -> UINT64 
    {
        UINT64 val;
        memcpy(&val, ptr, sizeof(UINT64));
        return val;
    };

    if (cchLength >= kCharsPerBlock)
    {
        UINT32 chunks = cchLength / kCharsPerBlock;
        
        for (UINT32 i = 0; i < chunks; i++)
        {
            UINT64 wPat = Read64Safe(pattern.LiteralPrefix.Buffer + (i * kCharsPerBlock));
            UINT64 wTxt = Read64Safe(sText + (i * kCharsPerBlock));
            
            if constexpr (IsCaseInsensitive)
            {
                if (KmStringPatternMatchDetail::IsAsciiSWAR<TChar>(wTxt))
                {
                    if (wPat != KmStringPatternMatchDetail::ToUpperSWAR<TChar>(wTxt))
                    {
                        return false;
                    }
                }
                else
                {
                    for (UINT32 k = 0; k < kCharsPerBlock; k++)
                    {
                        if (pattern.LiteralPrefix.Buffer[i * kCharsPerBlock + k] != KmStringPatternMatchDetail::ToUpperFast(sText[i * kCharsPerBlock + k]))
                        {
                            return false;
                        }
                    }
                }
            }
            else
            {
                if (wPat != wTxt)
                {
                    return false;
                }
            }
        }
        
        if ((cchLength & (kCharsPerBlock - 1)) != 0)
        {
            // Overlapping SWAR Tail Comparison: Check remaining characters
            // via a single 64-bit unaligned load overlapping the end of the prefix.
            UINT64 wPatTail = Read64Safe(pattern.LiteralPrefix.Buffer + cchLength - kCharsPerBlock);
            UINT64 wTxtTail = Read64Safe(sText + cchLength - kCharsPerBlock);
            
            if constexpr (IsCaseInsensitive)
            {
                if (KmStringPatternMatchDetail::IsAsciiSWAR<TChar>(wTxtTail))
                {
                    if (wPatTail != KmStringPatternMatchDetail::ToUpperSWAR<TChar>(wTxtTail))
                    {
                        return false;
                    }
                }
                else
                {
                    for (UINT32 k = 0; k < kCharsPerBlock; k++)
                    {
                        if (pattern.LiteralPrefix.Buffer[cchLength - kCharsPerBlock + k] != KmStringPatternMatchDetail::ToUpperFast(sText[cchLength - kCharsPerBlock + k]))
                        {
                            return false;
                        }
                    }
                }
            }
            else
            {
                if (wPatTail != wTxtTail)
                {
                    return false;
                }
            }
        }
    }
    else
    {
        // Fallback loop for prefixes under kCharsPerBlock characters
        for (UINT32 i = 0; i < cchLength; i++)
        {
            if constexpr (IsCaseInsensitive)
            {
                if (pattern.LiteralPrefix.Buffer[i] != KmStringPatternMatchDetail::ToUpperFast(sText[i]))
                {
                    return false;
                }
            }
            else
            {
                if (pattern.LiteralPrefix.Buffer[i] != sText[i])
                {
                    return false;
                }
            }
        }
    }

    return true;
}

// -------------------------------------------------------------------------------------------
// Evaluates whether a given pattern's anchored tail matches the end of the target text.
// Utilizes 64-bit SWAR block comparisons with O(1) early rejection.
//
// Parameters:
//   pattern - The pattern entry containing the tail anchor.
//   sText   - Pointer to the target text buffer.
//   cchText - Total character length of the target text.
//
// Return:
//   True if the tail anchor matches or is empty, false otherwise.
// -------------------------------------------------------------------------------------------
template <typename TContext, typename TChar, POOL_FLAGS PoolType>
template <bool IsCaseInsensitive>
inline bool KmStringPatternMatch<TContext, TChar, PoolType>::EvaluateTailMatch(_In_ const PatternEntry&                    pattern,
                                                                               _In_reads_(cchText) const TChar* __restrict sText,
                                                                               _In_ UINT32                                 cchText) const noexcept
{
    if (pattern.TailAnchor.Length == 0)
    {
        return true;
    }

    const TChar* sTail   = sText + (cchText - pattern.TailAnchor.Length);
    UINT32       tailLen = pattern.TailAnchor.Length;

    auto Read64Safe = [](const void* ptr) -> UINT64 
    {
        UINT64 val;
        memcpy(&val, ptr, sizeof(UINT64));
        return val;
    };

    if (tailLen >= kCharsPerBlock)
    {
        UINT32 chunks = tailLen / kCharsPerBlock;
        
        for (UINT32 i = 0; i < chunks; i++)
        {
            UINT64 wPat = Read64Safe(pattern.TailAnchor.Buffer + (i * kCharsPerBlock));
            UINT64 wTxt = Read64Safe(sTail + (i * kCharsPerBlock));
            
            if constexpr (IsCaseInsensitive)
            {
                if (KmStringPatternMatchDetail::IsAsciiSWAR<TChar>(wTxt))
                {
                    if (wPat != KmStringPatternMatchDetail::ToUpperSWAR<TChar>(wTxt))
                    {
                        return false;
                    }
                }
                else
                {
                    for (UINT32 k = 0; k < kCharsPerBlock; k++)
                    {
                        if (pattern.TailAnchor.Buffer[i * kCharsPerBlock + k] != KmStringPatternMatchDetail::ToUpperFast(sTail[i * kCharsPerBlock + k]))
                        {
                            return false;
                        }
                    }
                }
            }
            else
            {
                if (wPat != wTxt)
                {
                    return false;
                }
            }
        }
        
        if ((tailLen & (kCharsPerBlock - 1)) != 0)
        {
            UINT64 wPatTail = Read64Safe(pattern.TailAnchor.Buffer + tailLen - kCharsPerBlock);
            UINT64 wTxtTail = Read64Safe(sTail + tailLen - kCharsPerBlock);
            
            if constexpr (IsCaseInsensitive)
            {
                if (KmStringPatternMatchDetail::IsAsciiSWAR<TChar>(wTxtTail))
                {
                    if (wPatTail != KmStringPatternMatchDetail::ToUpperSWAR<TChar>(wTxtTail))
                    {
                        return false;
                    }
                }
                else
                {
                    for (UINT32 k = 0; k < kCharsPerBlock; k++)
                    {
                        if (pattern.TailAnchor.Buffer[tailLen - kCharsPerBlock + k] != KmStringPatternMatchDetail::ToUpperFast(sTail[tailLen - kCharsPerBlock + k]))
                        {
                            return false;
                        }
                    }
                }
            }
            else
            {
                if (wPatTail != wTxtTail)
                {
                    return false;
                }
            }
        }
    }
    else
    {
        for (UINT32 i = 0; i < tailLen; ++i)
        {
            if constexpr (IsCaseInsensitive)
            {
                if (pattern.TailAnchor.Buffer[i] != KmStringPatternMatchDetail::ToUpperFast(sTail[i]))
                {
                    return false;
                }
            }
            else
            {
                if (pattern.TailAnchor.Buffer[i] != sTail[i])
                {
                    return false;
                }
            }
        }
    }

    return true;
}

// -------------------------------------------------------------------------------------------
// Evaluates the wildcard suffix of a pattern against the remaining target text.
// Routes the comparison to the appropriate wildcard state machine specialization.
//
// Parameters:
//   pattern - The pattern entry containing the wildcard suffix.
//   sText   - Pointer to the remaining unmatched text segment.
//   cchText - Character length of the remaining text.
//
// Return:
//   True if the wildcard suffix matches the remaining text, false otherwise.
// -------------------------------------------------------------------------------------------
template <typename TContext, typename TChar, POOL_FLAGS PoolType>
template <bool IsCaseInsensitive>
inline bool KmStringPatternMatch<TContext, TChar, PoolType>::EvaluatePatternSuffix(_In_ const PatternEntry&                    pattern, 
                                                                                   _In_reads_(cchText) const TChar* __restrict sText, 
                                                                                   _In_                UINT32                  cchText) const noexcept
{
    if constexpr (IsCaseInsensitive)
    {
        if (pattern.Scope == SCOPE_PATH_SEGMENT)
        {
            return WildCardMatch<true, true>(pattern.WildcardSuffix.Buffer,
                                             pattern.WildcardSuffix.Length,
                                             sText,
                                             cchText,
                                             pattern.MinWildcardMatchLength);
        }
        else
        {
            return WildCardMatch<true, false>(pattern.WildcardSuffix.Buffer,
                                              pattern.WildcardSuffix.Length,
                                              sText,
                                              cchText,
                                              pattern.MinWildcardMatchLength);
        }
    }
    else
    {
        if (pattern.Scope == SCOPE_PATH_SEGMENT)
        {
            return WildCardMatch<false, true>(pattern.WildcardSuffix.Buffer,
                                              pattern.WildcardSuffix.Length,
                                              sText,
                                              cchText,
                                              pattern.MinWildcardMatchLength);
        }
        else
        {
            return WildCardMatch<false, false>(pattern.WildcardSuffix.Buffer,
                                               pattern.WildcardSuffix.Length,
                                               sText,
                                               cchText,
                                               pattern.MinWildcardMatchLength);
        }
    }
}

// -------------------------------------------------------------------------------------------
// Evaluates all registered slow-path patterns (patterns beginning with wildcard operators).
//
// Parameters:
//   sText     - Pointer to the target text buffer to be evaluated.
//   cchText   - The length of the target text in characters.
//   Collector - Functor executing context assignment when a match is found.
//
// Return:
//   True if the early exit condition in the collector is met, false otherwise.
// -------------------------------------------------------------------------------------------
template <typename TContext, typename TChar, POOL_FLAGS PoolType>
template <bool IsCaseInsensitive, typename F>
inline bool KmStringPatternMatch<TContext, TChar, PoolType>::ProcessSlowPath(_In_reads_(cchText) const TChar* __restrict sText, 
                                                                             _In_                UINT32                  cchText, 
                                                                             _In_                F&                      Collector) const noexcept
{
    if (m_SlowPathList.Size() == 0)
    {
        return false;
    }

    for (auto pEntry = m_SlowPathList.begin(); pEntry != m_SlowPathList.end(); ++pEntry)
    {
        const PatternEntry& pattern = *pEntry;

        if (cchText < pattern.MinWildcardMatchLength)
        {
            continue;
        }

        // FirstLiteralChar Optimization: O(N) early rejection before state machine evaluation
        if (pattern.FirstLiteralChar != 0)
        {
            bool bFound = false;
            
            for (UINT32 i = 0; i < cchText; ++i)
            {
                if constexpr (IsCaseInsensitive)
                {
                    if (KmStringPatternMatchDetail::ToUpperFast(sText[i]) == pattern.FirstLiteralChar)
                    {
                        bFound = true;
                        break;
                    }
                }
                else
                {
                    if (sText[i] == pattern.FirstLiteralChar)
                    {
                        bFound = true;
                        break;
                    }
                }
            }

            if (!bFound)
            {
                continue;
            }
        }

        if (!EvaluateTailMatch<IsCaseInsensitive>(pattern, sText, cchText))
        {
            continue;
        }

        if (EvaluatePatternSuffix<IsCaseInsensitive>(pattern, sText, cchText))
        {
            if (Collector(&m_ContextArena[pattern.ContextIndex]))
            {
                return true;
            }
        }
    }

    return false;
}

// -------------------------------------------------------------------------------------------
// Core pattern evaluation engine iterating through length filters and hash buckets.
//
// Parameters:
//   sText     - Pointer to the target text.
//   cchText   - Character length of the target text.
//   Collector - Functor executing context assignment when a match is found.
//
// Return:
//   True if the early exit condition in the collector is met, false otherwise.
// -------------------------------------------------------------------------------------------
template <typename TContext, typename TChar, POOL_FLAGS PoolType>
template <bool IsCaseInsensitive, typename F>
bool KmStringPatternMatch<TContext, TChar, PoolType>::SearchInternal(_In_reads_(cchText) const TChar* __restrict sText, 
                                                                     _In_                UINT32                  cchText, 
                                                                     _In_                F&&                     Collector) const noexcept
{
    if (m_nPatternCount == 0 || cchText < m_nGlobalMinMatchLength) [[unlikely]]
    {
        return false;
    }

    if (m_SlowPathList.Size() == 0 && (m_LengthVec.Size() == 0 || cchText < *m_LengthVec.begin())) [[unlikely]]
    {
        return false;
    }

    const UINT32* itStart = m_LengthVec.begin();
    
    if (!m_bWildCardPresent)
    {
        // Safe length boundary check bypass for pure zero-length literal constraints
        if (m_LengthVec.Size() > 0)
        {
            if (cchText > *(m_LengthVec.end() - 1)) [[unlikely]]
            {
                return false;
            }

            const UINT32* first = m_LengthVec.begin();
            SIZE_T count = m_LengthVec.Size();
            
            while (count > 0)
            {
                SIZE_T step = count / 2;
                const UINT32* mid = first + step;
                
                if (*mid < cchText)
                {
                    first = mid + 1;
                    count -= step + 1;
                }
                else
                {
                    count = step;
                }
            }
            
            if (first == m_LengthVec.end() || *first != cchText) [[unlikely]]
            {
                return false;
            }
            
            itStart = first;
        }
        else
        {
            if (cchText > 0) [[unlikely]]
            {
                return false;
            }
        }
    }

    // Safely load 64-bit blocks avoiding C++ Strict Aliasing UB
    auto Read64Safe = [](const void* ptr) -> UINT64 
    {
        UINT64 val;
        memcpy(&val, ptr, sizeof(UINT64));
        return val;
    };

    constexpr UINT64 kPrime = 0x8bb84b93962eacc9ULL;

    UINT64 chunkHash    = 0;
    SIZE_T currentChunk = 0; // Use SIZE_T to prevent integer overflow bound bypass

    for (const UINT32* it = itStart; it != m_LengthVec.end(); ++it)
    {
        UINT32 cchLength = *it;

        if (cchLength > cchText)
        {
            break;
        }

        if (!m_bWildCardPresent && cchLength != cchText)
        {
            continue;
        }

        // Cast to SIZE_T prior to multiplication to prevent integer overflow
        SIZE_T targetChunks = (static_cast<SIZE_T>(cchLength) * sizeof(TChar)) / 8;

        // Monotonically advance full 64-bit SWAR chunk state without restarting from index 0
        while (currentChunk < targetChunks)
        {
            UINT64 w = Read64Safe(sText + (currentChunk * kCharsPerBlock));

            if constexpr (IsCaseInsensitive)
            {
                if (KmStringPatternMatchDetail::IsAsciiSWAR<TChar>(w))
                {
                    w = KmStringPatternMatchDetail::ToUpperSWAR<TChar>(w);
                }
                else
                {
                    UINT64       folded = 0;
                    const TChar* pChunk = sText + (currentChunk * kCharsPerBlock);

                    for (UINT32 k = 0; k < kCharsPerBlock; k++)
                    {
                        folded |= (KmStringPatternMatchDetail::CharToUint64(KmStringPatternMatchDetail::ToUpperFast(pChunk[k])) << (k * sizeof(TChar) * 8));
                    }

                    w = folded;
                }
            }

            chunkHash = KmStringPatternMatchDetail::Mix64(chunkHash ^ w, kPrime);
            currentChunk++;
        }

        UINT64 Hash           = chunkHash;
        UINT32 remainingChars = cchLength - static_cast<UINT32>(targetChunks * kCharsPerBlock);

        // Evaluate remaining unaligned characters into a temporary hash without mutating chunkHash
        if (remainingChars > 0)
        {
            UINT64       tail  = 0;
            const TChar* pTail = sText + (targetChunks * kCharsPerBlock);

            for (UINT32 j = 0; j < remainingChars; j++)
            {
                if constexpr (IsCaseInsensitive)
                {
                    tail |= (KmStringPatternMatchDetail::CharToUint64(KmStringPatternMatchDetail::ToUpperFast(pTail[j])) << (j * sizeof(TChar) * 8));
                }
                else
                {
                    tail |= (KmStringPatternMatchDetail::CharToUint64(pTail[j]) << (j * sizeof(TChar) * 8));
                }
            }

            Hash = KmStringPatternMatchDetail::Mix64(chunkHash ^ tail, kPrime);
        }

        // Fast-path rejection via hash-existence filter
        if (!SPM_BIT_TEST64(m_HashFilter[(Hash >> 6) & 7], Hash & 63)) [[likely]]
        {
            continue;
        }

        const KVector<PatternEntry, PoolType>* pBucket = m_HashMap.Find(Hash);
        
        if (pBucket != nullptr) [[likely]]
        {
            for (auto pEntry = pBucket->begin(); pEntry != pBucket->end(); ++pEntry)
            {
                const PatternEntry& pattern = *pEntry;

                if (pattern.LiteralPrefix.Length == cchLength)
                {
                    if (cchText < cchLength + pattern.MinWildcardMatchLength)
                    {
                        continue;
                    }

                    if (EvaluatePrefixMatch<IsCaseInsensitive>(pattern, sText, cchLength))
                    {
                        if (cchLength == cchText)
                        {
                            bool bOnlyStars = true;
                            
                            for (UINT32 i = 0; i < pattern.WildcardSuffix.Length; ++i)
                            {
                                if (pattern.WildcardSuffix.Buffer[i] != kStar)
                                {
                                    bOnlyStars = false;
                                    break;
                                }
                            }

                            if (bOnlyStars)
                            {
                                if (Collector(&m_ContextArena[pattern.ContextIndex]))
                                {
                                    return true;
                                }
                            }
                        }
                        else
                        {
                            if (EvaluateTailMatch<IsCaseInsensitive>(pattern, sText, cchText))
                            {
                                if (EvaluatePatternSuffix<IsCaseInsensitive>(pattern, sText + cchLength, cchText - cchLength))
                                {
                                    if (Collector(&m_ContextArena[pattern.ContextIndex]))
                                    {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if (!m_bWildCardPresent)
        {
            break;
        }
    }

    return ProcessSlowPath<IsCaseInsensitive>(sText, cchText, Collector);
}

// -------------------------------------------------------------------------------------------
// Non-recursive wildcard state machine with fast-forward search optimization.
//
// Parameters:
//   sPattern           - Pointer to the wildcard suffix of the pattern.
//   cchPattern         - Character length of the wildcard suffix.
//   sText              - Pointer to the remaining unmatched text segment.
//   cchText            - Character length of the remaining text.
//   remainingMinLength - Minimum matching characters required by the remaining pattern states.
//
// Return:
//   True if the wildcard suffix wholly matches the remaining text, false otherwise.
// -------------------------------------------------------------------------------------------
template <typename TContext, typename TChar, POOL_FLAGS PoolType>
template <bool IsCaseInsensitive, bool LimitWildScope>
bool KmStringPatternMatch<TContext, TChar, PoolType>::WildCardMatch(_In_reads_(cchPattern) const TChar* __restrict sPattern,
                                                                    _In_                   UINT32                  cchPattern,
                                                                    _In_reads_(cchText)    const TChar* __restrict sText,
                                                                    _In_                   UINT32                  cchText,
                                                                    _In_                   UINT32                  remainingMinLength) const noexcept
{
    const TChar* s          = sText;
    const TChar* p          = sPattern;
    const TChar* StringEnd  = sText + cchText;
    const TChar* PatternEnd = sPattern + cchPattern;

    const TChar* lastStarP        = nullptr;
    const TChar* lastStarS        = nullptr;
    UINT32       starRemainingMinLength = 0;

    // Fast-Forward Engine: Propels the evaluation cursor O(N) towards the required sequence 
    // without invoking recursive state transitions inside the wildcard state machine loop.
    auto fastForward = [&](TChar target) -> bool
    {
        auto checkChar = [&](TChar c) -> bool
        {
            if constexpr (IsCaseInsensitive)
            {
                return KmStringPatternMatchDetail::ToUpperFast(c) == target;
            }
            else
            {
                return c == target;
            }
        };

        while (s + 3 < StringEnd)
        {
            if (checkChar(s[0])) 
            {
                return true;
            }
            
            if constexpr (LimitWildScope)
            {
                if (KmStringPatternMatchDetail::IsPathSeparator(s[0])) [[unlikely]]
                {
                    return false;
                }
            }
            
            if (checkChar(s[1])) 
            { 
                s += 1; 
                return true; 
            }
            
            if constexpr (LimitWildScope)
            {
                if (KmStringPatternMatchDetail::IsPathSeparator(s[1])) [[unlikely]]
                {
                    return false;
                }
            }
            
            if (checkChar(s[2])) 
            { 
                s += 2; 
                return true; 
            }
            
            if constexpr (LimitWildScope)
            {
                if (KmStringPatternMatchDetail::IsPathSeparator(s[2])) [[unlikely]]
                {
                    return false;
                }
            }
            
            if (checkChar(s[3])) 
            { 
                s += 3; 
                return true; 
            }
            
            if constexpr (LimitWildScope)
            {
                if (KmStringPatternMatchDetail::IsPathSeparator(s[3])) [[unlikely]]
                {
                    return false;
                }
            }
            
            s += 4;
        }
        
        while (s < StringEnd)
        {
            if (checkChar(*s)) 
            {
                return true;
            }
            
            if constexpr (LimitWildScope)
            {
                if (KmStringPatternMatchDetail::IsPathSeparator(*s)) [[unlikely]]
                {
                    return false;
                }
            }
            
            s++;
        }
        
        return false;
    };

    auto matchChar = [](TChar patChar,
                        TChar strChar) -> bool
    {
        if constexpr (IsCaseInsensitive)
        {
            return patChar == KmStringPatternMatchDetail::ToUpperFast(strChar);
        }
        else
        {
            return patChar == strChar;
        }
    };

    while (s < StringEnd)
    {
        // Remaining-length bounds check
        if (static_cast<UINT32>(StringEnd - s) < remainingMinLength)
        {
            goto HandleMismatch;
        }

        if (p < PatternEnd)
        {
            switch (*p)
            {
                case kStar:
                {
                    do 
                    {
                        p++;
                    } 
                    while (p < PatternEnd && *p == kStar);

                    if (p == PatternEnd)
                    {
                        if constexpr (LimitWildScope)
                        {
                            while (s < StringEnd)
                            {
                                if (KmStringPatternMatchDetail::IsPathSeparator(*s)) [[unlikely]]
                                {
                                    return false;
                                }
                                
                                s++;
                            }
                        }

                        return true;
                    }

                    lastStarP = p;
                    starRemainingMinLength = remainingMinLength;

                    // Engage the linear fast-forward cursor instead of locking into character increments
                    TChar target         = 0;
                    bool  canFastForward = false;
                    
                    if (*p != kQuestion)
                    {
                        if (*p == kEscape && p + 1 < PatternEnd && (p[1] == kStar || p[1] == kQuestion || p[1] == kEscape))
                        {
                            target = p[1];
                            canFastForward = true;
                        }
                        else
                        {
                            target = *p;
                            canFastForward = true;
                        }
                    }

                    if (canFastForward)
                    {
                        if (!fastForward(target))
                        {
                            return false;
                        }
                    }

                    lastStarS = s;
                    continue;
                }

                case kQuestion:
                {
                    if constexpr (LimitWildScope)
                    {
                        if (KmStringPatternMatchDetail::IsPathSeparator(*s)) [[unlikely]]
                        {
                            break; 
                        }
                    }
                    
                    p++;
                    s++;
                    remainingMinLength--;
                    continue;
                }

                case kEscape:
                {
                    if (p + 1 < PatternEnd) [[likely]]
                    {
                        if (p[1] == kStar || p[1] == kQuestion || p[1] == kEscape)
                        {
                            if (matchChar(p[1], *s))
                            {
                                p += 2;
                                s++;
                                remainingMinLength--;
                                continue;
                            }
                        }
                        else
                        {
                            if (matchChar(*p, *s))
                            {
                                p++;
                                s++;
                                remainingMinLength--;
                                continue;
                            }
                        }
                    }
                    else
                    {
                        if (matchChar(*p, *s))
                        {
                            p++;
                            s++;
                            remainingMinLength--;
                            continue;
                        }
                    }
                    break;
                }

                default:
                {
                    if (matchChar(*p, *s))
                    {
                        p++;
                        s++;
                        remainingMinLength--;
                        continue;
                    }
                    break;
                }
            }
        }

        // Backtracking jump: Recover state from the most recent wildcard operator
    HandleMismatch:
        if (lastStarP != nullptr)
        {
            if constexpr (LimitWildScope)
            {
                if (KmStringPatternMatchDetail::IsPathSeparator(*lastStarS)) [[unlikely]]
                {
                    return false;
                }
            }

            p = lastStarP;
            s = lastStarS + 1; // Increment to resume backtracking past previous failure position
            remainingMinLength = starRemainingMinLength;
            
            // Re-engage the linear fast-forward cursor for subsequent tracking jumps
            TChar target         = 0;
            bool  canFastForward = false;
            
            if (*p != kQuestion)
            {
                if (*p == kEscape && p + 1 < PatternEnd && (p[1] == kStar || p[1] == kQuestion || p[1] == kEscape))
                {
                    target = p[1];
                    canFastForward = true;
                }
                else
                {
                    target = *p; 
                    canFastForward = true;
                }
            }

            if (canFastForward)
            {
                if (!fastForward(target)) 
                {
                    return false;
                }
            }

            lastStarS = s;
            continue;
        }

        return false;
    }

    while (p < PatternEnd && *p == kStar)
    {
        p++;
    }

    return (p == PatternEnd);
}
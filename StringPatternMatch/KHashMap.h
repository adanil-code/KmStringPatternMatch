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
#include <ntintsafe.h>
#include "PlatformUtils.h"

#if !defined(_M_X64) && !defined(_M_ARM64)
    #error "KHashMap.h requires a 64-bit architecture (x64 or ARM64)."
#endif

//--------------------------------------------------------------------------------
// High-performance kernel hasher providing near-uniform 64-bit bit distribution 
// and strict avalanche characteristics. Specially optimized for SwissTable 
// probing architectures where both low bits (bucket index) and high 7 bits 
// require statistical randomization.
//
// Template Parameters:
//   T - The structural type of the key being hashed.
//--------------------------------------------------------------------------------
template <typename T>
struct KDefaultHash
{
    //--------------------------------------------------------------------------------
    // Low-latency 128-bit multiply-fold mixer (~5-6 cycles on x64/ARM64).
    // Pre-folds the upper 32 bits into the lower 32 bits before multiplying so that
    // high-bit entropy avalanches into both halves of the 128-bit product, then folds
    // the low and high 64-bit halves so every input bit avalanches across both the
    // lower bucket index bits and upper 7 H2 bits.
    //
    // Parameters:
    //   Val - The 64-bit seed or block to be avalanched.
    //
    // Return:
    //   The mixed 64-bit value ensuring uniform bit distribution.
    //--------------------------------------------------------------------------------
    static __forceinline UINT64 Mix64(_In_ UINT64 Val) noexcept
    {        
        Val ^= Val >> 32;

        UINT64 low, high;
    #if defined(_M_X64)
        low = _umul128(Val + 0x9E3779B97F4A7C15ULL, 0xBF58476D1CE4E5B9ULL, &high);
    #elif defined(_M_ARM64)
        const UINT64 a = Val + 0x9E3779B97F4A7C15ULL;
        constexpr UINT64 b = 0xBF58476D1CE4E5B9ULL;
        low  = a * b;
        high = __umulh(a, b);
    #endif
        return low ^ high;
    }

    //--------------------------------------------------------------------------------
    // Computes the hash for the given key based on its structural size.
    // Memory is copied to bypass C++ strict aliasing violations.
    //
    // Parameters:
    //   Key - The structural element being hashed.
    //
    // Return:
    //   A 64-bit randomized hash value corresponding to the input.
    //--------------------------------------------------------------------------------
    SIZE_T operator()(_In_ const T& Key) const noexcept
    {
        static_assert(kstd::has_unique_object_representations_v<T>,
            "KDefaultHash requires types without padding to prevent uninitialized memory entropy leaks.");

        if constexpr (sizeof(T) == 8)
        {
            // Scalar path for 64-bit integers, pointers, handles, and 8-byte structures.
            UINT64 val;
            RtlCopyMemory(&val, &Key, sizeof(UINT64));
            return static_cast<SIZE_T>(Mix64(val));
        }
        else if constexpr (sizeof(T) == 4)
        {
            // Scalar path for 32-bit integers, ULONGs, NTSTATUS codes, etc.
            UINT32 val;
            RtlCopyMemory(&val, &Key, sizeof(UINT32));
            return static_cast<SIZE_T>(Mix64(static_cast<UINT64>(val)));
        }
        else if constexpr (sizeof(T) == 2)
        {
            // Scalar path for 16-bit integers, USHORT, WCHAR, etc.
            UINT16 val;
            RtlCopyMemory(&val, &Key, sizeof(UINT16));
            return static_cast<SIZE_T>(Mix64(static_cast<UINT64>(val)));
        }
        else if constexpr (sizeof(T) == 1)
        {
            // Scalar path for 8-bit integers, CHAR, UCHAR, bool.
            UCHAR val;
            RtlCopyMemory(&val, &Key, sizeof(UCHAR));
            return static_cast<SIZE_T>(Mix64(static_cast<UINT64>(val)));
        }
        else if constexpr (sizeof(T) == 16)
        {
            UINT64 p64[2];
            RtlCopyMemory(p64, &Key, sizeof(p64));

            // Asymmetric primes to break commutativity (preventing [A, B] from hashing same as [B, A])
            constexpr UINT64 c1 = 0x9E3779B97F4A7C15ULL; 
            constexpr UINT64 c2 = 0xBF58476D1CE4E5B9ULL; 

            UINT64 a = p64[0] ^ c1;
            UINT64 b = p64[1] ^ c2;

            UINT64 low, high;
    
        #if defined(_M_X64)
            low = _umul128(a, b, &high);
        #elif defined(_M_ARM64)
            low = a * b;
            high = __umulh(a, b);
        #endif

            // Fold the 128-bit product with asymmetric feed-forward (a ^ _rotl64(b, 31)) to
            // prevent both zero-annihilation and (a, b) <-> (b, a) operand swap collisions,
            // then avalanche so high bits of p64[1] influence both low index bits and high H2 bits.
            return static_cast<SIZE_T>(Mix64(low ^ high ^ a ^ _rotl64(b, 31)));
        }
        else
        {
            const unsigned char* p = reinterpret_cast<const unsigned char*>(&Key);

            // ------------------------------------------------------------------------
            // Small Odd-Sizes (3, 5-7, 9-15 bytes) -> Overlapping Branchless Reads
            // ------------------------------------------------------------------------
            if constexpr (sizeof(T) < 16)
            {
                UINT64 a = 0, b = 0;

                // Exact size known at compile time; compiler extracts only the active branch
                if constexpr (sizeof(T) >= 9)
                {
                    RtlCopyMemory(&a, p, 8);
                    RtlCopyMemory(&b, p + sizeof(T) - 8, 8); // Overlapping 8-byte read
                }
                else if constexpr (sizeof(T) >= 5)
                {
                    UINT32 low, high;
                    RtlCopyMemory(&low, p, 4);
                    RtlCopyMemory(&high, p + sizeof(T) - 4, 4); // Overlapping 4-byte read
                    a = low; 
                    b = high;
                }
                else // sizeof(T) == 3
                {
                    UINT16 low, high;
                    RtlCopyMemory(&low, p, 2);
                    RtlCopyMemory(&high, p + sizeof(T) - 2, 2); // Overlapping 2-byte read
                    a = low; 
                    b = high;
                }

                a ^= 0x9E3779B97F4A7C15ULL;
                b ^= 0xBF58476D1CE4E5B9ULL;

                UINT64 lowRes, highRes;
            #if defined(_M_X64)
                lowRes = _umul128(a, b, &highRes);
            #elif defined(_M_ARM64)
                lowRes = a * b;
                highRes = __umulh(a, b);
            #endif
                // Incorporate struct size and asymmetric feed-forward operands into the final mix
                return static_cast<SIZE_T>(Mix64(lowRes ^ highRes ^ a ^ _rotl64(b, 31) ^ sizeof(T)));
            }
            // ------------------------------------------------------------------------
            // Large Structs (> 16 bytes) -> 32-Byte ILP Chunking + Overlapping Tail
            // ------------------------------------------------------------------------
            else
            {
                UINT64 seed1 = 0xCBF29CE484222325ULL ^ (static_cast<UINT64>(sizeof(T)) * 0x9E3779B97F4A7C15ULL);
                UINT64 seed2 = 0xBF58476D1CE4E5B9ULL;

                SIZE_T i = 0;

                // Dual-state loop allows out-of-order execution engines to run L1 and L2 concurrently
                for (; i + 32 <= sizeof(T); i += 32)
                {
                    UINT64 a1, b1, a2, b2;
                    RtlCopyMemory(&a1, p + i, 8);
                    RtlCopyMemory(&b1, p + i + 8, 8);
                    RtlCopyMemory(&a2, p + i + 16, 8);
                    RtlCopyMemory(&b2, p + i + 24, 8);

                    const UINT64 prevSeed1 = seed1;
                    const UINT64 prevSeed2 = seed2;

                    a1 ^= prevSeed1;
                    b1 ^= prevSeed2 ^ 0x9E3779B97F4A7C15ULL;
                    a2 ^= prevSeed2;
                    b2 ^= prevSeed1 ^ 0xBF58476D1CE4E5B9ULL;

                    UINT64 L1, H1, L2, H2;
                #if defined(_M_X64)
                    L1 = _umul128(a1, b1, &H1);
                    L2 = _umul128(a2, b2, &H2);
                #elif defined(_M_ARM64)
                    L1 = a1 * b1; H1 = __umulh(a1, b1);
                    L2 = a2 * b2; H2 = __umulh(a2, b2);
                #endif
                    // Feed-forward a1/b1 and a2/b2 so a zero multiplier never wipes prior state
                    seed1 = L1 ^ H1 ^ a1 ^ _rotl64(b1, 31);
                    seed2 = L2 ^ H2 ^ a2 ^ _rotl64(b2, 31);
                }

                if constexpr ((sizeof(T) % 32) >= 16)
                {
                    UINT64 a, b;
                    RtlCopyMemory(&a, p + i, 8);
                    RtlCopyMemory(&b, p + i + 8, 8);

                    a ^= seed1;
                    b ^= seed2 ^ 0x9E3779B97F4A7C15ULL;

                    UINT64 L, H;
                #if defined(_M_X64)
                    L = _umul128(a, b, &H);
                #elif defined(_M_ARM64)
                    L = a * b; 
                    H = __umulh(a, b);
                #endif
                    seed1 = L ^ H ^ a ^ _rotl64(b, 31);
                }

                // Branchless Overlapping Tail: Hash the absolute LAST 16 bytes of the struct.
                if constexpr ((sizeof(T) % 16) != 0)
                {
                    UINT64 a, b;
                    RtlCopyMemory(&a, p + sizeof(T) - 16, 8);
                    RtlCopyMemory(&b, p + sizeof(T) - 8, 8);

                    a ^= seed1;
                    b ^= seed2 ^ 0x94D049BB133111EBULL;

                    UINT64 L, H;
                #if defined(_M_X64)
                    L = _umul128(a, b, &H);
                #elif defined(_M_ARM64)
                    L = a * b; 
                    H = __umulh(a, b);
                #endif
                    seed1 = L ^ H ^ a ^ _rotl64(b, 31);
                }

                return static_cast<SIZE_T>(Mix64(seed1 ^ _rotl64(seed2, 31)));
            }
        }
    }
};

//--------------------------------------------------------------------------------
// Generates a well-distributed hash from an already generated 64-bit seed.
//
// Parameters:
//   Key - The precomputed 64-bit value to hash.
//
// Return:
//   Avalanched 64-bit hash.
//--------------------------------------------------------------------------------
struct KPrecomputedHash
{
    SIZE_T operator()(_In_ UINT64 Key) const noexcept
    {
        return static_cast<SIZE_T>(KDefaultHash<UINT64>::Mix64(Key));
    }
};

//--------------------------------------------------------------------------------
// Pass-Through Hasher. Exclusively for clients supplying keys that are ALREADY 
// nearly-uniformly distributed. Directly maps a trivially copyable structural key
// into a size_t index. For types smaller than 64 bits, shifts the lower bits by 3
// to align with m_GroupMask (~7ULL) so low key bits are not discarded, and 
// populates bits 57..63 so the H2 control metadata byte is populated rather
// than constantly zero.
//
// Parameters:
//   Key - The key to pass through.
//
// Return:
//   The unmixed original key mapped to SIZE_T with populated H2 bits. 
//--------------------------------------------------------------------------------
template <typename T>
struct KIdentityHash
{
    static_assert(kstd::is_trivially_copyable_v<T>, "KIdentityHash requires a trivially copyable type.");
    static_assert(kstd::has_unique_object_representations_v<T>, "KIdentityHash requires types without padding.");
    static_assert(sizeof(T) <= sizeof(SIZE_T), "KIdentityHash requires a scalar type no larger than SIZE_T.");
    static_assert(sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8,
        "KIdentityHash requires a 1, 2, 4, or 8 byte scalar type to prevent partial key truncation.");

    SIZE_T operator()(_In_ const T& Key) const noexcept
    {
        if constexpr (sizeof(T) == 8)
        {
            UINT64 val;
            RtlCopyMemory(&val, &Key, sizeof(UINT64));
            return static_cast<SIZE_T>(val);
        }
        else if constexpr (sizeof(T) == 4)
        {
            UINT32 val;
            RtlCopyMemory(&val, &Key, sizeof(UINT32));
            const SIZE_T s = static_cast<SIZE_T>(val);
            return ((s * 0x9E3779B97F4A7C15ULL) & 0xFE00000000000000ULL) | (s << 3);
        }
        else if constexpr (sizeof(T) == 2)
        {
            UINT16 val;
            RtlCopyMemory(&val, &Key, sizeof(UINT16));
            const SIZE_T s = static_cast<SIZE_T>(val);
            return ((s * 0x9E3779B97F4A7C15ULL) & 0xFE00000000000000ULL) | (s << 3);
        }
        else
        {
            UCHAR val;
            RtlCopyMemory(&val, &Key, sizeof(UCHAR));
            const SIZE_T s = static_cast<SIZE_T>(val);
            return ((s * 0x9E3779B97F4A7C15ULL) & 0xFE00000000000000ULL) | (s << 3);
        }
    }
};

//--------------------------------------------------------------------------------
// KFlatHashMap is an open-addressing append-only hash table leveraging SIMD Within 
// A Register (SWAR) optimization. Modeled after SwissTable/F14 architectures, it 
// partitions its footprint into an array of 1-byte metadata entries (m_Ctrl) and 
// an array of key-value pairs (m_Slots). Lookups fetch 8 control bytes at once, 
// using bitwise operations to detect matches simultaneously, virtually eliminating 
// costly memory comparisons and maximizing CPU cache locality.
//
// Template Parameters:
//   K         - The type of the keys stored in the map.
//   V         - The type of the values associated with the keys.
//   Hash      - The functor used to generate 64-bit hashes from keys.
//   PoolFlags - The NT kernel pool flags used for internal array allocations.
//   PoolTag   - The 4-byte tag used for kernel memory tracking.
//--------------------------------------------------------------------------------
template <typename K, typename V, typename Hash = KDefaultHash<K>, ULONG64 PoolFlags = POOL_FLAG_NON_PAGED, ULONG PoolTag = 'amHK'>
class KFlatHashMap
{
private:
    // Sentinel value representing an empty, unpopulated slot in the control array.
    static constexpr UCHAR  kEmptyCtrl = 0xFF;
    
    // The number of elements fetched and processed simultaneously during SWAR probing.
    static constexpr SIZE_T kGroupSize = 8;

    struct Slot
    {        
        K Key;   // The unique key used to index the hash map.                
        V Value; // The data value mapped to the unique key.
    };

    //--------------------------------------------------------------------------------
    // Loads an 8-byte control group without violating C++ strict aliasing rules.
    // Compiles to a single 64-bit load instruction (mov / ldr) on x64 and ARM64.
    //
    // Parameters:
    //   pCtrl - Pointer to the start of the 8-byte control group.
    //
    // Return:
    //   The 64-bit block of 8 control metadata bytes.
    //--------------------------------------------------------------------------------
    static __forceinline UINT64 LoadCtrlGroup(_In_reads_(kGroupSize) const UCHAR* pCtrl) noexcept
    {
        UINT64 ctrlBlock;
        RtlCopyMemory(&ctrlBlock, pCtrl, sizeof(UINT64));
        return ctrlBlock;
    }

    //--------------------------------------------------------------------------------
    // SWAR (SIMD Within A Register) byte-matching technique.
    // Identifies which of the 8 bytes inside 'Block' equal 'MatchByte'.
    // Because MatchByte is strictly 7-bit (MSB = 0) and empty slots are 0xFF (MSB = 1),
    // '~xorBlock' unconditionally masks out all empty slots, guaranteeing an empty
    // slot is never matched. Adding 0x01 to the masked 7-bit lanes (~xorBlock & 0x7F)
    // sets bit 7 if and only if all 7 lower bits of xorBlock are zero, preventing
    // inter-byte borrow propagation across adjacent control bytes.
    //
    // Parameters:
    //   Block     - The 64-bit block of 8 control metadata bytes.
    //   MatchByte - The target 7-bit metadata byte to search for (zero-extended).
    //
    // Return:
    //   A 64-bit bitmask where matched byte locations have their MSB set to 1.
    //--------------------------------------------------------------------------------
    static __forceinline UINT64 SwarMatch(_In_ UINT64 Block, 
                                          _In_ UINT64 MatchByte) noexcept
    {
        const UINT64 xorBlock = Block ^ (0x0101010101010101ULL * MatchByte);
        return ((~xorBlock & 0x7F7F7F7F7F7F7F7FULL) + 0x0101010101010101ULL) & ~xorBlock & 0x8080808080808080ULL;
    }

    //--------------------------------------------------------------------------------
    // Traits mapping boolean constness to the appropriate internal pointer types.
    //--------------------------------------------------------------------------------
    template <bool IsConst>
    struct IterTraits;

    template <>
    struct IterTraits<false>
    {
        using CtrlPtr = UCHAR*;
        using SlotPtr = Slot*;
        using SlotRef = Slot&;
    };

    template <>
    struct IterTraits<true>
    {
        using CtrlPtr = const UCHAR*;
        using SlotPtr = const Slot*;
        using SlotRef = const Slot&;
    };

public:    
    //--------------------------------------------------------------------------------
    // Default constructor leaving internal dynamic arrays safely zero-initialized.
    //--------------------------------------------------------------------------------
    KFlatHashMap() noexcept : m_Ctrl(nullptr), 
                              m_Slots(nullptr), 
                              m_Capacity(0), 
                              m_Size(0),
                              m_MaxLoad(0),
                              m_GroupMask(0)
    {
    }

    //--------------------------------------------------------------------------------
    // Move constructor transferring ownership of internal allocations in O(1).
    //--------------------------------------------------------------------------------
    KFlatHashMap(KFlatHashMap&& Other) noexcept : m_Ctrl(Other.m_Ctrl),
                                                  m_Slots(Other.m_Slots),
                                                  m_Capacity(Other.m_Capacity),
                                                  m_Size(Other.m_Size),
                                                  m_MaxLoad(Other.m_MaxLoad),
                                                  m_GroupMask(Other.m_GroupMask)
    {
        Other.m_Ctrl      = nullptr;
        Other.m_Slots     = nullptr;
        Other.m_Capacity  = 0;
        Other.m_Size      = 0;
        Other.m_MaxLoad   = 0;
        Other.m_GroupMask = 0;
    }

    //--------------------------------------------------------------------------------
    // Move assignment operator releasing existing pool allocations and transferring
    // ownership from the source map in O(1).
    //--------------------------------------------------------------------------------
    KFlatHashMap& operator=(KFlatHashMap&& Other) noexcept
    {
        if (this != &Other)
        {
            DestroyElements();

            if (m_Ctrl != nullptr)
            {
                ExFreePoolWithTag(m_Ctrl, PoolTag);
            }

            m_Ctrl      = Other.m_Ctrl;
            m_Slots     = Other.m_Slots;
            m_Capacity  = Other.m_Capacity;
            m_Size      = Other.m_Size;
            m_MaxLoad   = Other.m_MaxLoad;
            m_GroupMask = Other.m_GroupMask;

            Other.m_Ctrl      = nullptr;
            Other.m_Slots     = nullptr;
            Other.m_Capacity  = 0;
            Other.m_Size      = 0;
            Other.m_MaxLoad   = 0;
            Other.m_GroupMask = 0;
        }

        return *this;
    }
    
    //--------------------------------------------------------------------------------
    // Core destructor resolving allocations safely back to the pool.
    //--------------------------------------------------------------------------------
    ~KFlatHashMap() noexcept
    {
        DestroyElements();

        if (m_Ctrl != nullptr)
        {
            ExFreePoolWithTag(m_Ctrl, PoolTag);
        }
    }

    KFlatHashMap(const KFlatHashMap&) = delete;
    KFlatHashMap& operator=(const KFlatHashMap&) = delete;

    //--------------------------------------------------------------------------------
    // Returns the number of active elements currently stored in the map.
    //--------------------------------------------------------------------------------
    SIZE_T Size() const noexcept
    {
        return m_Size;
    }

    //--------------------------------------------------------------------------------
    // Returns the total allocated slot capacity of the map.
    //--------------------------------------------------------------------------------
    SIZE_T Capacity() const noexcept
    {
        return m_Capacity;
    }

    //--------------------------------------------------------------------------------
    // Evaluates whether the map currently contains zero elements.
    //--------------------------------------------------------------------------------
    bool IsEmpty() const noexcept
    {
        return m_Size == 0;
    }

    //--------------------------------------------------------------------------------
    // Pre-allocates map capacity to prevent reallocation and element migration churn.
    // Accounts for the 70% maximum load factor threshold so 'Capacity' elements can
    // be inserted without triggering an intermediate rehash.
    //
    // Parameters:
    //   Capacity - Minimum number of elements required before re-allocation triggers.
    //
    // Return:
    //   NTSTATUS indicating success, integer overflow, or pool insufficiency.
    //--------------------------------------------------------------------------------
    NTSTATUS Reserve(_In_ SIZE_T Capacity) noexcept
    {
        if (Capacity <= m_MaxLoad)
        {
            return STATUS_SUCCESS;
        }

        // Scale the requested element so that 'Capacity' elements fit
        // within the 70% load factor threshold computed in Rehash().
        SIZE_T scaledCap = 0;
        if (!NT_SUCCESS(RtlSizeTMult(Capacity, 10, &scaledCap))) [[unlikely]]
        {
            return STATUS_INTEGER_OVERFLOW;
        }
        
        // Clamp the minimum baseline before the bitwise expansion to prevent 
        // intercepting legitimate arithmetic overflows later in the pipeline.
        SIZE_T targetCap = (scaledCap - 3) / 7;        
        if (targetCap < 16)
        {
            targetCap = 16;
        }

        // Hardware-accelerated algorithm to find the next power of 2.
        unsigned long msbIndex;
        _BitScanReverse64(&msbIndex, targetCap - 1);

        // Prevent undefined behavior from out-of-bounds bit shifts and catch integer overflow.        
        constexpr unsigned long maxBitIndex = (sizeof(SIZE_T) * 8) - 1;        
        if (msbIndex >= maxBitIndex) [[unlikely]]
        {
            return STATUS_INTEGER_OVERFLOW;
        }

        SIZE_T finalCap = static_cast<SIZE_T>(1) << (msbIndex + 1);

        return Rehash(finalCap);
    }

    //--------------------------------------------------------------------------------
    // Emplacing mechanism constructing value in-place, bypassing redundant default 
    // initialization.
    //
    // IMPORTANT RESOURCE LIFECYCLE NOTE:
    //   If the key already exists in the map, this function returns 
    //   STATUS_OBJECT_NAME_EXISTS. In this scenario, variadic arguments passed via 
    //   kstd::move() are NOT consumed. The caller retains ownership of these 
    //   resources and is strictly responsible for freeing them to prevent kernel 
    //   memory leaks.
    //
    // Parameters:
    //   Key      - The map key indexing the element.
    //   OutValue - Double-pointer receiving the constructed or existing value's 
    //              memory address.
    //   args     - Variadic template parameters for the constructed value object.
    //
    // Return:
    //   STATUS_SUCCESS on new placement, STATUS_OBJECT_NAME_EXISTS if the key 
    //   already exists, or an error NTSTATUS on memory constraints.
    //--------------------------------------------------------------------------------
    template <typename... Args>
    NTSTATUS Emplace(_In_                           const K& Key,
                     _Outptr_result_nullonfailure_  V**      OutValue,
                     _In_                           Args&&... args) noexcept
    {
        *OutValue = nullptr;

        // Allocate initial table capacity on first insertion when map is unallocated.
        if (m_Capacity == 0) [[unlikely]]
        {
            NTSTATUS status = Rehash(16);
            if (!NT_SUCCESS(status)) [[unlikely]]
            {
                return status;
            }
        }

        const SIZE_T hash  = Hash{}(Key);        
        SIZE_T groupMask   = m_GroupMask;
        SIZE_T index       = hash & groupMask;
        const SIZE_T start = index; 
        const UINT64 h2    = hash >> 57; 

        while (true)
        {            
            Slot* const  pGroupSlots = &m_Slots[index];
            const UINT64 ctrlBlock   = LoadCtrlGroup(&m_Ctrl[index]);
            UINT64       match       = SwarMatch(ctrlBlock, h2);
            
            // Check for existing keys colliding with the same H2 metadata byte
            while (match != 0)
            {
                unsigned long bitPos;
                _BitScanForward64(&bitPos, match);
                
                Slot* const pSlot = pGroupSlots + (bitPos >> 3);

                if (pSlot->Key == Key) [[unlikely]]
                {
                    *OutValue = &pSlot->Value;
                    
                    // Return informational status so callers know variadic args were not consumed
                    return STATUS_OBJECT_NAME_EXISTS; 
                }
                
                match &= match - 1;
            }

            // Find an empty slot using the zero-latency MSB shortcut.
            UINT64 empty = ctrlBlock & 0x8080808080808080ULL;            
            if (empty != 0) [[likely]]
            {
                // Optimized load factor threshold bumped to 70% to prevent degraded linear probe chains
                // before hash table scaling evaluates sizing constraints. Checked only after confirming
                // Key is absent so lookups via Emplace/GetOrInsert at m_Size == m_MaxLoad never rehash.
                if (m_Size >= m_MaxLoad) [[unlikely]]
                {
                    SIZE_T newCap = 0;
                    if (!NT_SUCCESS(RtlSizeTMult(m_Capacity, 2, &newCap))) [[unlikely]]
                    {
                        return STATUS_INTEGER_OVERFLOW;
                    }

                    NTSTATUS status = Rehash(newCap);
                    if (!NT_SUCCESS(status)) [[unlikely]]
                    {
                        return status;
                    }

                    groupMask = m_GroupMask;
                    index     = hash & groupMask;

                    while (true)
                    {
                        const UINT64 newCtrlBlock = LoadCtrlGroup(&m_Ctrl[index]);
                        empty = newCtrlBlock & 0x8080808080808080ULL;
                        if (empty != 0) [[likely]]
                        {
                            break;
                        }

                        index = (index + kGroupSize) & groupMask;
                    }
                }

                unsigned long bitPos;
                _BitScanForward64(&bitPos, empty);
                
                // Since index is strictly aligned, index + bitPos/8 is guaranteed to never overflow m_Capacity
                const SIZE_T offset = bitPos >> 3;
                Slot* const  pSlot  = &m_Slots[index + offset];
                
                m_Ctrl[index + offset] = static_cast<UCHAR>(h2);
                
                new (&pSlot->Key)   K(Key);
                new (&pSlot->Value) V(kstd::forward<Args>(args)...);
                m_Size++;
                
                *OutValue = &pSlot->Value;
                return STATUS_SUCCESS;
            }

            // Hardware-friendly linear probing
            index = (index + kGroupSize) & groupMask;            
            if (index == start) [[unlikely]]
            {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }
    }

    //--------------------------------------------------------------------------------
    // Fetches an existing value or inserts a newly constructed one.
    //
    // IMPORTANT RESOURCE LIFECYCLE NOTE:
    //   Returns STATUS_OBJECT_NAME_EXISTS if the key is already present. Callers 
    //   forwarding r-values must check for this specific status code and manually 
    //   cleanup their unconsumed resources.
    //
    // Parameters:
    //   Key      - The mapped entry identifier to lookup or create.
    //   OutValue - Receives a mutable pointer mapped to the object's memory.
    //
    // Return:
    //   STATUS_SUCCESS on creation, STATUS_OBJECT_NAME_EXISTS if found, or 
    //   an error NTSTATUS on failed resource allocation.
    //--------------------------------------------------------------------------------
    NTSTATUS GetOrInsert(_In_                          const K& Key,
                         _Outptr_result_nullonfailure_ V**      OutValue) noexcept
    {
        return Emplace(Key, OutValue);
    }

    //--------------------------------------------------------------------------------
    // Looks up a key and returns a pointer to its mutable value if found.
    //
    // Parameters:
    //   Key - Target key structure evaluated via SWAR hashing protocol.
    //
    // Return:
    //   Pointer to the mapped item, or nullptr if the element is absent.
    //--------------------------------------------------------------------------------
    V* Find(_In_ const K& Key) noexcept
    {
        return const_cast<V*>(FindValueInternal(Key));
    }

    //--------------------------------------------------------------------------------
    // Looks up a key and returns a pointer to its constant value if found.
    //
    // Parameters:
    //   Key - Target key structure evaluated via SWAR hashing protocol.
    //
    // Return:
    //   Pointer to the mapped item, or nullptr if the element is absent.
    //--------------------------------------------------------------------------------
    const V* Find(_In_ const K& Key) const noexcept
    {
        return FindValueInternal(Key);
    }

    //--------------------------------------------------------------------------------
    // Clears the map, resetting control bytes and destroying values.
    // Restores metadata structures back to pre-allocation empty sentinels.
    //--------------------------------------------------------------------------------
    void Clear() noexcept
    {
        if (m_Ctrl != nullptr && m_Size != 0)
        {
            DestroyElements();
            RtlFillMemory(m_Ctrl, m_Capacity, kEmptyCtrl);
        }
        
        m_Size = 0;
    }

    //--------------------------------------------------------------------------------
    // BaseIterator acts as a unified template for both mutable and const iterators.
    // It utilizes the control byte array to efficiently skip empty indices 
    // without inspecting the underlying Key/Value slots.
    //--------------------------------------------------------------------------------
    template <bool IsConst>
    class BaseIterator
    {
        friend class KFlatHashMap;
        
        // Grant mutual friendship to allow the const iterator to read the non-const iterator's pointers
        template <bool> friend class BaseIterator; 
    public:
        using CtrlPtr = typename IterTraits<IsConst>::CtrlPtr;
        using SlotPtr = typename IterTraits<IsConst>::SlotPtr;
        using SlotRef = typename IterTraits<IsConst>::SlotRef;

        // Standard C++ iterator trait aliases for template metaprogramming
        using iterator_category = kstd::forward_iterator_tag; 
        using value_type        = Slot;
        using difference_type   = INT_PTR;
        using pointer           = SlotPtr;
        using reference         = SlotRef;

        //--------------------------------------------------------------------------------
        // Default constructor required by C++ forward_iterator_tag concept.
        //--------------------------------------------------------------------------------
        BaseIterator() noexcept : m_Ctrl(nullptr),
                                  m_Slots(nullptr),
                                  m_Capacity(0),
                                  m_Index(0)
        {
        }

        //--------------------------------------------------------------------------------
        // Initializes the iterator and automatically advances to the first occupied 
        // slot in the map.
        //
        // Parameters:
        //   pCtrl    - Root metadata byte tracking array.
        //   pSlots   - Contiguous mapping target containing exact properties.
        //   Capacity - Upper limit array constraint protecting evaluation overruns.
        //   Index    - Starting location scalar.
        //--------------------------------------------------------------------------------
        BaseIterator(_In_reads_opt_(Capacity) CtrlPtr pCtrl, 
                     _In_reads_opt_(Capacity) SlotPtr pSlots, 
                     _In_                     SIZE_T  Capacity, 
                     _In_                     SIZE_T  Index) noexcept : m_Ctrl(pCtrl), 
                                                                        m_Slots(pSlots), 
                                                                        m_Capacity(Capacity), 
                                                                        m_Index(Index) 
        { 
            AdvanceToOccupied(); 
        }

        BaseIterator(const BaseIterator&) noexcept = default;
        BaseIterator& operator=(const BaseIterator&) noexcept = default;

        //--------------------------------------------------------------------------------
        // Conversion constructor allowing implicit promotion from Iterator to ConstIterator.
        // Const-correctness is inherently enforced: attempting to construct a non-const 
        // Iterator from a ConstIterator will fail to compile as UCHAR* cannot bind to const UCHAR*.
        //--------------------------------------------------------------------------------
        template <bool OtherConst>
        BaseIterator(const BaseIterator<OtherConst>& Other) noexcept : m_Ctrl(Other.m_Ctrl), 
                                                                       m_Slots(Other.m_Slots), 
                                                                       m_Capacity(Other.m_Capacity), 
                                                                       m_Index(Other.m_Index) 
        {
        }

        //--------------------------------------------------------------------------------
        // Evaluates inequality between two iterators based on their parent control block
        // and current index. Permits direct comparisons between Iterators and ConstIterators.
        //
        // Parameters:
        //   Other - Object against which inequality comparison occurs.
        //
        // Return:
        //   True if iterators point to different maps or indices, false otherwise.
        //--------------------------------------------------------------------------------
        template <bool OtherConst>
        bool operator!=(const BaseIterator<OtherConst>& Other) const noexcept
        { 
            return m_Ctrl != Other.m_Ctrl || m_Index != Other.m_Index; 
        }

        //--------------------------------------------------------------------------------
        // Evaluates equality between two iterators based on their parent control block
        // and current index. Permits direct comparisons between Iterators and ConstIterators.
        //
        // Parameters:
        //   Other - Object against which equality comparison occurs.
        //
        // Return:
        //   True if iterators point to the same map and index, false otherwise.
        //--------------------------------------------------------------------------------
        template <bool OtherConst>
        bool operator==(const BaseIterator<OtherConst>& Other) const noexcept
        { 
            return m_Ctrl == Other.m_Ctrl && m_Index == Other.m_Index; 
        }
        
        //--------------------------------------------------------------------------------
        // Pre-increments the iterator, advancing past empty entries to the next valid 
        // element.
        //
        // Return:
        //   A reference to the incremented operator element.
        //--------------------------------------------------------------------------------
        BaseIterator& operator++() noexcept
        { 
            m_Index++; 
            AdvanceToOccupied(); 
            return *this; 
        }

        //--------------------------------------------------------------------------------
        // Post-increments the iterator, advancing past empty entries to the next valid 
        // element, while returning a copy of the original iterator state.
        //
        // Return:
        //   A copy of the iterator prior to incrementing.
        //--------------------------------------------------------------------------------
        BaseIterator operator++(int) noexcept
        { 
            BaseIterator temp = *this; 
            ++(*this); // Offload logic to the pre-increment operator
            return temp; 
        }
        
        //--------------------------------------------------------------------------------
        // Dereferences the iterator to provide a direct reference to the Key/Value slot.
        //
        // Return:
        //   Underlying reference (mutable or const depending on instantiation).
        //--------------------------------------------------------------------------------
        SlotRef operator*() const noexcept
        { 
            return m_Slots[m_Index]; 
        }

        //--------------------------------------------------------------------------------
        // Accesses the Key or Value properties of the currently pointed-to slot.
        //
        // Return:
        //   Underlying address (mutable or const depending on instantiation).
        //--------------------------------------------------------------------------------
        SlotPtr operator->() const noexcept
        { 
            return &m_Slots[m_Index]; 
        }

    private:
        //--------------------------------------------------------------------------------
        // Linearly scans the control array until a valid (non-empty) control byte is 
        // found, or the end of capacity is reached. Append-only logic relies safely 
        // on checking strictly for kEmptyCtrl.
        //--------------------------------------------------------------------------------
        void AdvanceToOccupied() noexcept
        {
            while (m_Index < m_Capacity && m_Ctrl[m_Index] == kEmptyCtrl) 
            { 
                m_Index++; 
            }
        }
        
        CtrlPtr m_Ctrl;     // Pointer to the parent map's control byte array.                
        SlotPtr m_Slots;    // Pointer to the parent map's key-value slots.                 
        SIZE_T  m_Capacity; // The total allocated capacity of the map.                 
        SIZE_T  m_Index;    // The current cursor index representing the iterator's position.
    };

    using Iterator      = BaseIterator<false>;
    using ConstIterator = BaseIterator<true>;

    //--------------------------------------------------------------------------------
    // Generates an Iterator at the start of the populated dataset block map.
    //
    // Return:
    //   An Iterator mapping to element index zero.
    //--------------------------------------------------------------------------------
    Iterator begin() noexcept
    { 
        return Iterator(m_Ctrl, m_Slots, m_Capacity, 0); 
    }

    //--------------------------------------------------------------------------------
    // Exposes the boundary Iterator mapped directly after maximum object capacity.
    //
    // Return:
    //   A terminus Iterator object indicating completion.
    //--------------------------------------------------------------------------------
    Iterator end() noexcept
    { 
        return Iterator(m_Ctrl, m_Slots, m_Capacity, m_Capacity); 
    }

    //--------------------------------------------------------------------------------
    // Map traversal boundary accessors for const-qualified maps.
    //--------------------------------------------------------------------------------
    ConstIterator begin() const noexcept
    { 
        return ConstIterator(m_Ctrl, m_Slots, m_Capacity, 0); 
    }
    
    ConstIterator end() const noexcept
    { 
        return ConstIterator(m_Ctrl, m_Slots, m_Capacity, m_Capacity); 
    }
    
    ConstIterator cbegin() const noexcept
    { 
        return begin(); 
    }
    
    ConstIterator cend() const noexcept
    { 
        return end(); 
    }

private:

    //--------------------------------------------------------------------------------
    // Invokes destructors on all active Key/Value pairs using 64-bit SWAR group
    // scanning to jump directly across occupied slots. Completely elided by the
    // compiler when K and V are trivially destructible.
    //--------------------------------------------------------------------------------
    void DestroyElements() noexcept
    {
        if constexpr (!kstd::is_trivially_destructible_v<K> || !kstd::is_trivially_destructible_v<V>)
        {
            if (m_Ctrl != nullptr && m_Size != 0)
            {
                for (SIZE_T groupIdx = 0; groupIdx < m_Capacity; groupIdx += kGroupSize)
                {
                    const UINT64 ctrlBlock = LoadCtrlGroup(&m_Ctrl[groupIdx]);
                    UINT64 occupied = ~ctrlBlock & 0x8080808080808080ULL;

                    while (occupied != 0)
                    {
                        unsigned long bitPos;
                        _BitScanForward64(&bitPos, occupied);

                        const SIZE_T i = groupIdx + (bitPos >> 3);
                        m_Slots[i].Key.~K();
                        m_Slots[i].Value.~V();

                        occupied &= occupied - 1;
                    }
                }
            }
        }
    }

    //--------------------------------------------------------------------------------
    // Internal helper to locate the value pointer of a key directly.
    // Unifies the probing logic for Find() and Find() const operations while
    // overlapping the slot cache-line fetch with the control block evaluation.
    //
    // Parameters:
    //   Key - Target key structure to locate.
    //
    // Return:
    //   Pointer to the mapped Value in the slot array, or nullptr if not found.
    //--------------------------------------------------------------------------------
    __forceinline const V* FindValueInternal(_In_ const K& Key) const noexcept
    {
        // Bypass map hashing entirely if there are currently no active elements
        if (m_Size == 0) [[unlikely]]
        {
            return nullptr;
        }

        const SIZE_T hash      = Hash{}(Key);        
        const SIZE_T groupMask = m_GroupMask;
        SIZE_T       index     = hash & groupMask;
        const SIZE_T start     = index;
        const UINT64 h2        = hash >> 57;

        while (true)
        {            
            const Slot* const pGroupSlots = &m_Slots[index];

            // Overlap the m_Slots L3/DRAM fetch with the m_Ctrl lookup and SWAR math
            PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, pGroupSlots);

            const UINT64 ctrlBlock = LoadCtrlGroup(&m_Ctrl[index]);
            UINT64       match     = SwarMatch(ctrlBlock, h2);
            
            while (match != 0)
            {
                unsigned long bitPos;
                _BitScanForward64(&bitPos, match);
                
                const Slot* const pSlot = pGroupSlots + (bitPos >> 3);

                if (pSlot->Key == Key) [[likely]]
                {
                    return &pSlot->Value;
                }
                
                match &= match - 1;
            }

            // High-speed empty block detection: 
            // Valid h2 metadata bytes are strictly 7-bit (MSB = 0).
            // Empty control bytes (0xFF) are the only bytes with the MSB set.
            if ((ctrlBlock & 0x8080808080808080ULL) != 0) [[likely]]
            {
                return nullptr;
            }

            index = (index + kGroupSize) & groupMask;
            
            if (index == start) [[unlikely]]
            {
                break;
            }
        }

        return nullptr;
    }

    //--------------------------------------------------------------------------------
    // Expands and reorganizes internal memory capacity, migrating items to new slots.
    //
    // Parameters:
    //   NewCapacity - The target power-of-two size parameter scaling requirement.
    //
    // Return:
    //   STATUS_SUCCESS on memory operation success.
    //--------------------------------------------------------------------------------
    NTSTATUS Rehash(_In_ SIZE_T NewCapacity) noexcept
    {        
        SIZE_T ctrlBytes          = NewCapacity;
        SIZE_T slotBytes          = 0;
        // Align slots to 128 bytes so each 8-slot group sits in an aligned 128-byte
        // L2 spatial prefetcher pair on x64 and ARM64 processors.
        constexpr SIZE_T slotAlign  = (alignof(Slot) > 128) ? alignof(Slot) : 128;
        constexpr SIZE_T maxPadding = slotAlign - 1;
        
        // Re-introduce padding baseline separation for optimal cache lane separation
        SIZE_T totalAllocSize = 0;

        if (!NT_SUCCESS(RtlSizeTMult(NewCapacity, sizeof(Slot), &slotBytes))) [[unlikely]]
        {
            return STATUS_INTEGER_OVERFLOW;
        }

        if (!NT_SUCCESS(RtlSizeTAdd(ctrlBytes, maxPadding, &totalAllocSize)) ||
            !NT_SUCCESS(RtlSizeTAdd(totalAllocSize, slotBytes, &totalAllocSize))) [[unlikely]]
        {
            return STATUS_INTEGER_OVERFLOW;
        }

        constexpr POOL_FLAGS allocFlags = PoolFlags | POOL_FLAG_UNINITIALIZED;

        UCHAR* __restrict pNewCtrl = static_cast<UCHAR*>(ExAllocatePool2(allocFlags, totalAllocSize, PoolTag));        
        if (pNewCtrl == nullptr) [[unlikely]]
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        UINT_PTR ctrlAddr  = reinterpret_cast<UINT_PTR>(pNewCtrl);
        UINT_PTR slotsAddr = (ctrlAddr + ctrlBytes + maxPadding) & ~static_cast<UINT_PTR>(maxPadding);
        Slot* __restrict pNewSlots = reinterpret_cast<Slot*>(slotsAddr);

        RtlFillMemory(pNewCtrl, NewCapacity, kEmptyCtrl);

        const SIZE_T newGroupMask = (NewCapacity - 1) & ~(kGroupSize - 1);

        if (m_Ctrl != nullptr)
        {
            if (m_Size != 0)
            {
                // Re-hash and move existing items over to the newly expanded table
                // using 64-bit SWAR scanning to skip empty control slots without branching.
                for (SIZE_T groupIdx = 0; groupIdx < m_Capacity; groupIdx += kGroupSize)
                {
                    const UINT64 oldCtrlBlock = LoadCtrlGroup(&m_Ctrl[groupIdx]);
                    UINT64 occupied = ~oldCtrlBlock & 0x8080808080808080ULL;

                    while (occupied != 0)
                    {
                        unsigned long occBit;
                        _BitScanForward64(&occBit, occupied);

                        const SIZE_T i     = groupIdx + (occBit >> 3);
                        const SIZE_T hash  = Hash{}(m_Slots[i].Key);                    
                        SIZE_T       index = hash & newGroupMask;
                        const UCHAR  h2    = static_cast<UCHAR>(hash >> 57);
                        
                        while (true)
                        {                        
                            const UINT64 ctrlBlock = LoadCtrlGroup(&pNewCtrl[index]);
                            UINT64 empty = ctrlBlock & 0x8080808080808080ULL;
                            
                            if (empty != 0) [[likely]]
                            {
                                unsigned long bitPos;
                                _BitScanForward64(&bitPos, empty);
                                
                                const SIZE_T realIdx = index + (bitPos >> 3);
                                pNewCtrl[realIdx] = h2;
                                
                                new (&pNewSlots[realIdx].Key)   K(kstd::move(m_Slots[i].Key));
                                new (&pNewSlots[realIdx].Value) V(kstd::move(m_Slots[i].Value));
                                
                                m_Slots[i].Key.~K();
                                m_Slots[i].Value.~V();
                                break;
                            }
                            
                            index = (index + kGroupSize) & newGroupMask;
                        }

                        occupied &= occupied - 1;
                    }
                }
            }
            
            ExFreePoolWithTag(m_Ctrl, PoolTag);
        }

        m_Ctrl      = pNewCtrl;
        m_Slots     = pNewSlots;
        m_Capacity  = NewCapacity;
        m_MaxLoad   = (NewCapacity / 10) * 7 + ((NewCapacity % 10) * 7 + 9) / 10;
        m_GroupMask = newGroupMask;
        
        return STATUS_SUCCESS;
    }

private:    
    UCHAR* m_Ctrl;      // Pointer to the control byte array mapping H2 metadata and empty slots.        
    Slot*  m_Slots;     // Pointer to the array holding the mapped Key/Value structures.        
    SIZE_T m_Capacity;  // The current maximum number of elements the map can hold before expanding.        
    SIZE_T m_Size;      // The current count of actively stored elements in the map.
    SIZE_T m_MaxLoad;   // Precomputed 70% load factor threshold eliminating per-insert multiplications.
    SIZE_T m_GroupMask; // Precomputed group index mask ((m_Capacity - 1) & ~(kGroupSize - 1)).
};
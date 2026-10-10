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
    // Stafford's Mix13 / SplitMix64 bijection mixer.
    // Provides strict avalanche (SAC criterion) and forms a 1-to-1 bijection on 
    // 64-bit values.
    //
    // Parameters:
    //   Val - The 64-bit seed or block to be avalanched.
    //
    // Return:
    //   The mixed 64-bit value ensuring uniform bit distribution.
    //--------------------------------------------------------------------------------
    static __forceinline UINT64 Mix64(_In_ UINT64 Val) noexcept
    {        
        UINT64 z = Val + 0x9E3779B97F4A7C15ULL;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
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
        #else
            #error "KDefaultHash 16-byte fast path requires a 64-bit architecture (x64 or ARM64)."
        #endif

            // Fold the 128-bit product back into 64 bits ensuring high bits influence the lower index
            return static_cast<SIZE_T>(low ^ high);
        }
        else
        {
            static_assert(kstd::has_unique_object_representations_v<T>,
                "KDefaultHash generic fallback requires types without padding to prevent entropy leaks.");

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
                // Incorporate struct size into the final mix to prevent cross-size collisions
                return static_cast<SIZE_T>(Mix64(lowRes ^ highRes ^ sizeof(T)));
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

                    a1 ^= seed1;
                    b1 ^= 0x9E3779B97F4A7C15ULL;
                    a2 ^= seed2;
                    b2 ^= 0xBF58476D1CE4E5B9ULL;

                    UINT64 L1, H1, L2, H2;
                #if defined(_M_X64)
                    L1 = _umul128(a1, b1, &H1);
                    L2 = _umul128(a2, b2, &H2);
                #elif defined(_M_ARM64)
                    L1 = a1 * b1; H1 = __umulh(a1, b1);
                    L2 = a2 * b2; H2 = __umulh(a2, b2);
                #endif
                    seed1 = L1 ^ H1;
                    seed2 = L2 ^ H2;
                }

                if constexpr ((sizeof(T) % 32) >= 16)
                {
                    UINT64 a, b;
                    RtlCopyMemory(&a, p + i, 8);
                    RtlCopyMemory(&b, p + i + 8, 8);

                    a ^= seed1;
                    b ^= 0x9E3779B97F4A7C15ULL;

                    UINT64 L, H;
                #if defined(_M_X64)
                    L = _umul128(a, b, &H);
                #elif defined(_M_ARM64)
                    L = a * b; 
                    H = __umulh(a, b);
                #endif
                    seed1 = L ^ H;
                }

                // Branchless Overlapping Tail: Hash the absolute LAST 16 bytes of the struct.
                if constexpr ((sizeof(T) % 16) != 0)
                {
                    UINT64 a, b;
                    RtlCopyMemory(&a, p + sizeof(T) - 16, 8);
                    RtlCopyMemory(&b, p + sizeof(T) - 8, 8);

                    a ^= seed1;
                    b ^= seed2;

                    UINT64 L, H;
                #if defined(_M_X64)
                    L = _umul128(a, b, &H);
                #elif defined(_M_ARM64)
                    L = a * b; 
                    H = __umulh(a, b);
                #endif
                    seed1 = L ^ H;
                }

                return static_cast<SIZE_T>(Mix64(seed1 ^ seed2));
            }
        }
    }
};

//--------------------------------------------------------------------------------
// Disperses the top 7 bits for short string prefixes so H2 != 0x00.
//--------------------------------------------------------------------------------
struct KPrecomputedHash
{
    //--------------------------------------------------------------------------------
    // Generates a well-distributed hash from an already generated 64-bit seed.
    //
    // Parameters:
    //   Key - The precomputed 64-bit value to hash.
    //
    // Return:
    //   Avalanched 64-bit hash.
    //--------------------------------------------------------------------------------
    SIZE_T operator()(_In_ UINT64 Key) const noexcept
    {
        return static_cast<SIZE_T>(KDefaultHash<UINT64>::Mix64(Key));
    }
};

//--------------------------------------------------------------------------------
// Pass-Through Hasher. Exclusively for clients supplying keys that are ALREADY 
// nearly-uniformly distributed. Acts as a pure identity function, bypassing
// all CPU mixing overhead and mapping the raw key directly to the SwissTable
// buckets.
//
// Template Parameters:
//   T - The scalar type of the raw key being mapped.
//--------------------------------------------------------------------------------
template <typename T>
struct KIdentityHash
{
    static_assert(kstd::is_trivially_copyable_v<T>, "KIdentityHash requires a trivially copyable type.");
    static_assert(sizeof(T) <= sizeof(SIZE_T), "KIdentityHash requires a scalar type no larger than SIZE_T.");

    //--------------------------------------------------------------------------------
    // Directly maps a trivially copyable structural key into a size_t index.
    //
    // Parameters:
    //   Key - The key to pass through.
    //
    // Return:
    //   The unmixed original key zero-extended to SIZE_T.
    //--------------------------------------------------------------------------------
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
            return static_cast<SIZE_T>(val);
        }
        else if constexpr (sizeof(T) == 2)
        {
            UINT16 val;
            RtlCopyMemory(&val, &Key, sizeof(UINT16));
            return static_cast<SIZE_T>(val);
        }
        else
        {
            UCHAR val;
            RtlCopyMemory(&val, &Key, sizeof(UCHAR));
            return static_cast<SIZE_T>(val);
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
    // SWAR (SIMD Within A Register) byte-matching technique.
    // Identifies exactly which of the 8 bytes inside 'Block' equal 'MatchByte'.
    //
    // Parameters:
    //   Block     - The 64-bit block of 8 control metadata bytes.
    //   MatchByte - The target metadata byte to search for.
    //
    // Return:
    //   A 64-bit bitmask where matched byte locations have their MSB set to 1.
    //--------------------------------------------------------------------------------
    static __forceinline UINT64 SwarMatch(_In_ UINT64 Block, 
                                          _In_ UCHAR  MatchByte) noexcept
    {
        const UINT64 xorBlock = Block ^ (0x0101010101010101ULL * MatchByte);
        return (xorBlock - 0x0101010101010101ULL) & ~xorBlock & 0x8080808080808080ULL;
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
                              m_Size(0)
    {
    }
    
    //--------------------------------------------------------------------------------
    // Core destructor resolving allocations safely back to the pool.
    //--------------------------------------------------------------------------------
    ~KFlatHashMap() noexcept
    {
        Clear();

        if (m_Ctrl != nullptr)
        {
            ExFreePoolWithTag(m_Ctrl, PoolTag);
        }
    }

    KFlatHashMap(const KFlatHashMap&) = delete;
    KFlatHashMap& operator=(const KFlatHashMap&) = delete;

    //--------------------------------------------------------------------------------
    // Pre-allocates map capacity to prevent reallocation and element migration churn.
    //
    // Parameters:
    //   Capacity - Minimum number of elements required before re-allocation triggers.
    //
    // Return:
    //   NTSTATUS indicating success, integer overflow, or pool insufficiency.
    //--------------------------------------------------------------------------------
    NTSTATUS Reserve(_In_ SIZE_T Capacity) noexcept
    {
        if (Capacity <= m_Capacity)
        {
            return STATUS_SUCCESS;
        }

        // Clamp the minimum baseline before the bitwise expansion to prevent 
        // intercepting legitimate arithmetic overflows later in the pipeline.
        SIZE_T targetCap = Capacity;
        
        if (targetCap < 16)
        {
            targetCap = 16;
        }

        // Hardware-accelerated algorithm to find the next power of 2.
        // Utilizes MSVC hardware intrinsics (bsr/lzcnt) to eliminate sequential 
        // bitwise data dependencies, reducing the operation to a single hardware instruction.
        unsigned long msbIndex;

    #ifdef _WIN64
        _BitScanReverse64(&msbIndex, targetCap - 1);
    #else
        _BitScanReverse(&msbIndex, static_cast<unsigned long>(targetCap - 1));
    #endif

        // Prevent undefined behavior from out-of-bounds bit shifts and catch integer overflow.
        // If the MSB is at the highest bit index for the architecture, the next power of 2 cannot fit.
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

        // Optimized load factor threshold bumped to 70% to prevent degraded linear probe chains
        // before hash table scaling evaluates sizing constraints
        if (m_Size * 10 >= m_Capacity * 7) [[unlikely]]
        {
            const SIZE_T newCap = (m_Capacity == 0) ? 16 : m_Capacity * 2;
            NTSTATUS status = Rehash(newCap);
            if (!NT_SUCCESS(status)) [[unlikely]]
            {
                return status;
            }
        }

        const SIZE_T hash  = Hash{}(Key);        
        SIZE_T       index = (hash & (m_Capacity - 1)) & ~(kGroupSize - 1);
        const SIZE_T start = index; 
        const UCHAR  h2    = static_cast<UCHAR>(hash >> 57) & 0x7F; 

        while (true)
        {            
            const UINT64 ctrlBlock = *reinterpret_cast<const __unaligned UINT64*>(&m_Ctrl[index]);
            UINT64 match = SwarMatch(ctrlBlock, h2);
            
            // Check for existing keys colliding with the same H2 metadata byte
            while (match != 0)
            {
                unsigned long bitPos;
                _BitScanForward64(&bitPos, match);
                
                const SIZE_T realIdx = index + (bitPos / 8);

                if (m_Slots[realIdx].Key == Key) [[unlikely]]
                {
                    *OutValue = &m_Slots[realIdx].Value;
                    
                    // Return informational status so callers know variadic args were not consumed
                    return STATUS_OBJECT_NAME_EXISTS; 
                }
                
                match &= match - 1;
            }

            // Find an empty slot using the zero-latency MSB shortcut.
            UINT64 empty = ctrlBlock & 0x8080808080808080ULL;            
            if (empty != 0) [[likely]]
            {
                unsigned long bitPos;
                _BitScanForward64(&bitPos, empty);
                
                // Since index is strictly aligned, index + bitPos/8 is guaranteed to never overflow m_Capacity
                const SIZE_T realIdx = index + (bitPos / 8);
                
                m_Ctrl[realIdx] = h2;
                
                new (&m_Slots[realIdx].Key)   K(Key);
                new (&m_Slots[realIdx].Value) V(kstd::forward<Args>(args)...);
                m_Size++;
                
                *OutValue = &m_Slots[realIdx].Value;
                return STATUS_SUCCESS;
            }

            // Hardware-friendly linear probing
            index = (index + kGroupSize) & (m_Capacity - 1);            
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
        const SIZE_T idx = FindIndexInternal(Key);

        if (idx != m_Capacity) [[likely]]
        {
            return &m_Slots[idx].Value;
        }

        return nullptr;
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
        const SIZE_T idx = FindIndexInternal(Key);

        if (idx != m_Capacity) [[likely]]
        {
            return &m_Slots[idx].Value;
        }

        return nullptr;
    }

    //--------------------------------------------------------------------------------
    // Clears the map, resetting control bytes and destroying values.
    // Restores metadata structures back to pre-allocation empty sentinels.
    //--------------------------------------------------------------------------------
    void Clear() noexcept
    {
        if (m_Ctrl != nullptr)
        {
            for (SIZE_T i = 0; i < m_Capacity; i++)
            {
                if (m_Ctrl[i] != kEmptyCtrl)
                {
                    m_Slots[i].Key.~K();
                    m_Slots[i].Value.~V();
                    m_Ctrl[i] = kEmptyCtrl;
                }
            }
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
        // Initializes the iterator and automatically advances to the first occupied 
        // slot in the map.
        //
        // Parameters:
        //   pCtrl    - Root metadata byte tracking array.
        //   pSlots   - Contiguous mapping target containing exact properties.
        //   Capacity - Upper limit array constraint protecting evaluation overruns.
        //   Index    - Starting location scalar.
        //--------------------------------------------------------------------------------
        BaseIterator(_In_ CtrlPtr pCtrl, 
                     _In_ SlotPtr pSlots, 
                     _In_ SIZE_T  Capacity, 
                     _In_ SIZE_T  Index) : m_Ctrl(pCtrl), 
                                           m_Slots(pSlots), 
                                           m_Capacity(Capacity), 
                                           m_Index(Index) 
        { 
            AdvanceToOccupied(); 
        }

        BaseIterator(const BaseIterator&) = default;
        BaseIterator& operator=(const BaseIterator&) = default;

        //--------------------------------------------------------------------------------
        // Conversion constructor allowing implicit promotion from Iterator to ConstIterator.
        // Const-correctness is inherently enforced: attempting to construct a non-const 
        // Iterator from a ConstIterator will fail to compile as UCHAR* cannot bind to const UCHAR*.
        //--------------------------------------------------------------------------------
        template <bool OtherConst>
        BaseIterator(const BaseIterator<OtherConst>& Other) : m_Ctrl(Other.m_Ctrl), 
                                                              m_Slots(Other.m_Slots), 
                                                              m_Capacity(Other.m_Capacity), 
                                                              m_Index(Other.m_Index) 
        {
        }

        //--------------------------------------------------------------------------------
        // Evaluates inequality between two iterators based on their current index.
        // Permits direct comparisons between Iterators and ConstIterators.
        //
        // Parameters:
        //   Other - Object against which inequality comparison occurs.
        //
        // Return:
        //   True if object indices are unequal, false otherwise.
        //--------------------------------------------------------------------------------
        template <bool OtherConst>
        bool operator!=(const BaseIterator<OtherConst>& Other) const 
        { 
            return m_Index != Other.m_Index; 
        }

        //--------------------------------------------------------------------------------
        // Evaluates equality between two iterators based on their current index.
        // Permits direct comparisons between Iterators and ConstIterators.
        //
        // Parameters:
        //   Other - Object against which equality comparison occurs.
        //
        // Return:
        //   True if object indices are equal, false otherwise.
        //--------------------------------------------------------------------------------
        template <bool OtherConst>
        bool operator==(const BaseIterator<OtherConst>& Other) const 
        { 
            return m_Index == Other.m_Index; 
        }
        
        //--------------------------------------------------------------------------------
        // Pre-increments the iterator, advancing past empty entries to the next valid 
        // element.
        //
        // Return:
        //   A reference to the incremented operator element.
        //--------------------------------------------------------------------------------
        BaseIterator& operator++() 
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
        BaseIterator operator++(int) 
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
        SlotRef operator*() const  
        { 
            return m_Slots[m_Index]; 
        }

        //--------------------------------------------------------------------------------
        // Accesses the Key or Value properties of the currently pointed-to slot.
        //
        // Return:
        //   Underlying address (mutable or const depending on instantiation).
        //--------------------------------------------------------------------------------
        SlotPtr operator->() const 
        { 
            return &m_Slots[m_Index]; 
        }

    private:
        //--------------------------------------------------------------------------------
        // Linearly scans the control array until a valid (non-empty) control byte is 
        // found, or the end of capacity is reached. Append-only logic relies safely 
        // on checking strictly for kEmptyCtrl.
        //--------------------------------------------------------------------------------
        void AdvanceToOccupied()
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
    Iterator begin() 
    { 
        return Iterator(m_Ctrl, m_Slots, m_Capacity, 0); 
    }

    //--------------------------------------------------------------------------------
    // Exposes the boundary Iterator mapped directly after maximum object capacity.
    //
    // Return:
    //   A terminus Iterator object indicating completion.
    //--------------------------------------------------------------------------------
    Iterator end()   
    { 
        return Iterator(m_Ctrl, m_Slots, m_Capacity, m_Capacity); 
    }

    //--------------------------------------------------------------------------------
    // Map traversal boundary accessors for const-qualified maps.
    //--------------------------------------------------------------------------------
    ConstIterator begin() const  
    { 
        return ConstIterator(m_Ctrl, m_Slots, m_Capacity, 0); 
    }
    
    ConstIterator end() const    
    { 
        return ConstIterator(m_Ctrl, m_Slots, m_Capacity, m_Capacity); 
    }
    
    ConstIterator cbegin() const 
    { 
        return begin(); 
    }
    
    ConstIterator cend() const   
    { 
        return end(); 
    }

private:

    //--------------------------------------------------------------------------------
    // Internal helper to locate the absolute index of a key.
    // Unifies the probing logic for Find() and Find() const operations.
    //
    // Parameters:
    //   Key - Target key structure to locate.
    //
    // Return:
    //   The absolute index in the slot array, or m_Capacity if not found.
    //--------------------------------------------------------------------------------
    __forceinline SIZE_T FindIndexInternal(_In_ const K& Key) const noexcept
    {
        // Bypass map hashing entirely if there are currently no active elements
        if (m_Size == 0) [[unlikely]]
        {
            return m_Capacity;
        }

        const SIZE_T hash  = Hash{}(Key);        
        SIZE_T       index = (hash & (m_Capacity - 1)) & ~(kGroupSize - 1);
        const SIZE_T start = index;
        const UCHAR  h2    = static_cast<UCHAR>(hash >> 57) & 0x7F;

        while (true)
        {            
            const UINT64 ctrlBlock = *reinterpret_cast<const __unaligned UINT64*>(&m_Ctrl[index]);
            UINT64 match = SwarMatch(ctrlBlock, h2);
            
            while (match != 0)
            {
                unsigned long bitPos;
                _BitScanForward64(&bitPos, match);
                
                const SIZE_T realIdx = index + (bitPos / 8);

                if (m_Slots[realIdx].Key == Key) [[likely]]
                {
                    return realIdx;
                }
                
                match &= match - 1;
            }

            // High-speed empty block detection: 
            // Valid h2 metadata bytes are strictly 7-bit (MSB = 0).
            // Empty control bytes (0xFF) are the only bytes with the MSB set.
            if ((ctrlBlock & 0x8080808080808080ULL) != 0) [[likely]]
            {
                return m_Capacity;
            }

            index = (index + kGroupSize) & (m_Capacity - 1);
            
            if (index == start) [[unlikely]]
            {
                break;
            }
        }

        return m_Capacity;
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
        SIZE_T ctrlBytes      = NewCapacity;
        SIZE_T slotBytes      = 0;
        SIZE_T slotAlign      = alignof(Slot);
        SIZE_T maxPadding     = slotAlign - 1;
        
        // Re-introduce padding baseline separation for optimal cache lane separation
        SIZE_T slotsOffset    = 0;
        SIZE_T totalAllocSize = 0;

        if (!NT_SUCCESS(RtlSizeTAdd(ctrlBytes, 63, &slotsOffset))) [[unlikely]]
        {
            return STATUS_INTEGER_OVERFLOW;
        }
        
        slotsOffset = slotsOffset & ~63ULL;

        if (!NT_SUCCESS(RtlSizeTMult(NewCapacity, sizeof(Slot), &slotBytes))) [[unlikely]]
        {
            return STATUS_INTEGER_OVERFLOW;
        }

        if (!NT_SUCCESS(RtlSizeTAdd(slotsOffset, maxPadding, &totalAllocSize)) ||
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
        UINT_PTR slotsAddr = (ctrlAddr + slotsOffset + maxPadding) & ~maxPadding;
        Slot* __restrict pNewSlots = reinterpret_cast<Slot*>(slotsAddr);

        for (SIZE_T i = 0; i < NewCapacity; i++)
        {
            pNewCtrl[i] = kEmptyCtrl;
        }

        if (m_Ctrl != nullptr)
        {
            // Re-hash and move existing items over to the newly expanded table
            for (SIZE_T i = 0; i < m_Capacity; i++)
            {
                if (m_Ctrl[i] != kEmptyCtrl) [[likely]]
                {
                    const SIZE_T hash = Hash{}(m_Slots[i].Key);                    
                    SIZE_T index = (hash & (NewCapacity - 1)) & ~(kGroupSize - 1);
                    const UCHAR h2 = static_cast<UCHAR>(hash >> 57) & 0x7F;
                    
                    while (true)
                    {                        
                        const UINT64 ctrlBlock = *reinterpret_cast<const __unaligned UINT64*>(&pNewCtrl[index]);
                        UINT64 empty = ctrlBlock & 0x8080808080808080ULL;
                        
                        if (empty != 0) [[likely]]
                        {
                            unsigned long bitPos;
                            _BitScanForward64(&bitPos, empty);
                            
                            SIZE_T realIdx = index + (bitPos / 8);
                            pNewCtrl[realIdx] = h2;
                            
                            new (&pNewSlots[realIdx].Key)   K(kstd::move(m_Slots[i].Key));
                            new (&pNewSlots[realIdx].Value) V(kstd::move(m_Slots[i].Value));
                            
                            m_Slots[i].Key.~K();
                            m_Slots[i].Value.~V();
                            break;
                        }
                        
                        index = (index + kGroupSize) & (NewCapacity - 1);
                    }
                }
            }
            
            ExFreePoolWithTag(m_Ctrl, PoolTag);
        }

        m_Ctrl     = pNewCtrl;
        m_Slots    = pNewSlots;
        m_Capacity = NewCapacity;
        
        return STATUS_SUCCESS;
    }

private:    
    UCHAR* m_Ctrl;     // Pointer to the control byte array mapping H2 metadata and empty slots.        
    Slot*  m_Slots;    // Pointer to the array holding the mapped Key/Value structures.        
    SIZE_T m_Capacity; // The current maximum number of elements the map can hold before expanding.        
    SIZE_T m_Size;     // The current count of actively stored elements in the map.
};
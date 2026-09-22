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
    static inline UINT64 Mix64(_In_ UINT64 Val) noexcept
    {
        // Adding the odd golden-ratio constant guarantees a 1-to-1 bijection and non-zero zero mapping.
        UINT64 z = Val + 0x9E3779B97F4A7C15ULL;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
    }

    //--------------------------------------------------------------------------------
    // Computes the hash for the given key based on its structural size.
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
            const UINT64 val = *reinterpret_cast<const __unaligned UINT64*>(&Key);
            return static_cast<SIZE_T>(Mix64(val));
        }
        else if constexpr (sizeof(T) == 4)
        {
            // Scalar path for 32-bit integers, ULONGs, NTSTATUS codes, etc.
            const UINT32 val = *reinterpret_cast<const __unaligned UINT32*>(&Key);
            return static_cast<SIZE_T>(Mix64(static_cast<UINT64>(val)));
        }
        else if constexpr (sizeof(T) == 2)
        {
            // Scalar path for 16-bit integers, USHORT, WCHAR, etc.
            const UINT16 val = *reinterpret_cast<const __unaligned UINT16*>(&Key);
            return static_cast<SIZE_T>(Mix64(static_cast<UINT64>(val)));
        }
        else if constexpr (sizeof(T) == 1)
        {
            // Scalar path for 8-bit integers, CHAR, UCHAR, bool.
            const UCHAR val = *reinterpret_cast<const UCHAR*>(&Key);
            return static_cast<SIZE_T>(Mix64(static_cast<UINT64>(val)));
        }
        else if constexpr (sizeof(T) == 16)
        {
            // Branchless fast path for 128-bit types (GUID, LUID pairs, IPv6 addresses).
            // Asymmetric mixing prevents commutativity (k1 ^ k2 != k2 ^ k1).
            const __unaligned UINT64* p64 = reinterpret_cast<const __unaligned UINT64*>(&Key);
            return static_cast<SIZE_T>(Mix64(p64[0] ^ Mix64(p64[1])));
        }
        else
        {
            // High-speed SWAR 64-bit block chunking for arbitrary structs and memory buffers.            
            const unsigned char* p = reinterpret_cast<const unsigned char*>(&Key);
            UINT64 hash = 0xCBF29CE484222325ULL ^ (static_cast<UINT64>(sizeof(T)) * 0x9E3779B97F4A7C15ULL);
            SIZE_T i = 0;

            for (; i + 8 <= sizeof(T); i += 8)
            {
                const UINT64 chunk = *reinterpret_cast<const __unaligned UINT64*>(p + i);
                hash = (hash ^ chunk) * 0x100000001B3ULL;
                hash ^= (hash >> 31);
            }

            if constexpr ((sizeof(T) & 7) != 0)
            {
                UINT64 tail = 0;
                for (SIZE_T j = i; j < sizeof(T); ++j)
                {
                    tail |= static_cast<UINT64>(p[j]) << ((j - i) * 8);
                }
                hash = (hash ^ tail) * 0x100000001B3ULL;
            }

            // Final avalanche step guarantees uniform bit distribution across all 64 bits.
            return static_cast<SIZE_T>(Mix64(hash));
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
            return static_cast<SIZE_T>(*reinterpret_cast<const __unaligned UINT64*>(&Key));
        }
        else if constexpr (sizeof(T) == 4)
        {
            return static_cast<SIZE_T>(*reinterpret_cast<const __unaligned UINT32*>(&Key));
        }
        else if constexpr (sizeof(T) == 2)
        {
            return static_cast<SIZE_T>(*reinterpret_cast<const __unaligned UINT16*>(&Key));
        }
        else
        {
            return static_cast<SIZE_T>(*reinterpret_cast<const UCHAR*>(&Key));
        }
    }
};

//--------------------------------------------------------------------------------
// KFlatHashMap is an open-addressing hash table leveraging SIMD Within 
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
class alignas(64) KFlatHashMap
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
    static inline UINT64 SwarMatch(_In_ UINT64 Block, 
                                   _In_ UCHAR  MatchByte) noexcept
    {
        const UINT64 xorBlock = Block ^ (0x0101010101010101ULL * MatchByte);
        return (xorBlock - 0x0101010101010101ULL) & ~xorBlock & 0x8080808080808080ULL;
    }

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
    // Parameters:
    //   Key      - The map key indexing the element.
    //   OutValue - Double-pointer receiving the constructed value's memory address.
    //   args     - Variadic template parameters for the constructed value object.
    //
    // Return:
    //   STATUS_SUCCESS on placement completion or NTSTATUS on memory constraints.
    //--------------------------------------------------------------------------------
    template <typename... Args>
    NTSTATUS Emplace(_In_                           const K& Key,
                     _Outptr_result_nullonfailure_  V**      OutValue,
                     _In_                           Args&&... args) noexcept
    {
        *OutValue = nullptr;

        // Optimized load factor threshold bumped to 75% for better memory density
        if (m_Size * 4 >= m_Capacity * 3) [[unlikely]]
        {
            const SIZE_T newCap = (m_Capacity == 0) ? 16 : m_Capacity * 2;
            NTSTATUS status = Rehash(newCap);
            if (!NT_SUCCESS(status)) [[unlikely]]
            {
                return status;
            }
        }

        const SIZE_T hash  = Hash{}(Key);        
        SIZE_T       index = hash & (m_Capacity - 1);
        const SIZE_T start = index; 
        const UCHAR  h2    = static_cast<UCHAR>(hash >> 57) & 0x7F; 

        while (true)
        {            
            const UINT64 ctrlBlock = *reinterpret_cast<const __unaligned UINT64*>(&m_Ctrl[index]);
            
            // Optimized prefetching pipeline two groups ahead to hide memory latency
            K_PREFETCH(&m_Ctrl[(index + kGroupSize * 2) & (m_Capacity - 1)]);

            UINT64 match = SwarMatch(ctrlBlock, h2);
            
            // Check for existing keys colliding with the same H2 metadata byte
            while (match != 0)
            {
                unsigned long bitPos;
                _BitScanForward64(&bitPos, match);
                
                const SIZE_T realIdx = (index + (bitPos / 8)) & (m_Capacity - 1);

                // Removed immediate K_PREFETCH(&m_Slots[realIdx]) to eliminate CPU pipeline stalling

                if (m_Slots[realIdx].Key == Key) [[unlikely]]
                {
                    *OutValue = &m_Slots[realIdx].Value;
                    return STATUS_SUCCESS;
                }
                
                match &= match - 1;
            }

            // Find an empty slot using the zero-latency MSB shortcut.
            // Valid h2 bytes are clamped to 0x7F (MSB=0). kEmptyCtrl is 0xFF (MSB=1).
            UINT64 empty = ctrlBlock & 0x8080808080808080ULL;            
            if (empty != 0) [[likely]]
            {
                unsigned long bitPos;
                _BitScanForward64(&bitPos, empty);
                
                const SIZE_T realIdx = (index + (bitPos / 8)) & (m_Capacity - 1);
                
                m_Ctrl[realIdx] = h2;
                
                // Replicate control bytes to the end to optimize boundary wrap-around checks
                if (realIdx < kGroupSize) [[unlikely]]
                {
                    m_Ctrl[m_Capacity + realIdx] = h2;
                }
                
                new (&m_Slots[realIdx].Key)   K(Key);
                new (&m_Slots[realIdx].Value) V(kstd::forward<Args>(args)...);
                m_Size++;
                
                *OutValue = &m_Slots[realIdx].Value;
                return STATUS_SUCCESS;
            }

            // Linear probe to the next group of 8 slots
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
    // Parameters:
    //   Key      - The mapped entry identifier to lookup or create.
    //   OutValue - Receives a mutable pointer mapped to the object's memory.
    //
    // Return:
    //   STATUS_SUCCESS or corresponding NTSTATUS on failed resource allocation.
    //--------------------------------------------------------------------------------
    NTSTATUS GetOrInsert(_In_                          const K& Key,
                         _Outptr_result_nullonfailure_ V**      OutValue) noexcept
    {
        return Emplace(Key, OutValue);
    }

    //--------------------------------------------------------------------------------
    // Looks up a key and returns a pointer to its value if found.
    //
    // Parameters:
    //   Key - Target key structure evaluated via SWAR hashing protocol.
    //
    // Return:
    //   Pointer to the mapped item, or nullptr if the element is absent.
    //--------------------------------------------------------------------------------
    V* Find(_In_ const K& Key) const noexcept
    {
        if (m_Capacity == 0) [[unlikely]]
        {
            return nullptr;
        }

        const SIZE_T hash  = Hash{}(Key);        
        SIZE_T       index = hash & (m_Capacity - 1);
        const SIZE_T start = index;
        
        const UCHAR h2 = static_cast<UCHAR>(hash >> 57) & 0x7F;

        while (true)
        {            
            const UINT64 ctrlBlock = *reinterpret_cast<const __unaligned UINT64*>(&m_Ctrl[index]);
            
            // Optimized prefetching pipeline two groups ahead
            K_PREFETCH(&m_Ctrl[(index + kGroupSize * 2) & (m_Capacity - 1)]);

            UINT64 match = SwarMatch(ctrlBlock, h2);
            
            while (match != 0)
            {
                unsigned long bitPos;
                _BitScanForward64(&bitPos, match);
                
                const SIZE_T realIdx = (index + (bitPos / 8)) & (m_Capacity - 1);
                
                // Removed immediate K_PREFETCH(&m_Slots[realIdx]) to eliminate CPU pipeline stalling

                if (m_Slots[realIdx].Key == Key) [[likely]]
                {
                    return &m_Slots[realIdx].Value;
                }
                
                match &= match - 1;
            }

            // High-speed empty block detection: 
            // Valid h2 metadata bytes are strictly 7-bit (MSB = 0).
            // Empty control bytes (0xFF) are the only bytes with the MSB set.
            // Bypasses SwarMatch overhead entirely.
            if ((ctrlBlock & 0x8080808080808080ULL) != 0) [[likely]]
            {
                return nullptr;
            }

            index = (index + kGroupSize) & (m_Capacity - 1);
            
            if (index == start) [[unlikely]]
            {
                break;
            }
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
                    
                    if (i < kGroupSize) [[unlikely]]
                    {
                        m_Ctrl[m_Capacity + i] = kEmptyCtrl;
                    }
                }
            }
        }
        
        m_Size = 0;
    }

    //--------------------------------------------------------------------------------
    // Iterator provides forward-traversal capabilities across the hash map.
    // It utilizes the control byte array to efficiently skip empty indices 
    // without inspecting the underlying Key/Value slots.
    //--------------------------------------------------------------------------------
    class Iterator
    {
    public:
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
        Iterator(_In_ UCHAR* pCtrl, 
                 _In_ Slot*  pSlots, 
                 _In_ SIZE_T Capacity, 
                 _In_ SIZE_T Index) : m_Ctrl(pCtrl), 
                                      m_Slots(pSlots), 
                                      m_Capacity(Capacity), 
                                      m_Index(Index) 
        { 
            AdvanceToOccupied(); 
        }

        //--------------------------------------------------------------------------------
        // Evaluates inequality between two iterators based on their current index.
        //
        // Parameters:
        //   Other - Object against which inequality comparison occurs.
        //
        // Return:
        //   True if object indices are unequal, false otherwise.
        //--------------------------------------------------------------------------------
        bool operator!=(const Iterator& Other) const 
        { 
            return m_Index != Other.m_Index; 
        }
        
        //--------------------------------------------------------------------------------
        // Pre-increments the iterator, advancing past empty entries to the next valid 
        // element.
        //
        // Return:
        //   A reference to the incremented operator element.
        //--------------------------------------------------------------------------------
        Iterator& operator++() 
        { 
            m_Index++; 
            AdvanceToOccupied(); 
            return *this; 
        }
        
        //--------------------------------------------------------------------------------
        // Dereferences the iterator to provide a direct reference to the Key/Value slot.
        //
        // Return:
        //   Mutable underlying reference.
        //--------------------------------------------------------------------------------
        Slot& operator*()  
        { 
            return m_Slots[m_Index]; 
        }

        //--------------------------------------------------------------------------------
        // Accesses the Key or Value properties of the currently pointed-to slot.
        //
        // Return:
        //   Mutable underlying address.
        //--------------------------------------------------------------------------------
        Slot* operator->() 
        { 
            return &m_Slots[m_Index]; 
        }

    private:
        //--------------------------------------------------------------------------------
        // Linearly scans the control array until a valid (non-empty) control byte is 
        // found, or the end of capacity is reached.
        //--------------------------------------------------------------------------------
        void AdvanceToOccupied()
        {
            while (m_Index < m_Capacity && m_Ctrl[m_Index] == kEmptyCtrl) 
            { 
                m_Index++; 
            }
        }
        
        UCHAR* m_Ctrl;     // Pointer to the parent map's control byte array.                
        Slot*  m_Slots;    // Pointer to the parent map's key-value slots.                
        SIZE_T m_Capacity; // The total allocated capacity of the map.                
        SIZE_T m_Index;    // The current cursor index representing the iterator's position.
    };

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

private:
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
        SIZE_T ctrlBytes      = 0;
        SIZE_T slotBytes      = 0;
        SIZE_T slotsOffset    = 0;
        SIZE_T totalAllocSize = 0;

        if (!NT_SUCCESS(RtlSizeTAdd(NewCapacity, kGroupSize, &ctrlBytes))) [[unlikely]]
        {
            return STATUS_INTEGER_OVERFLOW;
        }
        
        SIZE_T unalignedOffset = 0;
        
        if (!NT_SUCCESS(RtlSizeTAdd(ctrlBytes, 63, &unalignedOffset))) [[unlikely]]
        {
            return STATUS_INTEGER_OVERFLOW;
        }
        
        slotsOffset = unalignedOffset & ~63ULL;
        
        if (!NT_SUCCESS(RtlSizeTMult(NewCapacity, sizeof(Slot), &slotBytes))) [[unlikely]]
        {
            return STATUS_INTEGER_OVERFLOW;
        }

        if (!NT_SUCCESS(RtlSizeTAdd(slotsOffset, slotBytes, &totalAllocSize))) [[unlikely]]
        {
            return STATUS_INTEGER_OVERFLOW;
        }

        constexpr POOL_FLAGS allocFlags = PoolFlags | POOL_FLAG_UNINITIALIZED | POOL_FLAG_CACHE_ALIGNED;

        UCHAR* __restrict pNewCtrl = static_cast<UCHAR*>(ExAllocatePool2(allocFlags, totalAllocSize, PoolTag));        
        if (pNewCtrl == nullptr) [[unlikely]]
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Slot* __restrict pNewSlots = reinterpret_cast<Slot*>(pNewCtrl + slotsOffset);

        for (SIZE_T i = 0; i < NewCapacity + kGroupSize; i++)
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
                    SIZE_T index = hash & (NewCapacity - 1);
                    const UCHAR h2 = static_cast<UCHAR>(hash >> 57) & 0x7F;
                    
                    while (true)
                    {                        
                        const UINT64 ctrlBlock = *reinterpret_cast<const __unaligned UINT64*>(&pNewCtrl[index]);
                        
                        // Use MSB shortcut to quickly find the new empty target slot
                        UINT64 empty = ctrlBlock & 0x8080808080808080ULL;
                        
                        if (empty != 0) [[likely]]
                        {
                            unsigned long bitPos;
                            _BitScanForward64(&bitPos, empty);
                            SIZE_T realIdx = (index + (bitPos / 8)) & (NewCapacity - 1);
                            
                            pNewCtrl[realIdx] = h2;
                            
                            if (realIdx < kGroupSize) [[unlikely]]
                            {
                                pNewCtrl[NewCapacity + realIdx] = h2;
                            }
                            
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
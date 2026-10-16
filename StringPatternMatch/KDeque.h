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
#include "PlatformUtils.h"

#ifndef SIZE_MAX
#define SIZE_MAX ((SIZE_T)(~((SIZE_T)0)))
#endif

//--------------------------------------------------------------------------------
// KDeque implements a segmented array-based double-ended queue (optimized 
// as an append-only deque). By dividing memory into fixed-size contiguous chunks 
// (BlockCapacity), it bypasses the need for massive contiguous allocations and 
// prevents costly memory shifting or reallocations. This segmented structure 
// also guarantees that pointers to elements remain stable once emplaced.
//
// Capacity Limitation: 
//   To prevent unbounded kernel memory exhaustion, KDeque is constrained to a 
//   maximum of kMaxBlocks (256) dynamically tracked blocks. With the default 
//   BlockCapacity of 512, the absolute maximum number of elements is 131,072.
//
// Template Parameters:
//   T             - The type of elements stored in the deque.
//   PoolType      - The NT kernel pool type used for block allocations.
//   BlockCapacity - The fixed number of elements each memory block holds.
//   PoolTag       - The 4-byte tag used for kernel memory tracking.
//--------------------------------------------------------------------------------
template <typename T, POOL_FLAGS PoolType = POOL_FLAG_NON_PAGED, SIZE_T BlockCapacity = 512, ULONG PoolTag = 'qeDK'>
class KDeque
{
    static_assert(BlockCapacity > 0 && (BlockCapacity & (BlockCapacity - 1)) == 0,
        "BlockCapacity must be a non-zero power of 2.");
    static_assert(BlockCapacity <= (SIZE_MAX / sizeof(T)),
        "BlockCapacity exceeds size limits.");
    static_assert(alignof(T) <= MEMORY_ALLOCATION_ALIGNMENT,
        "KDeque requires alignof(T) <= MEMORY_ALLOCATION_ALIGNMENT (16 bytes) for kernel pool allocations.");

private:

    //--------------------------------------------------------------------------------
    // Calculates the base-2 logarithm of a given number.
    // Replaced recursion with an iterative constexpr loop to strictly adhere to 
    // kernel-mode safe coding practices and prevent static analysis warnings.
    //
    // Parameters:
    //   n - The numeric value to calculate the logarithm for.
    //
    // Return:
    //   The base-2 logarithm of the provided value.
    //--------------------------------------------------------------------------------
    static constexpr SIZE_T Log2(_In_ SIZE_T n) noexcept 
    { 
        SIZE_T result = 0;
        
        while (n > 1) 
        {
            n >>= 1;
            result++;
        }
        
        return result;
    }
    
    static constexpr SIZE_T BlockShift = Log2(BlockCapacity);
    static constexpr SIZE_T BlockMask  = BlockCapacity - 1;

    //--------------------------------------------------------------------------------
    // Out-of-line slow path for allocating a new segment block when crossing a block
    // boundary (once every BlockCapacity insertions). Keeps EmplaceBack a tiny leaf
    // function on the hot path so caller loops inline and unroll without register spills.
    //
    // Parameters:
    //   BlockIndex - The target block slot index to validate and allocate.
    //
    // Return:
    //   STATUS_SUCCESS on success, STATUS_QUOTA_EXCEEDED if BlockIndex >= kMaxBlocks,
    //   or STATUS_INSUFFICIENT_RESOURCES on pool allocation failure.
    //--------------------------------------------------------------------------------
    __declspec(noinline) NTSTATUS AllocateBlock(_In_ SIZE_T BlockIndex) noexcept
    {
        // Ensure we do not exceed the maximum number of statically tracked blocks.
        if (BlockIndex >= kMaxBlocks) [[unlikely]]
        {
            return STATUS_QUOTA_EXCEEDED;
        }

        if (m_Blocks[BlockIndex] == nullptr) [[likely]]
        {
            constexpr POOL_FLAGS allocFlags = PoolType | POOL_FLAG_UNINITIALIZED;
            
            m_Blocks[BlockIndex] = static_cast<T*>(ExAllocatePool2(allocFlags, BlockCapacity * sizeof(T), PoolTag));
            
            if (m_Blocks[BlockIndex] == nullptr) [[unlikely]]
            {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }

        return STATUS_SUCCESS;
    }

public:
    //--------------------------------------------------------------------------------
    // Initializes an empty KDeque, zeroing out the block tracking array.
    //--------------------------------------------------------------------------------
    KDeque() noexcept : m_Size(0)
    {
        RtlZeroMemory(m_Blocks, sizeof(m_Blocks));
    }

    KDeque(const KDeque&) = delete;
    KDeque& operator=(const KDeque&) = delete;

    //--------------------------------------------------------------------------------
    // Move constructor transferring block ownership in O(1) without pool allocations.
    //--------------------------------------------------------------------------------
    KDeque(KDeque&& Other) noexcept : m_Size(Other.m_Size)
    {
        RtlCopyMemory(m_Blocks, Other.m_Blocks, sizeof(m_Blocks));
        RtlZeroMemory(Other.m_Blocks, sizeof(Other.m_Blocks));
        Other.m_Size = 0;
    }

    //--------------------------------------------------------------------------------
    // Move assignment operator releasing current blocks and taking ownership of Other.
    //--------------------------------------------------------------------------------
    KDeque& operator=(KDeque&& Other) noexcept
    {
        if (this != &Other)
        {
            Clear();
            RtlCopyMemory(m_Blocks, Other.m_Blocks, sizeof(m_Blocks));
            m_Size = Other.m_Size;

            RtlZeroMemory(Other.m_Blocks, sizeof(Other.m_Blocks));
            Other.m_Size = 0;
        }

        return *this;
    }

    //--------------------------------------------------------------------------------
    // Destroys the deque, invoking destructors on all elements and freeing pool memory.
    //--------------------------------------------------------------------------------
    ~KDeque() noexcept
    {
        Clear();
    }

    //--------------------------------------------------------------------------------
    // Constructs an element in-place at the end of the deque.
    //
    // Parameters:
    //   arguments - Variadic template arguments forwarded to the element constructor.
    //
    // Return:
    //   STATUS_SUCCESS on success.
    //   STATUS_QUOTA_EXCEEDED if the kMaxBlocks capacity limitation is reached.
    //   STATUS_INSUFFICIENT_RESOURCES if kernel pool allocation fails.
    //--------------------------------------------------------------------------------
    template <typename... Args>
    __forceinline NTSTATUS EmplaceBack(_In_ Args&&... arguments) noexcept
    {
        const SIZE_T currentSize = m_Size;
        const SIZE_T slotIndex   = currentSize & BlockMask;

        // A new block is only ever needed at the start of a block (slotIndex == 0).
        // For slots 1..BlockCapacity-1 (99.8% of calls), the block is guaranteed to be
        // already allocated and within kMaxBlocks.
        if (slotIndex == 0) [[unlikely]]
        {
            NTSTATUS status = AllocateBlock(currentSize >> BlockShift);
            if (!NT_SUCCESS(status)) [[unlikely]]
            {
                return status;
            }
        }

        // Locate the exact slot within the block and construct the object.
        T* __restrict pBlock = m_Blocks[currentSize >> BlockShift];
        new (&pBlock[slotIndex]) T(kstd::forward<Args>(arguments)...);
        m_Size = currentSize + 1;

        return STATUS_SUCCESS;
    }

    //--------------------------------------------------------------------------------
    // Retrieves a reference to the last element in the deque.
    // Caller must ensure the deque is not empty prior to invocation.
    //
    // Return:
    //   A mutable reference to the most recently emplaced element.
    //--------------------------------------------------------------------------------
    T& Back() noexcept
    {
        SIZE_T lastIndex = m_Size - 1;
        return m_Blocks[lastIndex >> BlockShift][lastIndex & BlockMask];
    }

    //--------------------------------------------------------------------------------
    // Retrieves a const reference to the last element in the deque.
    // Caller must ensure the deque is not empty prior to invocation.
    //
    // Return:
    //   A constant reference to the most recently emplaced element.
    //--------------------------------------------------------------------------------
    const T& Back() const noexcept
    {
        SIZE_T lastIndex = m_Size - 1;
        return m_Blocks[lastIndex >> BlockShift][lastIndex & BlockMask];
    }

    //--------------------------------------------------------------------------------
    // Clears all elements, invoking destructors if necessary, and frees underlying 
    // memory blocks.
    //--------------------------------------------------------------------------------
    void Clear() noexcept
    {
        const SIZE_T fullBlocks = m_Size >> BlockShift;
        const SIZE_T remSlots   = m_Size & BlockMask;

        // Explicitly invoke destructors for complex types using contiguous block loops.
        if constexpr (!kstd::is_trivially_destructible_v<T>)
        {
            for (SIZE_T b = 0; b < fullBlocks; b++)
            {
                T* __restrict pBlock = m_Blocks[b];
                for (SIZE_T s = 0; s < BlockCapacity; s++)
                {
                    pBlock[s].~T();
                }
            }

            if (remSlots > 0)
            {
                T* __restrict pBlock = m_Blocks[fullBlocks];
                for (SIZE_T s = 0; s < remSlots; s++)
                {
                    pBlock[s].~T();
                }
            }
        }

        // Only scan up to the highest potentially allocated block index.
        // Note: if the first EmplaceBack of a new block allocated the block and then
        // exited, at most fullBlocks + 1 blocks can be non-null.
        const SIZE_T maxAllocatedBlocks = (fullBlocks < kMaxBlocks) ? (fullBlocks + 1) : kMaxBlocks;

        for (SIZE_T i = 0; i < maxAllocatedBlocks; i++)
        {
            if (m_Blocks[i] != nullptr)
            {
                ExFreePoolWithTag(m_Blocks[i], PoolTag);
                m_Blocks[i] = nullptr;
            }
        }
        
        m_Size = 0;
    }

    //--------------------------------------------------------------------------------
    // Accesses an element at the specified index.
    // Caller must guarantee the index is strictly less than Size().
    //
    // Parameters:
    //   Index - The zero-based index of the element to retrieve.
    //
    // Return:
    //   A mutable reference to the stored element.
    //--------------------------------------------------------------------------------
    __forceinline T& operator[](_In_ SIZE_T Index) noexcept
    {
        return m_Blocks[Index >> BlockShift][Index & BlockMask];
    }

    //--------------------------------------------------------------------------------
    // Accesses an element at the specified index (const).
    // Caller must guarantee the index is strictly less than Size().
    //
    // Parameters:
    //   Index - The zero-based index of the element to retrieve.
    //
    // Return:
    //   A constant reference to the stored element.
    //--------------------------------------------------------------------------------
    __forceinline const T& operator[](_In_ SIZE_T Index) const noexcept
    {
        return m_Blocks[Index >> BlockShift][Index & BlockMask];
    }

    //--------------------------------------------------------------------------------
    // Retrieves the current number of elements in the deque.
    //
    // Return:
    //   The total count of active elements currently stored.
    //--------------------------------------------------------------------------------
    SIZE_T Size() const noexcept
    {
        return m_Size;
    }

    //--------------------------------------------------------------------------------
    // Evaluates whether the deque currently contains zero elements.
    //
    // Return:
    //   True if the deque is empty, false otherwise.
    //--------------------------------------------------------------------------------
    bool IsEmpty() const noexcept
    {
        return m_Size == 0;
    }

private:
    // Maximum number of statically tracked blocks allowed in the deque.
    static constexpr SIZE_T kMaxBlocks = 256;

    T*     m_Blocks[kMaxBlocks]; // Array of pointers to the dynamically allocated memory blocks.       
    SIZE_T m_Size;               // The total number of active elements currently stored in the deque.
};
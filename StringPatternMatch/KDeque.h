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
class alignas(64) KDeque
{
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

public:
    //--------------------------------------------------------------------------------
    // Initializes an empty KDeque, zeroing out the block tracking array.
    //--------------------------------------------------------------------------------
    KDeque() noexcept : m_Size(0)
    {
        RtlZeroMemory(m_Blocks, sizeof(m_Blocks));
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
    NTSTATUS EmplaceBack(_In_ Args&&... arguments) noexcept
    {
        static_assert((BlockCapacity & (BlockCapacity - 1)) == 0, "BlockCapacity must be a power of 2.");
        static_assert(BlockCapacity <= (SIZE_MAX / sizeof(T)), "BlockCapacity exceeds size limits.");

        SIZE_T blockIndex = m_Size >> BlockShift;
        SIZE_T slotIndex  = m_Size & BlockMask;

        // Ensure we do not exceed the maximum number of statically tracked blocks.
        if (blockIndex >= kMaxBlocks) [[unlikely]]
        {
            return STATUS_QUOTA_EXCEEDED;
        }

        // Allocate a new block dynamically if the current block index is uninitialized.
        if (m_Blocks[blockIndex] == nullptr) [[unlikely]]
        {
            constexpr POOL_FLAGS allocFlags = PoolType | POOL_FLAG_UNINITIALIZED | POOL_FLAG_CACHE_ALIGNED;
            
            m_Blocks[blockIndex] = static_cast<T*>(ExAllocatePool2(allocFlags, BlockCapacity * sizeof(T), PoolTag));
            
            if (m_Blocks[blockIndex] == nullptr) [[unlikely]]
            {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }

        // Locate the exact slot within the block and construct the object.
        T* pSlot = &m_Blocks[blockIndex][slotIndex];
        new (pSlot) T(kstd::forward<Args>(arguments)...);
        m_Size++;

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
    // Clears all elements, invoking destructors if necessary, and frees underlying 
    // memory blocks.
    //--------------------------------------------------------------------------------
    void Clear() noexcept
    {
        // Explicitly invoke destructors for complex types.
        if constexpr (!kstd::is_trivially_destructible_v<T>)
        {
            for (SIZE_T i = 0; i < m_Size; i++)
            {
                m_Blocks[i >> BlockShift][i & BlockMask].~T();
            }
        }

        // Free all allocated memory blocks and reset pointers.
        for (SIZE_T i = 0; i < kMaxBlocks; i++)
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
    T& operator[](_In_ SIZE_T Index) noexcept
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
    const T& operator[](_In_ SIZE_T Index) const noexcept
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

private:
    // Maximum number of statically tracked blocks allowed in the deque.
    static constexpr SIZE_T kMaxBlocks = 256;

    T*     m_Blocks[kMaxBlocks]; // Array of pointers to the dynamically allocated memory blocks.       
    SIZE_T m_Size;               // The total number of active elements currently stored in the deque.
};
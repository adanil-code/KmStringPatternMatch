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
// KVector is a resizable, contiguous array that implements Small Vector 
// Optimization (SVO). It embeds a pre-sized inline byte buffer directly within 
// the object's local footprint. If the vector capacity stays within 'SvoCapacity',
// no dynamic kernel memory allocation occurs, saving CPU cycles and preventing 
// fragmentation. It dynamically spills over to the ExAllocate pool architecture 
// only when the inline limits are exceeded.
//
// Template Parameters:
//   T        - The type of elements to store.
//   PoolType - The NT kernel pool flags used for dynamic array allocations.
//   PoolTag  - The 4-byte tag used for kernel memory tracking.
//--------------------------------------------------------------------------------
template <typename T, POOL_FLAGS PoolType = POOL_FLAG_NON_PAGED, ULONG PoolTag = 'ceVK'>
class alignas(64) KVector
{
private:
    //--------------------------------------------------------------------------------
    // Small Vector Optimization (SVO): Eliminates ExAllocatePool2 calls entirely for 
    // buckets containing 2 or fewer patterns (which covers many real-world hash map 
    // distributions).
    //--------------------------------------------------------------------------------
    static constexpr SIZE_T SvoCapacity = 2;

    T* m_First; // Pointer to the beginning of the actively used buffer (inline or dynamic).
    T* m_Last;  // Pointer to one past the last initialized element in the buffer.
    T* m_End;   // Pointer to the end of the allocated capacity.
    
    //--------------------------------------------------------------------------------
    // Inline buffer residing directly inside the class/map bucket to prevent cache 
    // misses.
    //--------------------------------------------------------------------------------
    alignas(T) UCHAR m_InlineBuffer[SvoCapacity * sizeof(T)];

    //--------------------------------------------------------------------------------
    // Evaluates whether the vector is currently using dynamic kernel pool memory.
    //
    // Return:
    //   True if the vector relies on external heap tracking rather than inline SVO.
    //--------------------------------------------------------------------------------
    inline bool IsDynamic() const noexcept
    {
        return m_First != reinterpret_cast<const T*>(m_InlineBuffer);
    }

public:    
    //--------------------------------------------------------------------------------
    // Default constructor configuring the initial parameters against SVO storage limits.
    //--------------------------------------------------------------------------------
    KVector() noexcept
    {
        m_First = reinterpret_cast<T*>(m_InlineBuffer);
        m_Last  = m_First;
        m_End   = m_First + SvoCapacity;
    }
    
    KVector(const KVector& Other) = delete;    
    KVector& operator=(const KVector& Other) = delete;

    //--------------------------------------------------------------------------------
    // Explicit cloning implementation enforcing strict NTSTATUS lifecycle evaluation.
    //
    // Parameters:
    //   pOutVector - Target output pointer location that will house the mirrored data.
    //
    // Return:
    //   STATUS_SUCCESS upon identical state execution or an allocation failure flag.
    //--------------------------------------------------------------------------------
    NTSTATUS Clone(_Out_ KVector* __restrict pOutVector) const noexcept
    {
        if (pOutVector == nullptr) [[unlikely]]
        {
            return STATUS_INVALID_PARAMETER;
        }

        pOutVector->Clear();
        SIZE_T currentSize = Size();
        
        if (currentSize > 0) [[likely]]
        {
            NTSTATUS status = pOutVector->Reserve(currentSize);
            
            if (!NT_SUCCESS(status)) [[unlikely]]
            {
                return status;
            }

            if constexpr (kstd::is_trivially_copyable_v<T>)
            {
                RtlCopyMemory(pOutVector->m_First, m_First, currentSize * sizeof(T));
            }
            else
            {
                for (SIZE_T i = 0; i < currentSize; i++)
                {
                    new (&pOutVector->m_First[i]) T(m_First[i]);
                }
            }
            
            pOutVector->m_Last = pOutVector->m_First + currentSize;
        }
        
        return STATUS_SUCCESS;
    }

    //--------------------------------------------------------------------------------
    // Move Constructor - Safely handles transitions between inline and dynamic 
    // buffers without performing unnecessary structural deep copies.
    //
    // Parameters:
    //   Other - Object supplying transfer characteristics for consumption.
    //--------------------------------------------------------------------------------
    KVector(KVector&& Other) noexcept
    {
        if (Other.IsDynamic())
        {
            // Take ownership of the dynamically allocated memory
            m_First = Other.m_First;
            m_Last  = Other.m_Last;
            m_End   = Other.m_End;
        }
        else
        {
            // Move items locally into this object's inline buffer
            m_First = reinterpret_cast<T*>(m_InlineBuffer);
            m_Last  = m_First;
            m_End   = m_First + SvoCapacity;
            
            SIZE_T otherSize = Other.Size();
            if constexpr (kstd::is_trivially_copyable_v<T>)
            {
                RtlCopyMemory(m_First, Other.m_First, otherSize * sizeof(T));
            }
            else
            {
                for (SIZE_T i = 0; i < otherSize; i++)
                {
                    new (&m_First[i]) T(kstd::move(Other.m_First[i]));
                    Other.m_First[i].~T();
                }
            }

            m_Last = m_First + otherSize;
        }

        Other.m_First = reinterpret_cast<T*>(Other.m_InlineBuffer);
        Other.m_Last  = Other.m_First;
        Other.m_End   = Other.m_First + SvoCapacity;
    }

    //--------------------------------------------------------------------------------
    // Move Assignment Operator implementing memory transfers without deep copies.
    //
    // Parameters:
    //   Other - Supplying evaluation target for structural transitions.
    //
    // Return:
    //   Mutable reference resolving self operation.
    //--------------------------------------------------------------------------------
    KVector& operator=(KVector&& Other) noexcept
    {
        if (this != &Other)
        {
            Clear();
            
            if (IsDynamic() && m_First != nullptr)
            {
                ExFreePoolWithTag(m_First, PoolTag);
            }
            
            if (Other.IsDynamic())
            {
                m_First = Other.m_First;
                m_Last  = Other.m_Last;
                m_End   = Other.m_End;
            }
            else
            {
                m_First = reinterpret_cast<T*>(m_InlineBuffer);
                m_Last  = m_First;
                m_End   = m_First + SvoCapacity;
                
                SIZE_T otherSize = Other.Size();
                if constexpr (kstd::is_trivially_copyable_v<T>)
                {
                    RtlCopyMemory(m_First, Other.m_First, otherSize * sizeof(T));
                }
                else
                {
                    for (SIZE_T i = 0; i < otherSize; i++)
                    {
                        new (&m_First[i]) T(kstd::move(Other.m_First[i]));
                        Other.m_First[i].~T();
                    }
                }

                m_Last = m_First + otherSize;
            }

            Other.m_First = reinterpret_cast<T*>(Other.m_InlineBuffer);
            Other.m_Last  = Other.m_First;
            Other.m_End   = Other.m_First + SvoCapacity;
        }
        
        return *this;
    }

    //--------------------------------------------------------------------------------
    // Destroys all elements and frees any dynamically allocated memory ensuring
    // resource parity closure.
    //--------------------------------------------------------------------------------
    ~KVector() noexcept
    {
        Clear();
        
        if (IsDynamic() && m_First != nullptr)
        {
            ExFreePoolWithTag(m_First, PoolTag);
        }
    }

    //--------------------------------------------------------------------------------
    // Expands storage backing, moving values to a new dynamic allocation if needed.
    // Marked noinline to prevent bloat at invocation sites.
    //
    // Parameters:
    //   NewCapacity - Guaranteed bounds requirement dictating allocation sizing.
    //
    // Return:
    //   STATUS_SUCCESS or appropriate NTSTATUS upon resource fault or overflow limit.
    //--------------------------------------------------------------------------------
    __declspec(noinline) NTSTATUS Reserve(_In_ SIZE_T NewCapacity) noexcept
    {
        SIZE_T currentCap = static_cast<SIZE_T>(m_End - m_First);
        if (NewCapacity <= currentCap)
        {
            return STATUS_SUCCESS;
        }

        SIZE_T allocationSize = 0;
        if (!NT_SUCCESS(RtlSizeTMult(NewCapacity, sizeof(T), &allocationSize))) [[unlikely]]
        {
            return STATUS_INTEGER_OVERFLOW;
        }

        constexpr POOL_FLAGS allocFlags = PoolType | POOL_FLAG_UNINITIALIZED | POOL_FLAG_CACHE_ALIGNED;
        T* __restrict pNewData = static_cast<T*>(ExAllocatePool2(allocFlags, allocationSize, PoolTag));
        
        if (pNewData == nullptr) [[unlikely]]
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T currentSize = static_cast<SIZE_T>(m_Last - m_First);

        // Migrate current elements into the newly allocated block
        if (currentSize > 0)
        {
            if constexpr (kstd::is_trivially_copyable_v<T>)
            {
                RtlCopyMemory(pNewData, m_First, currentSize * sizeof(T));
            }
            else
            {
                for (SIZE_T i = 0; i < currentSize; i++)
                {
                    new (&pNewData[i]) T(kstd::move(m_First[i]));
                    m_First[i].~T();
                }
            }
        }

        // Only free memory if we were utilizing the dynamic pool, protecting SVO stack boundary
        if (IsDynamic() && m_First != nullptr)
        {
            ExFreePoolWithTag(m_First, PoolTag);
        }

        m_First = pNewData;
        m_Last  = pNewData + currentSize;
        m_End   = pNewData + NewCapacity;
        
        return STATUS_SUCCESS;
    }

    //--------------------------------------------------------------------------------
    // Constructs a new element in-place at the rear of the vector, scaling if maxed.
    //
    // Parameters:
    //   arguments - Variadic parameters directly fed into the value's constructor.
    //
    // Return:
    //   STATUS_SUCCESS or NTSTATUS code resolving potential ExAllocate limits.
    //--------------------------------------------------------------------------------
    template <typename... Args>
    NTSTATUS EmplaceBack(_In_ Args&&... arguments) noexcept
    {
        if (m_Last < m_End) [[likely]]
        {
            new (m_Last) T(kstd::forward<Args>(arguments)...);
            m_Last++;
            return STATUS_SUCCESS;
        }

        return GrowAndEmplace(kstd::forward<Args>(arguments)...);
    }

    //--------------------------------------------------------------------------------
    // Appends a single value to the end of the vector (lvalue overload).
    // Direct pointer dereference eliminates complex base+index scaling calculations.
    //
    // Parameters:
    //   Value - Readonly element reference providing data copies to the container.
    //
    // Return:
    //   STATUS_SUCCESS or pool failure code limit hit.
    //--------------------------------------------------------------------------------
    NTSTATUS PushBack(_In_ const T& Value) noexcept
    {
        if (m_Last < m_End) [[likely]]
        {
            if constexpr (kstd::is_trivially_copyable_v<T>)
            {
                *m_Last = Value;
            }
            else
            {
                new (m_Last) T(Value);
            }

            m_Last++;
            return STATUS_SUCCESS;
        }

        return GrowAndPush(Value);
    }

    //--------------------------------------------------------------------------------
    // Appends a single value to the end of the vector (rvalue overload).
    //
    // Parameters:
    //   Value - Mutable container subject resolving zero-copy state data evaluation.
    //
    // Return:
    //   STATUS_SUCCESS or NTSTATUS failure constraint limits.
    //--------------------------------------------------------------------------------
    NTSTATUS PushBack(_In_ T&& Value) noexcept
    {
        if (m_Last < m_End) [[likely]]
        {
            if constexpr (kstd::is_trivially_copyable_v<T>)
            {
                *m_Last = Value;
            }
            else
            {
                new (m_Last) T(kstd::move(Value));
            }

            m_Last++;
            return STATUS_SUCCESS;
        }

        return GrowAndPush(kstd::move(Value));
    }

    //--------------------------------------------------------------------------------
    // Injects a value into a given position, shifting sequential elements right.
    //
    // Parameters:
    //   Position - Relative mapped evaluation cursor inside vector buffer logic limit.
    //   Value    - Fixed data component written to sequential execution blocks.
    //
    // Return:
    //   STATUS_SUCCESS on operational validation or resource scaling limits.
    //--------------------------------------------------------------------------------
    NTSTATUS Insert(_In_       T* Position,
                    _In_ const T& Value) noexcept
    {
        SIZE_T index      = Position - m_First;
        T      localValue = Value;

        if (m_Last >= m_End) [[unlikely]]
        {
            NTSTATUS status = Grow();
            
            if (!NT_SUCCESS(status)) [[unlikely]]
            {
                return status;
            }
        }

        SIZE_T currentSize = static_cast<SIZE_T>(m_Last - m_First);

        if constexpr (kstd::is_trivially_copyable_v<T>)
        {
            if (currentSize > index)
            {
                RtlMoveMemory(&m_First[index + 1], &m_First[index], (currentSize - index) * sizeof(T));
            }
        }
        else
        {
            for (SIZE_T i = currentSize; i > index; i--)
            {
                if (i == currentSize)
                {
                    new (&m_First[i]) T(kstd::move(m_First[i - 1]));
                }
                else
                {
                    m_First[i] = kstd::move(m_First[i - 1]);
                }
            }
        }

        if (index == currentSize)
        {
            new (&m_First[index]) T(kstd::move(localValue));
        }
        else
        {
            m_First[index] = kstd::move(localValue);
        }

        m_Last++;
        return STATUS_SUCCESS;
    }

    //--------------------------------------------------------------------------------
    // Empties the container, calling element destructors without releasing pool 
    // capacity.
    //--------------------------------------------------------------------------------
    void Clear() noexcept
    {
        if constexpr (!kstd::is_trivially_destructible_v<T>)
        {
            for (T* p = m_First; p != m_Last; ++p)
            {
                p->~T();
            }
        }
        
        m_Last = m_First;
    }

    //--------------------------------------------------------------------------------
    // Accesses an element natively directly bounded sequentially at position Index.
    //
    // Parameters:
    //   Index - Direct relative zero-offset bounds constraint marker.
    //
    // Return:
    //   Mutable item matching standard array behaviors.
    //--------------------------------------------------------------------------------
    T& operator[](_In_ SIZE_T Index) noexcept
    {
        return m_First[Index];
    }

    //--------------------------------------------------------------------------------
    // Constants read wrapper tracking vector capacity sequential block bounds.
    //
    // Parameters:
    //   Index - Direct relative zero-offset bounds constraint marker.
    //
    // Return:
    //   Readonly evaluation reference matching array limits.
    //--------------------------------------------------------------------------------
    const T& operator[](_In_ SIZE_T Index) const noexcept
    {
        return m_First[Index];
    }

    //--------------------------------------------------------------------------------
    // Accessor navigating immediately bounding elements inside current size index limits.
    // Caller must evaluate for zero sizes.
    //
    // Return:
    //   Mutable element representation mapped at container terminal bounds.
    //--------------------------------------------------------------------------------
    T& Back() noexcept
    {
        return *(m_Last - 1);
    }

    //--------------------------------------------------------------------------------
    // Enumerates actively allocated instance lengths rather than true overall memory 
    // capacity limits tracking bytes parameters constraints.
    //
    // Return:
    //   Number of populated instance counts in array blocks.
    //--------------------------------------------------------------------------------
    SIZE_T Size() const noexcept
    {
        return static_cast<SIZE_T>(m_Last - m_First);
    }

    //--------------------------------------------------------------------------------
    // Quick limits state query returning boolean operation limit bounds conditions.
    //
    // Return:
    //   True if empty.
    //--------------------------------------------------------------------------------
    bool IsEmpty() const noexcept
    {
        return m_First == m_Last;
    }
    
    //--------------------------------------------------------------------------------
    // Pointer marker mapping relative 0 parameter bound values targeting iterator calls.
    //
    // Return:
    //   Mutable front object block reference limits bound value parameter.
    //--------------------------------------------------------------------------------
    T* begin() noexcept
    {
        return m_First;
    }

    //--------------------------------------------------------------------------------
    // Terminal constraint bound limits navigating standard pointer tracking size.
    //
    // Return:
    //   Mutable terminus block bounds.
    //--------------------------------------------------------------------------------
    T* end() noexcept
    {
        return m_Last;
    }

    //--------------------------------------------------------------------------------
    // Evaluated constant pointer tracking offset 0 iterator bounds.
    //
    // Return:
    //   Constants constraint limits front tracking component bounds.
    //--------------------------------------------------------------------------------
    const T* begin() const noexcept
    {
        return m_First;
    }

    //--------------------------------------------------------------------------------
    // Evaluated array bounds tracking object marker endpoint pointer values.
    //
    // Return:
    //   Constants constraint terminal boundary tracking block parameter.
    //--------------------------------------------------------------------------------
    const T* end() const noexcept
    {
        return m_Last;
    }

private:
    //--------------------------------------------------------------------------------
    // Triggers a 1.5x/2x allocation growth curve when capacity is exhausted.
    // Marked noinline to keep the primary container mutation functions lean.
    //
    // Return:
    //   STATUS_SUCCESS or pool failure execution limits.
    //--------------------------------------------------------------------------------
    __declspec(noinline) NTSTATUS Grow() noexcept
    {
        SIZE_T capacity = static_cast<SIZE_T>(m_End - m_First);
        SIZE_T newCapacity = 0;

        if (capacity == 0) [[unlikely]]
        {
            newCapacity = 8;
        }
        else if (capacity < 1024)
        {
            if (!NT_SUCCESS(RtlSizeTMult(capacity, 2, &newCapacity))) [[unlikely]]
            {
                return STATUS_INTEGER_OVERFLOW;
            }
        }
        else
        {
            SIZE_T halfCapacity = capacity >> 1;
            
            if (!NT_SUCCESS(RtlSizeTAdd(capacity, halfCapacity, &newCapacity))) [[unlikely]]
            {
                return STATUS_INTEGER_OVERFLOW;
            }
        }

        return Reserve(newCapacity);
    }

    //--------------------------------------------------------------------------------
    // Out-of-line slow paths for vector reallocation. Keeps PushBack and EmplaceBack
    // leaf-like on the critical path, enabling aggressive compiler loop unrolling.
    //
    // Parameters:
    //   Value - The constant reference to the value being appended to the newly 
    //           allocated vector.
    //
    // Return:
    //   STATUS_SUCCESS upon successful reallocation and insertion, or an NTSTATUS 
    //   error code.
    //--------------------------------------------------------------------------------
    __declspec(noinline) NTSTATUS GrowAndPush(_In_ const T& Value) noexcept
    {
        NTSTATUS status = Grow();
        if (!NT_SUCCESS(status)) [[unlikely]]
        {
            return status;
        }

        if constexpr (kstd::is_trivially_copyable_v<T>)
        {
            *m_Last = Value;
        }
        else
        {
            new (m_Last) T(Value);
        }

        m_Last++;
        return STATUS_SUCCESS;
    }

    //--------------------------------------------------------------------------------
    // Out-of-line slow path for vector reallocation via rvalue reference.
    // Keeps PushBack leaf-like on the critical path while supporting move semantics.
    //
    // Parameters:
    //   Value - The mutable rvalue reference to the value being moved into the newly
    //           allocated vector.
    //
    // Return:
    //   STATUS_SUCCESS upon successful reallocation and insertion, or an NTSTATUS 
    //   error code.
    //--------------------------------------------------------------------------------
    __declspec(noinline) NTSTATUS GrowAndPush(_In_ T&& Value) noexcept
    {
        NTSTATUS status = Grow();
        if (!NT_SUCCESS(status)) [[unlikely]]
        {
            return status;
        }

        if constexpr (kstd::is_trivially_copyable_v<T>)
        {
            *m_Last = Value;
        }
        else
        {
            new (m_Last) T(kstd::move(Value));
        }

        m_Last++;
        return STATUS_SUCCESS;
    }

    //--------------------------------------------------------------------------------
    // Out-of-line slow path for vector reallocation via in-place construction.
    // Keeps EmplaceBack leaf-like on the critical path while supporting forwarding.
    //
    // Parameters:
    //   arguments - Variadic template arguments forwarded to the element's constructor.
    //
    // Return:
    //   STATUS_SUCCESS upon successful reallocation and construction, or an NTSTATUS 
    //   error code.
    //--------------------------------------------------------------------------------
    template <typename... Args>
    __declspec(noinline) NTSTATUS GrowAndEmplace(_In_ Args&&... arguments) noexcept
    {
        NTSTATUS status = Grow();
        if (!NT_SUCCESS(status)) [[unlikely]]
        {
            return status;
        }

        new (m_Last) T(kstd::forward<Args>(arguments)...);
        m_Last++;
        return STATUS_SUCCESS;
    }
};
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

#if defined(_KERNEL_MODE)

#if !defined KERNEL_PLACEMENT_NEW_DEFINED
#define KERNEL_PLACEMENT_NEW_DEFINED

//--------------------------------------------------------------------------------
// Defines the alignment type parameter used by kernel-mode placement operators.
//--------------------------------------------------------------------------------
namespace std
{
    enum class align_val_t : SIZE_T {};
}

#pragma warning(push)
#pragma warning(disable: 4595)

//--------------------------------------------------------------------------------
// Standard placement new operator for kernel mode. 
// Allows constructing an object at a specifically pre-allocated memory address.
//
// Parameters:
//   Size   - The size tracking requirement boundary constraints.
//   _Where - The memory target allocated pointer buffer destination block.
//
// Return:
//   The unwrapped destination target reference.
//--------------------------------------------------------------------------------
inline void* __cdecl operator new(_In_ SIZE_T Size,
                                  _In_ void*  _Where) noexcept
{
    UNREFERENCED_PARAMETER(Size);
    return _Where;
}

//--------------------------------------------------------------------------------
// Corresponding placement delete operators to satisfy the compiler if a placement 
// new operation fails and needs to roll back. These are intentionally no-ops 
// because placement new does not allocate memory itself.
//
// Parameters:
//   Ptr   - Reference target constraint operator base block.
//   Place - Corresponding bounds mapping execution limits parameters context block.
//--------------------------------------------------------------------------------
inline void __cdecl operator delete(_In_     void* Ptr,
                                    _In_opt_ void* Place) noexcept
{
    UNREFERENCED_PARAMETER(Ptr);
    UNREFERENCED_PARAMETER(Place);
}

//--------------------------------------------------------------------------------
// Baseline delete operations nullifying execution without allocation blocks 
// constraints.
//
// Parameters:
//   Ptr - The target context bounds parameter limits base target.
//--------------------------------------------------------------------------------
inline void __cdecl operator delete(_In_ void* Ptr) noexcept
{
    UNREFERENCED_PARAMETER(Ptr);
}

//--------------------------------------------------------------------------------
// Delete bounds sizing constraint evaluating runtime parameter length offset 
// target blocks.
//
// Parameters:
//   Ptr  - Execution destination variable reference pointer constraint marker.
//   Size - Constant limit sizing execution limits variable.
//--------------------------------------------------------------------------------
inline void __cdecl operator delete(_In_ void*  Ptr,
                                    _In_ SIZE_T Size) noexcept
{
    UNREFERENCED_PARAMETER(Ptr);
    UNREFERENCED_PARAMETER(Size);
}

//--------------------------------------------------------------------------------
// Overloaded delete accommodating custom kernel space execution struct alignment 
// limits.
//
// Parameters:
//   Ptr       - Pointer limit sizing variable constraints limit context block.
//   Alignment - Required mapping values matching limits boundary parameter 
//               constants.
//--------------------------------------------------------------------------------
inline void __cdecl operator delete(_In_ void*            Ptr,
                                    _In_ std::align_val_t Alignment) noexcept
{
    UNREFERENCED_PARAMETER(Ptr);
    UNREFERENCED_PARAMETER(Alignment);
}

//--------------------------------------------------------------------------------
// Extended delete targeting constraints boundaries overloads handling exact length 
// sizes blocks evaluation marker alignments limits bounds context limits parameter
// values.
//
// Parameters:
//   Ptr       - Tracking length target marker constraint bound value offset sizing
//               constraints limits reference marker block.
//   Size      - Offset length tracking limits bounds marker component limits 
//               lengths constraint variable constraint block sizing variable 
//               constraint limit values variable tracking component limits 
//               constraint limits sizes limits blocks execution constraints offset
//               limits blocks limits parameter execution variable offset sizing 
//               variable offset bounds marker value reference.
//   Alignment - Bounds offset sizing parameter variables constraints block 
//               constraint limits reference marker limits bounds reference 
//               limits sizes bounds.
//--------------------------------------------------------------------------------
inline void __cdecl operator delete(_In_ void*            Ptr,
                                    _In_ SIZE_T           Size,
                                    _In_ std::align_val_t Alignment) noexcept
{
    UNREFERENCED_PARAMETER(Ptr);
    UNREFERENCED_PARAMETER(Size);
    UNREFERENCED_PARAMETER(Alignment);
}

#pragma warning(pop)
#endif // KERNEL_PLACEMENT_NEW_DEFINED

#else // User-Mode Test Compilation Fallback
#include <new> 
#endif

//--------------------------------------------------------------------------------
// Architecture-safe prefetch routing avoids XMM headers.
// Hints the CPU to fetch cache lines ahead of execution to reduce memory latency.
//--------------------------------------------------------------------------------
#if defined(_M_X64) || defined(_M_IX86)
#define K_PREFETCH(ptr) _mm_prefetch(reinterpret_cast<const char*>(ptr), 1 /*_MM_HINT_T0*/)
#elif defined(_M_ARM64)
#define K_PREFETCH(ptr) __prefetch(ptr)
#else
#define K_PREFETCH(ptr)
#endif

#ifndef KERNEL_TYPE_TRAITS_DEFINED
#define KERNEL_TYPE_TRAITS_DEFINED
namespace kstd
{
    //--------------------------------------------------------------------------------
    // Strips reference qualifiers from a type to reveal its base type.
    //--------------------------------------------------------------------------------
    template <typename T>
    struct remove_reference
    {
        using type = T;
    };

    template <typename T>
    struct remove_reference<T&>
    {
        using type = T;
    };

    template <typename T>
    struct remove_reference<T&&>
    {
        using type = T;
    };

    template <typename T>
    using remove_reference_t = typename remove_reference<T>::type;

    //--------------------------------------------------------------------------------
    // Casts a value to an rvalue reference, enabling move semantics.
    //
    // Parameters:
    //   arg - Mutable parameter value resolving standard value context assignment 
    //         offset.
    //
    // Return:
    //   A casted parameter resolving rvalue tracking parameter contexts markers 
    //   targets block lengths block mapping parameter block marker.
    //--------------------------------------------------------------------------------
    template <typename T>
    constexpr remove_reference_t<T>&& move(_Inout_ T&& arg) noexcept
    {
        return static_cast<remove_reference_t<T>&&>(arg);
    }

    //--------------------------------------------------------------------------------
    // Forwards an lvalue as either an lvalue or rvalue depending on its original type.
    //
    // Parameters:
    //   arg - Reference constraints variable markers parameter boundaries constraint 
    //         variables sizes length markers limits target pointer limits constraint 
    //         block offset context target variables limit sizing limits variable 
    //         variables.
    //
    // Return:
    //   A cast parameter context limit constraint length mapping mapping limit 
    //   mapping sizing context marker block marker.
    //--------------------------------------------------------------------------------
    template <typename T>
    constexpr T&& forward(_Inout_ remove_reference_t<T>& arg) noexcept
    {
        return static_cast<T&&>(arg);
    }

    //--------------------------------------------------------------------------------
    // Forwards an rvalue as an rvalue.
    //
    // Parameters:
    //   arg - Constraints target bounds variable boundaries constraint context length
    //         offset block mapping target constraint offset constraint mapping offset 
    //         parameters sizing marker block constraint sizing constraint parameters 
    //         sizing bounds block bounds bounds variables parameter constraints offset
    //         length tracking limits values mapping limits context.
    //
    // Return:
    //   Forwarded mapped context boundary constraint offset limit length limits
    //   mapping target values mapping boundaries limits variable constraint mapping 
    //   parameter offset block mapping sizing bounds target bounds constraint value 
    //   sizing target boundaries marker constraints lengths boundaries length target
    //   block boundaries mapping variables constraint limit variables context.
    //--------------------------------------------------------------------------------
    template <typename T>
    constexpr T&& forward(_Inout_ remove_reference_t<T>&& arg) noexcept
    {
        return static_cast<T&&>(arg);
    }

    template <typename T>
    inline constexpr bool is_trivially_copyable_v = __is_trivially_copyable(T);

    template <typename T>
    inline constexpr bool is_trivially_destructible_v = __is_trivially_destructible(T);
}
#endif
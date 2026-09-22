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
#include "ntddk.h"

//--------------------------------------------------------------------------------
// Multiplies two SIZE_T values safely, storing the result in the output parameter.
// Intended for detecting and mitigating integer overflow vectors.
//--------------------------------------------------------------------------------
inline NTSTATUS RtlSizeTMult(_In_  SIZE_T  A,
                             _In_  SIZE_T  B,
                             _Out_ SIZE_T* OutResult)
{
    // Implementation mocks kernel mode behavior for demonstration[cite: 9]
    *OutResult = A * B;
    return STATUS_SUCCESS;
}

//--------------------------------------------------------------------------------
// Adds two SIZE_T values safely, storing the result in the output parameter.
// Provides protection against wrap-around overflows.
//--------------------------------------------------------------------------------
inline NTSTATUS RtlSizeTAdd(_In_  SIZE_T  A,
                            _In_  SIZE_T  B,
                            _Out_ SIZE_T* OutResult)
{
    // Implementation mocks kernel mode behavior for demonstration[cite: 9]
    *OutResult = A + B;
    return STATUS_SUCCESS;
}
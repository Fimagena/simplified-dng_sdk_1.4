/*
 *
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Functions for safe arithmetic (guarded against overflow) on integer types.

#ifndef __dng_safe_arithmetic__
#define __dng_safe_arithmetic__

#include <cstddef>
#include <cstdint>
#include <limits>

#include "dng_exceptions.h"

// If the result of adding arg1 and arg2 will fit in an int32_t (without
// under-/overflow), stores this result in *result and returns true. Otherwise,
// returns false and leaves *result unchanged.
bool SafeInt32Add(std::int32_t arg1, std::int32_t arg2, std::int32_t *result);

// Returns the result of adding arg1 and arg2 if it will fit in the result type
// (without under-/overflow). Otherwise, throws a dng_exception with error code
// dng_error_unknown.
std::int32_t SafeInt32Add(std::int32_t arg1, std::int32_t arg2);
std::int64_t SafeInt64Add(std::int64_t arg1, std::int64_t arg2);

// If the result of adding arg1 and arg2 will fit in a uint32_t (without
// wraparound), stores this result in *result and returns true. Otherwise,
// returns false and leaves *result unchanged.
bool SafeUint32Add(std::uint32_t arg1, std::uint32_t arg2,
                   std::uint32_t *result);

// Returns the result of adding arg1 and arg2 if it will fit in a uint32_t
// (without wraparound). Otherwise, throws a dng_exception with error code
// dng_error_unknown.
std::uint32_t SafeUint32Add(std::uint32_t arg1, std::uint32_t arg2);

// If the subtraction of arg2 from arg1 will not result in an int32_t under- or
// overflow, stores this result in *result and returns true. Otherwise,
// returns false and leaves *result unchanged.
bool SafeInt32Sub(std::int32_t arg1, std::int32_t arg2, std::int32_t *result);

// Returns the result of subtracting arg2 from arg1 if this operation will not
// result in an int32_t under- or overflow. Otherwise, throws a dng_exception
// with error code dng_error_unknown.
std::int32_t SafeInt32Sub(std::int32_t arg1, std::int32_t arg2);

// If the result of multiplying arg1, ..., argn will fit in a uint32_t (without
// wraparound), stores this result in *result and returns true. Otherwise,
// returns false and leaves *result unchanged.
bool SafeUint32Mult(std::uint32_t arg1, std::uint32_t arg2,
                    std::uint32_t *result);
bool SafeUint32Mult(std::uint32_t arg1, std::uint32_t arg2, std::uint32_t arg3,
                    std::uint32_t *result);
bool SafeUint32Mult(std::uint32_t arg1, std::uint32_t arg2, std::uint32_t arg3,
                    std::uint32_t arg4, std::uint32_t *result);

// Returns the result of multiplying arg1, ..., argn if it will fit in a
// uint32_t (without wraparound). Otherwise, throws a dng_exception with error
// code dng_error_unknown.
std::uint32_t SafeUint32Mult(std::uint32_t arg1, std::uint32_t arg2);
std::uint32_t SafeUint32Mult(std::uint32_t arg1, std::uint32_t arg2,
                             std::uint32_t arg3);
std::uint32_t SafeUint32Mult(std::uint32_t arg1, std::uint32_t arg2,
                             std::uint32_t arg3, std::uint32_t arg4);

// Returns the result of multiplying arg1 and arg2 if it will fit in a size_t
// (without overflow). Otherwise, throws a dng_exception with error code
// dng_error_unknown.
std::size_t SafeSizetMult(std::size_t arg1, std::size_t arg2);

// Returns the result of multiplying arg1 and arg2 if it will fit in an int64_t
// (without overflow). Otherwise, throws a dng_exception with error code
// dng_error_unknown.
std::int64_t SafeInt64Mult(std::int64_t arg1, std::int64_t arg2);

// Returns the result of dividing arg1 by arg2; if the result is not an integer,
// rounds up to the next integer. If arg2 is zero, throws a dng_exception with
// error code dng_error_unknown.
// The function is safe against wraparound and will return the correct result
// for all combinations of arg1 and arg2.
std::uint32_t SafeUint32DivideUp(std::uint32_t arg1, std::uint32_t arg2);

// Finds the smallest integer multiple of 'multiple_of' that is greater than or
// equal to 'val'. If this value will fit in a uint32_t, stores it in *result
// and returns true. Otherwise, or if 'multiple_of' is zero, returns false and
// leaves *result unchanged.
bool RoundUpUint32ToMultiple(std::uint32_t val, std::uint32_t multiple_of,
                             std::uint32_t *result);

// If the uint32_t value val will fit in a int32_t, converts it to a int32_t and
// stores it in *result. Otherwise, returns false and leaves *result unchanged.
bool ConvertUint32ToInt32(std::uint32_t val, std::int32_t *result);

// Converts a value of the unsigned integer type TSrc to the unsigned integer
// type TDest. If the value in 'src' cannot be converted to the type TDest
// without truncation, throws a dng_exception with error code dng_error_unknown.
//
// Note: Though this function is typically used where TDest is a narrower type
// than TSrc, it is designed to work also if TDest is wider than from TSrc or
// identical to TSrc. This is useful in situations where the width of the types
// involved can change depending on the architecture -- for example, the
// conversion from size_t to uint32_t may either be narrowing, identical or even
// widening (though the latter admittedly happens only on architectures that
// aren't relevant to us).
template <class TSrc, class TDest>
static void ConvertUnsigned(TSrc src, TDest *dest) {
  static_assert(std::numeric_limits<TSrc>::is_integer &&
                    !std::numeric_limits<TSrc>::is_signed &&
                    std::numeric_limits<TDest>::is_integer &&
                    !std::numeric_limits<TDest>::is_signed,
                "TSrc and TDest must be unsigned integer types");

  const TDest converted = static_cast<TDest>(src);

  // Convert back to TSrc to check whether truncation occurred in the
  // conversion to TDest.
  if (static_cast<TSrc>(converted) != src) {
    ThrowProgramError("Overflow in unsigned integer conversion");
  }

  *dest = converted;
}

#endif  // __dng_safe_arithmetic__

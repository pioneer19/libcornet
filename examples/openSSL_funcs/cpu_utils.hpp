/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 *
 * This file is part of libcornet.
 *
 *  libcornet is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  libcornet is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with libcornet.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <cstdint>

inline uint64_t rdtsc();
inline void cpu_pause(); ///< make cpu pause in spin loop

#if defined(__i386) || defined(__x86_64__) // gcc,clang
inline uint64_t rdtsc()
{
    uint32_t tickl, tickh;
    __asm__ __volatile__("rdtsc":"=a"(tickl),"=d"(tickh));
    return ( static_cast<uint64_t>(tickh) << 32) | tickl;
}
inline void cpu_pause()
{
    asm volatile( "pause" );
}

__inline__ uint64_t rdtscp( uint32_t & aux )
{
    uint64_t rax,rdx;
    __asm__ __volatile__ ( "rdtscp\n" : "=a" (rax), "=d" (rdx), "=c" (aux) );
    return (rdx << 32) + rax;
}
// only EAX used to specify CPUID leaf
__inline__ void cpuid( uint32_t& eax, uint32_t& ebx, uint32_t& ecx, uint32_t& edx )
{
  __asm__ __volatile__ ( "cpuid"
    : "+a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx) );
}
// EAX:ECX used to specify CPUID leaf:subleaf
__inline__ void cpuidx( uint32_t& eax, uint32_t& ebx, uint32_t& ecx, uint32_t& edx )
{
  __asm__ __volatile__ ( "cpuid"
    : "+a" (eax), "=b" (ebx), "+c" (ecx), "=d" (edx) );
}


__inline__ int cpu_id(void)
{
    uint32_t reg_ebx;

    __asm__ __volatile__ (
                " mov	$1, %%eax\n\t"
                " cpuid;\n\t"
                // get CPU APIC ID from EBX[31:24]
                : "=b" (reg_ebx)
                :
                : "eax", "ecx", "edx");
    return (reg_ebx>>24) & 0xFF;
}

__inline__ uint64_t rdpid(void)
{
    uint64_t core_id;

    __asm__ __volatile__ (
                " rdpid %0\n\t"
                : "=r" (core_id) );
    return core_id;
}

__inline__ uint32_t pu_id()
{
    uint32_t pu_id;
    __asm__ __volatile__ ( "rdtscp\n"
                           : "=c" (pu_id)
                           :
                           : "eax", "edx" );
    return pu_id;
}

inline void cpu_relax(void)
{
    asm volatile("rep; nop" ::: "memory");
}
#elif defined(_M_IX86) || defined(_M_X64) // MSVC
#include <intrin.h>
#pragma intrinsic(__rdtsc)

inline uint64_t rdtsc()
{
    return __rdtsc();
}
inline void cpu_pause()
{
    _mm_pause();
}
#endif

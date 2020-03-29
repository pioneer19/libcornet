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

// clang++-7 -O3 -Wall -Wextra -pedantic -march=native -mtune=native -o rdrand32bytes ./rdrand.cpp

#include <cstdio>
#include <cstdint>

#include <chrono>
#include <thread>
#include <array>
#include <algorithm>

inline uint64_t rdtsc()
{
    uint32_t tickl, tickh;
    __asm__ __volatile__("rdtsc":"=a"(tickl),"=d"(tickh));
    return ( static_cast<uint64_t>(tickh) << 32) | tickl;
}

void calibrate_tsc()
{
    printf( "tsc calibration\n" );

    auto chrono_begin = std::chrono::steady_clock::now();
    uint64_t begin_tsc = rdtsc();
    std::this_thread::sleep_for( std::chrono::milliseconds(100) );
    uint64_t end_tsc = rdtsc();
    auto chrono_end   = std::chrono::steady_clock::now();
    std::chrono::duration<double> diff = chrono_end - chrono_begin;

    auto ticks_per_second = static_cast<size_t>((end_tsc-begin_tsc)/diff.count());
    printf( "tsc per second %zd\n", ticks_per_second );
}

using Random = std::array<uint8_t,32>;

void copy_random( const Random& src, Random& dst ) noexcept
{
    dst = src;
}

void print_random( const Random& rnd ) noexcept
{
    printf( "rnd:" );
    for( auto el : rnd )
    {
        printf( " %02x", el );
    }
    printf( "\n" );
}

int main()
{
    calibrate_tsc();

    uint64_t begin_tsc, end_tsc;

    Random rnd;
    std::fill( rnd.data(), rnd.data()+rnd.size(), 0 );
    rnd[10] = 0x19;
    print_random( rnd );

    begin_tsc = rdtsc();
    for( size_t i = 0; i < rnd.size()/8; ++i )
        __builtin_ia32_rdrand64_step( reinterpret_cast<unsigned long long*>(rnd.data()+8*i) );
    end_tsc = rdtsc();
    printf( "rdrand64 for buffer got %ld ticks\n", end_tsc-begin_tsc );

    print_random( rnd );

    Random rnd_copy;
    std::fill( rnd_copy.data(), rnd_copy.data()+rnd_copy.size(), 0xA5 );

    begin_tsc = rdtsc();
    copy_random( rnd, rnd_copy );
    end_tsc = rdtsc();
    printf( "copy_random got %ld ticks\n", end_tsc-begin_tsc );
    print_random( rnd_copy );

    std::fill( rnd_copy.data(), rnd_copy.data()+rnd_copy.size(), 0x77 );

    begin_tsc = rdtsc();
    copy_random( rnd, rnd_copy );
    end_tsc = rdtsc();
    printf( "copy_random got %ld ticks\n", end_tsc-begin_tsc );
    print_random( rnd_copy );

    return 0;
}

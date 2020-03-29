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

#include <cstdint>

#include <random>
#include <algorithm>
#include <iostream>

constexpr uint32_t ARRAY_SIZE = 10*1024*1024;
constexpr uint32_t TEST_SIZE = 16;

inline uint64_t rdtsc()
{
    uint32_t tickl, tickh;
    __asm__ __volatile__("rdtsc":"=a"(tickl),"=d"(tickh));
    return ( static_cast<uint64_t>(tickh) << 32) | tickl;
}

void test_mem_write( uint64_t* big_array, const uint32_t* test_index_array )
{
    uint64_t tsc_begin = rdtsc();

    for( uint32_t i = 0; i < TEST_SIZE; ++i )
    {
        big_array[test_index_array[i]] = 0xAAFF77EE00101900;
    }
    uint64_t tsc_end = rdtsc();
    std::cout << "tsc\n" << tsc_begin << "\n" << tsc_end << "\n";
    std::cout << "test got " << tsc_end - tsc_begin << " clocks\n";
}

int main()
{
    auto big_array = new uint64_t[ARRAY_SIZE];
    std::fill( big_array, big_array+ARRAY_SIZE, 0 );

    auto test_index_array = new uint32_t[TEST_SIZE];

    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<uint32_t> uni( 0, ARRAY_SIZE-1 );

    for( uint32_t i = 0; i < TEST_SIZE; ++i )
        test_index_array[i] = uni(rng);

    for( uint32_t i = 0; i < TEST_SIZE; ++i )
        std::cout << test_index_array[i] << " ";
    std::cout << "\n";

    test_mem_write( big_array, test_index_array );

    return 0;
}

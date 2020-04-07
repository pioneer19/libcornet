/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#include <cstdint>
#include <cstdio>
#include <numeric>

#include <libcornet/cache_allocator.hpp>
using pioneer19::CacheAllocator;

void benchmark_new( size_t block_size );
void benchmark_malloc( size_t block_size );
void benchmark_swap_static( size_t block_size );
void benchmark_cache_allocator20k();

inline uint64_t rdtsc()
{
    uint32_t tickl, tickh;
    __asm__ __volatile__("rdtsc":"=a"(tickl),"=d"(tickh));
    return ( static_cast<uint64_t>(tickh) << 32u) | tickl;
}

void fill_random_bytes( uint8_t* buffer, uint32_t buffer_size )
{
    for( size_t i = 0; i < buffer_size/8; ++i )
        __builtin_ia32_rdrand64_step( reinterpret_cast<unsigned long long*>(buffer+8*i) );
}

int main()
{
    printf( "Benchmarking different memory allocation schemas: new, malloc"
            ", swap with static preallocated cache\n" );
    uint64_t tsc_begin=0, tsc_end=0;

    tsc_begin = rdtsc();
    tsc_end   = rdtsc();
    printf( "empty rdtsc got %ld clocks\n", tsc_end - tsc_begin );
    // ===
    benchmark_new( 4096 );
    benchmark_new( 4096 );
    benchmark_new( 16*1024 );
    benchmark_new( 16*1024 );
    benchmark_new( 20*1024 );
    benchmark_new( 20*1024 );
    // ===
    benchmark_malloc( 4096 );
    benchmark_malloc( 4096 );
    benchmark_malloc( 16*1024 );
    benchmark_malloc( 16*1024 );
    benchmark_malloc( 20*1024 );
    benchmark_malloc( 20*1024 );
    // ===
    benchmark_swap_static( 20*1024 );
    benchmark_swap_static( 20*1024 );
    benchmark_swap_static( 20*1024 );
    // ===
    benchmark_cache_allocator20k();
    benchmark_cache_allocator20k();
    benchmark_cache_allocator20k();
    // ===

    return 0;
}

void benchmark_new( size_t block_size )
{
    uint64_t tsc_begin=0, tsc_end=0;
    tsc_begin = rdtsc();
    auto* data = new uint8_t[block_size];
    tsc_end   = rdtsc();
    fill_random_bytes( data, block_size );
    printf( "new %ld bytes got %ld clocks (random sum %d)\n"
            , block_size, tsc_end - tsc_begin, std::accumulate(data,data+block_size,0) );

    delete [] data;
}

void benchmark_malloc( size_t block_size )
{
    uint64_t tsc_begin=0, tsc_end=0;
    tsc_begin = rdtsc();
    auto* data = (uint8_t*)::malloc( block_size );
    tsc_end   = rdtsc();
    fill_random_bytes( data, block_size );
    printf( "malloc %ld bytes got %ld clocks (random sum %d)\n"
            , block_size, tsc_end - tsc_begin, std::accumulate(data,data+block_size,0) );

    free( data );
}

uint8_t* static_data = nullptr;

void benchmark_swap_static( size_t block_size )
{
    uint64_t tsc_begin=0, tsc_end=0;
    tsc_begin = rdtsc();
    uint8_t* data = nullptr;
    std::swap( data, static_data );
    if( data == nullptr )
        data = (uint8_t*)::malloc( block_size );
    tsc_end   = rdtsc();
    fill_random_bytes( data, block_size );
    printf( "swap_static %ld bytes got %ld clocks (random sum %d)\n"
            , block_size, tsc_end - tsc_begin, std::accumulate(data,data+block_size,0) );

    std::swap( data, static_data );
    if( data )
        free( data );
}

void benchmark_cache_allocator20k()
{
    static constexpr size_t BLOCK_SIZE = 20*1024;

    uint64_t tsc_begin=0, tsc_end=0;
    // allocate memory
    tsc_begin = rdtsc();
    auto* data = (uint8_t*)CacheAllocator<BLOCK_SIZE>::malloc();
    tsc_end   = rdtsc();

    fill_random_bytes( data, BLOCK_SIZE );
    printf( "cache_allocator20k %ld bytes got %ld clocks (random sum %d)\n"
            , BLOCK_SIZE, tsc_end - tsc_begin, std::accumulate(data,data+BLOCK_SIZE,0) );
    // free memory
    CacheAllocator<BLOCK_SIZE>::free( data );
}

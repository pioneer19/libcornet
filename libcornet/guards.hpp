/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#pragma once

#include <atomic>
#include <exception>
#include <utility>

namespace pioneer19::guards
{

template <typename T>
struct ScopeGuard
{
    ScopeGuard( T code )
        :code( code )
        ,own( true )
    {}
    ScopeGuard( ScopeGuard&& other )
        :code( other.code )
        ,own( true )
    { other.own = false; }
    ScopeGuard& operator=( ScopeGuard&& other ) = delete;
//    {
//        if( &other != this )
//        {
//            code = std::move( other.code );
//            own = true;
//            other.own = false;
//        }
//        return *this;
//    }
    ~ScopeGuard() { if( own ) code(); }

    ScopeGuard( const ScopeGuard& ) = delete;
    ScopeGuard& operator=( const ScopeGuard& ) = delete;

    void release() { own = false; }
    void acquire() { own = true; }
    void run_now() { if( own ) code(); own = false; }
    T code;
    bool own;
};
/**
 * run code on scope exit
 * @code{.cpp}
 * auto mmap_guard = make_scope_guard(
                [=](){ ::close( fd ); } );
 * @endcode
 */
template <typename T>
ScopeGuard<T> make_scope_guard( T code )
{
    return ScopeGuard<T>( code );
}

template <typename T>
struct OnExceptionGuard
{
    OnExceptionGuard( T code )
        :code( code )
    {}
    ~OnExceptionGuard()
    {
        if ( std::uncaught_exceptions() > 0 )
            code();
    }
    T code;
};
/**
 * run code if exception thrown
 * @code{.cpp}
 * auto mmap_guard = make_on_exception_guard(
                [=](){ ::close( fd ); } );
 * @endcode
 */
template <typename T>
OnExceptionGuard<T> make_on_exception_guard( T code )
{
    return OnExceptionGuard<T>( code );
}

}

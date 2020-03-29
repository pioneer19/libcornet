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

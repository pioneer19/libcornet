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

#include <experimental/coroutine>

#include <libcornet/guards.hpp>

namespace pioneer19::coroutines
{

template< typename ResumeType >
struct CoroutineAwaiter
{
    struct promise_type;
    using coroutine_awaiter_handle = std::experimental::coroutine_handle<promise_type>;

    coroutine_awaiter_handle awaiter_handle;

    CoroutineAwaiter( coroutine_awaiter_handle co_handle ) : awaiter_handle( co_handle)
    {}
    ~CoroutineAwaiter() { awaiter_handle.destroy(); }

    CoroutineAwaiter() = delete;
    CoroutineAwaiter( const CoroutineAwaiter& ) = delete;
    CoroutineAwaiter( CoroutineAwaiter&& ) = delete;
    CoroutineAwaiter& operator=( const CoroutineAwaiter&) = delete;
    CoroutineAwaiter& operator=( CoroutineAwaiter&&) = delete;

    struct promise_type{
        std::experimental::coroutine_handle<> caller_handle
                = std::experimental::noop_coroutine() ;
//        ResumeType resume_value;
        alignas(ResumeType) uint8_t resume_value[sizeof(ResumeType)];

        std::experimental::suspend_never  initial_suspend() { return {}; }
        auto final_suspend()
        {
            struct Awaiter {
                std::experimental::coroutine_handle<>& caller_handle;
                bool await_ready() { return false; }
                auto await_suspend( std::experimental::coroutine_handle<> )
                { return caller_handle; }
                void await_resume() {}
            };
            return Awaiter{ caller_handle };
        }
        auto get_return_object() { return coroutine_awaiter_handle::from_promise( *this ); }
        void unhandled_exception() { std::terminate(); }
        template< typename T >
//        void return_value( T&& value ) { resume_value = std::forward<T>(value); }
        void return_value( T&& value ) { new (resume_value) ResumeType(std::forward<T>(value)); }
    };

    bool await_ready() { return awaiter_handle.done(); }
    void await_suspend( std::experimental::coroutine_handle<> caller_handle )
    { awaiter_handle.promise().caller_handle = caller_handle; }
//    ResumeType await_resume() { return std::forward<ResumeType>(awaiter_handle.promise().resume_value); }
    ResumeType await_resume()
    {
        auto destructor = guards::make_scope_guard( [this]()
                { reinterpret_cast<ResumeType*>(this->awaiter_handle.promise().resume_value)->~ResumeType(); } );
        return std::forward<ResumeType>( *reinterpret_cast<ResumeType*>(awaiter_handle.promise().resume_value) );
    }
};

/**
 * if coroutine (caller) execute co_await CoroutineAwaiter
 * this Awaiter in final_suspend will resume caller
 */
template<>
struct CoroutineAwaiter<void>
{
    struct promise_type;
    using coroutine_awaiter_handle = std::experimental::coroutine_handle<promise_type>;

    coroutine_awaiter_handle awaiter_handle;

    CoroutineAwaiter( coroutine_awaiter_handle co_handle ) : awaiter_handle( co_handle)
    {}
    ~CoroutineAwaiter() { awaiter_handle.destroy(); }

    CoroutineAwaiter() = delete;
    CoroutineAwaiter( const CoroutineAwaiter& ) = delete;
    CoroutineAwaiter( CoroutineAwaiter&& ) = delete;
    CoroutineAwaiter& operator=( const CoroutineAwaiter&) = delete;
    CoroutineAwaiter& operator=( CoroutineAwaiter&&) = delete;

    struct promise_type{
        std::experimental::coroutine_handle<> caller_handle
                = std::experimental::noop_coroutine() ;

        std::experimental::suspend_never  initial_suspend() { return {}; }
        auto final_suspend()
        {
            struct Awaiter {
                std::experimental::coroutine_handle<>& caller_handle;
                bool await_ready() { return false; }
                auto await_suspend( std::experimental::coroutine_handle<> )
                { return caller_handle; }
                void await_resume() {}
            };
            return Awaiter{ caller_handle };
        }
        auto get_return_object() { return coroutine_awaiter_handle::from_promise( *this ); }
        void unhandled_exception() { std::terminate(); }
        void return_void() {}
    };

    bool await_ready() { return awaiter_handle.done(); }
    void await_suspend( std::experimental::coroutine_handle<> caller_handle )
    { awaiter_handle.promise().caller_handle = caller_handle; }
    void await_resume() {}
};
/**
 * coroutine return type for simple coroutines
 * @code{.cpp}
 * CommonCoroutine async_session( net::Poller& poller )
 * {
 *     net::TcpSocket client;
 *
 *     co_await client.async_connect( poller, &peer_addr );
 *     auto sent_bytes = co_await client.async_write( buff, sizeof(buff)-1 );
 *     auto read_bytes = co_await client.async_read(  buff, sent_bytes );
 *     client.close();
 *
 *     poller.stop();
 * }
 * int main()
 * {
 *     net::Poller poller;
 *     auto coro = async_session( poller );
 *     poller.run();
 *     return 0;
 * }
 * @endcode
 */
struct CommonCoroutine
{
    struct promise_type;
    using coro_handler = std::experimental::coroutine_handle<promise_type>;
    coro_handler coro;

    CommonCoroutine( coro_handler coro ) noexcept
            :coro( coro )
    {}
    CommonCoroutine( CommonCoroutine&& other ) noexcept
            : coro{other.coro}
    { other.coro = nullptr; }
    CommonCoroutine& operator=( CommonCoroutine&& other ) noexcept
    { if( this != &other) { std::swap( coro, other.coro); } return *this; }
    ~CommonCoroutine() { stop(); }

    void stop() { if( coro ) { coro.destroy(); coro = nullptr; } }

    CommonCoroutine() = delete;
    CommonCoroutine( const CommonCoroutine& ) = delete;
    CommonCoroutine& operator=( const CommonCoroutine& ) = delete;

    struct promise_type
    {
        std::experimental::suspend_never  initial_suspend() { return {}; }
        std::experimental::suspend_always final_suspend()   { return {}; }
        auto get_return_object() { return coro_handler::from_promise(*this); }
        void unhandled_exception() { std::terminate(); }
        void return_void() {}
    };
};

}

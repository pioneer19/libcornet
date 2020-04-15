/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#pragma once

#include <experimental/coroutine>

#include <libcornet/promise_list.hpp>
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

/**
 * coroutine which will run some actions and self destroyed
 *
 * It's promise linked in non intrusive list to destroy unfinished coroutines
 * on program exit or other reasons
 * @code{.cpp}
 * coroutines::LinkedCoroutine create_session( net::TcpSocket tcp_socket )
 * {
 *     uint8_t buffer[1024];
 *     auto bytes_read = co_await tcp_socket.async_read( buffer, sizeof(buffer) );
 *     auto bytes_sent = co_await tcp_socket.async_write( buffer, bytes_read );
 * }
 * void server()
 * {
 *     net::TcpSocket client_socket = co_await tcp_socket.async_accept( poller, nullptr );
 *     auto session = create_session( std::move( client_socket ) ); // coroutine will stop on initial_suspend
 *     session.link_promise( tls_sessions_list );                   // then linked in list
 *     session.start();                                             // then continue running
 * }
 * @endcode
 */
struct LinkedCoroutine
{
    struct promise_type;
    using List = PromiseList<promise_type>;
    using Node = PromiseNode<promise_type>;

    using coro_handler = std::experimental::coroutine_handle<promise_type>;
    struct promise_type : public Node
    {
        std::experimental::suspend_always initial_suspend() { return {}; }
        std::experimental::suspend_never  final_suspend()   { return {}; }
        coro_handler get_return_object() { return coro_handler::from_promise(*this); }
        void unhandled_exception() { std::terminate(); }
        void return_void() {}
    };

    LinkedCoroutine( coro_handler coro ) noexcept
            :coro{ coro }
    {}
    LinkedCoroutine( LinkedCoroutine&& other ) noexcept :coro{other.coro} {}
    LinkedCoroutine& operator=( LinkedCoroutine&& other ) noexcept
    { coro = other.coro; return *this; }
    ~LinkedCoroutine() = default;
    coro_handler coro;

    void link_promise( List& list ) const { list.push_front( &coro.promise() ); }
    void start() { coro.resume(); }
    LinkedCoroutine() = delete;
    LinkedCoroutine( const LinkedCoroutine& ) = delete;
    LinkedCoroutine& operator=( const LinkedCoroutine& ) = delete;
};

}

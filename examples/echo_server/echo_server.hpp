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

#include <libcornet/poller.hpp>
#include <libcornet/tcp_socket.hpp>
#include <libcornet/promise_list.hpp>

struct EchoSession
{
    struct promise_type;
    using PromiseList = pioneer19::coroutines::PromiseList<promise_type>;
    using PromiseNode = pioneer19::coroutines::PromiseNode<promise_type>;

    using coro_handler = std::experimental::coroutine_handle<promise_type>;
    struct promise_type : public PromiseNode
    {
        std::experimental::suspend_never initial_suspend() { return {}; }
        std::experimental::suspend_never final_suspend()   { return {}; }
        EchoSession get_return_object() { return EchoSession{coro_handler::from_promise(*this)}; }
        void unhandled_exception() { std::terminate(); }
        void return_void() {}
    };
    explicit EchoSession( coro_handler coro ) noexcept
        :coro( coro )
    {}
    coro_handler coro;
    void add_to_list( PromiseList& list )
    {
        list.push_front( &coro.promise() );
    }
};

struct EchoServerRunner
{
    struct promise_type;
    using coro_handler = std::experimental::coroutine_handle<promise_type>;

    struct promise_type
    {
        std::experimental::suspend_never initial_suspend() { return {}; }
        std::experimental::suspend_never final_suspend()   { return {}; }
        EchoServerRunner get_return_object()
        {
            return EchoServerRunner{coro_handler::from_promise(*this)};
        }
        void unhandled_exception() { std::terminate(); }
        void return_void() {}
    };

    EchoServerRunner() = default;
    explicit EchoServerRunner( coro_handler coro ) noexcept
        :coro( coro )
    {}
    EchoServerRunner( EchoServerRunner&& other ) noexcept
        : coro(std::move(other.coro) ){ other.coro = nullptr; }
    EchoServerRunner& operator=( EchoServerRunner&& other ) noexcept
    { if( this != &other) { std::swap( coro, other.coro); } return *this; }
    ~EchoServerRunner() { stop(); }

    EchoServerRunner( const EchoServerRunner& ) = delete;
    EchoServerRunner& operator=( const EchoServerRunner& ) = delete;

    void stop() { if( coro ) { coro.destroy(); coro = nullptr; } }

    coro_handler coro;
};

class EchoServer
{
public:
    explicit EchoServer( pioneer19::cornet::Poller& poller );
    EchoServer( const EchoServer& ) = delete;
    EchoServer( EchoServer&& ) = delete;
    EchoServer& operator=( const EchoServer& ) = delete;
    EchoServer& operator=( EchoServer&& ) = delete;

    void run();
    void stop() { m_server_socket.close(); m_runner.stop(); }

private:
    EchoServerRunner create_runner();

    pioneer19::cornet::Poller& m_poller;
    pioneer19::coroutines::PromiseList<EchoSession::promise_type> m_session_list;
    pioneer19::cornet::TcpSocket m_server_socket;
    EchoServerRunner m_runner;
};

inline void EchoServer::run()
{
    if( m_runner.coro )
        return;

    m_runner = create_runner();
}

EchoSession create_echo_session( pioneer19::cornet::TcpSocket tcp_socket );

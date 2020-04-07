/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#pragma once

#include <unordered_map>
#include <functional>
#include <experimental/coroutine>

#include <libcornet/async_file.hpp>

namespace pioneer19::cornet
{

class SignalProcessor
{
public:
    explicit SignalProcessor( Poller& poller );

    void add_signal_handler( int signum, std::function<void()> func );

private:
    struct SignalRunner
    {
        struct promise_type;
        using coro_handler = std::experimental::coroutine_handle<promise_type>;

        struct promise_type
        {
            std::experimental::suspend_never initial_suspend() { return {}; }
            std::experimental::suspend_never final_suspend()   { return {}; }
            SignalRunner get_return_object()
            {
                return SignalRunner{coro_handler::from_promise(*this)};
            }
            void unhandled_exception() { std::terminate(); }
            void return_void() {}
        };

        SignalRunner() = default;
        explicit SignalRunner( coro_handler coro ) noexcept
            :coro( coro )
        {}
        SignalRunner( SignalRunner&& other ) noexcept
            : coro(std::move(other.coro) ){ other.coro = nullptr; }
        SignalRunner& operator=( SignalRunner&& other ) noexcept
        { if( this != &other) { std::swap( coro, other.coro); } return *this; }

        SignalRunner( const SignalRunner& ) = delete;
        SignalRunner& operator=( const SignalRunner& ) = delete;
        ~SignalRunner() { if( coro ) coro.destroy(); }

        coro_handler coro;
    };

    using HandlersMap = std::unordered_map<int,std::function<void()>>;

    SignalRunner create_signal_runner( AsyncFile& m_async_file, const HandlersMap& m_signal_handlers );

    AsyncFile m_async_file;
    HandlersMap  m_signal_handlers;
    SignalRunner m_runner;
};

}

/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#include <libcornet/signal_processor.hpp>

#include <signal.h>
#include <sys/signalfd.h>
#include <cstring>

#include <system_error>
#include <iostream> // FIXME: remove this header

#include <libcornet/poller.hpp>

namespace pioneer19::cornet
{

SignalProcessor::SignalProcessor( Poller& poller )
{
    sigset_t mask;
    sigemptyset(&mask);
    int signal_fd = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC );
    if( signal_fd == -1 )
    {
        throw std::system_error(errno, std::system_category()
                                , "SignalProcessor() failed create signalfd" );
    }
    m_async_file = AsyncFile( signal_fd, &poller );
    m_runner = create_signal_runner( m_async_file, m_signal_handlers );
}

SignalProcessor::SignalRunner SignalProcessor::create_signal_runner(
        AsyncFile& async_file, const HandlersMap& signal_handlers )
{
    while( true )
    {
        signalfd_siginfo sig_info;
        auto bytes_read = co_await async_file.async_read(
                reinterpret_cast<char*>(&sig_info), sizeof(sig_info) );
        if( bytes_read != sizeof(sig_info) )
        {
            throw std::system_error( errno, std::system_category()
                    ,std::string("SignalRunner got ")+std::to_string(bytes_read)
                    +" bytes, expected "+std::to_string(sizeof(sig_info)) );
        }

        std::cout << "SignalRunner got " << ::strsignal( sig_info.ssi_signo ) << " signal\n";
        if( auto it = m_signal_handlers.find( sig_info.ssi_signo ); it != m_signal_handlers.end() )
        {
            it->second();
        }
    }
}

void SignalProcessor::add_signal_handler( int signum, std::function<void()> func )
{
    m_signal_handlers[ signum ] = func;

    sigset_t mask;
    sigemptyset(&mask);

    for( auto& [curr_signum, func] : m_signal_handlers )
    {
        sigaddset( &mask, curr_signum );
    }
    if (sigprocmask( SIG_BLOCK, &mask, nullptr ) == -1)
    {
        throw std::system_error(errno, std::system_category()
                                , "add_signal_handler() failed block signals" );
    }
    int signal_fd = signalfd( m_async_file.fd(), &mask, SFD_NONBLOCK|SFD_CLOEXEC );
    if( signal_fd == -1 )
    {
        throw std::system_error(errno, std::system_category()
                                ,"add_signal_handler() failed change signalfd" );
    }
}

}

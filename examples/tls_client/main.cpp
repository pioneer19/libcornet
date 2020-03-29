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

#include <unistd.h>
#include <iostream>

#include <tls_client/tls_client.hpp>
#include <libcornet/poller.hpp>
namespace net = pioneer19::cornet;

int main()
{
    std::cout << "Polling TLS client (single thread)\n";

    net::Poller poller;

    TlsClient tls_client{ poller };
    tls_client.run();

    poller.run_on_signal( SIGINT, [&tls_client,&poller](){ tls_client.stop(); poller.stop();} );
    poller.run_on_signal( SIGHUP, [&tls_client,&poller](){ tls_client.stop(); poller.stop();} );

    poller.run();

    return 0;
}

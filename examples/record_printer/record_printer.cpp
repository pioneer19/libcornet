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

#include <iostream>

#include <libcornet/tls/parser.hpp>
namespace record = pioneer19::cornet::tls13::record;

#include "client_hello_record.hpp"
#include "server_hello_record.hpp"

int main()
{
    auto err = record::print_net_record( tls13_client_hello_record
                                         ,sizeof( tls13_client_hello_record ) );
//    auto err = record::print_net_record( reinterpret_cast<const char*>(tls13_server_hello_record)
//                                         ,sizeof( tls13_server_hello_record ) );

    if( err )
        std::cout << "error: " << err.message() << "\n";

    return 0;
}

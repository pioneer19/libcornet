/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#include <sys/socket.h>
#include <netinet/in.h>

#include <cstring>
#include <unistd.h>
#include <system_error>
#include <iostream>

int main()
{
    std::cout << "Single thread echo server\n";

    int server_fd = socket( AF_INET, SOCK_STREAM, 0 );
    if( server_fd == -1 )
        throw std::system_error(errno, std::system_category(), "failed create socket" );

    int so_reuse = 1;
    setsockopt( server_fd, SOL_SOCKET, SO_REUSEADDR, &so_reuse, sizeof( so_reuse ));

    sockaddr_in server_addr;
    std::fill((char*)&server_addr, (char*)&server_addr + sizeof( server_addr ), 0 );
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    server_addr.sin_port = htons( 10000 );

    if( bind( server_fd, (struct sockaddr*)&server_addr, sizeof( struct sockaddr_in )) == -1 )
        throw std::system_error(errno, std::system_category(), "failed bind" );

    if( listen( server_fd, 1024 ) == -1 )
        throw std::system_error(errno, std::system_category(), "failed listen" );

    while( true )
    {
        sockaddr_in peer_addr;
        socklen_t peer_addr_size = sizeof( struct sockaddr_in );
        int client_fd = accept( server_fd, (struct sockaddr*)&peer_addr, &peer_addr_size );
        if( client_fd == -1 )
            throw std::system_error(errno, std::system_category(), "accept failed" );

        char buff[1024];
        ssize_t net_io_res = recv( client_fd, buff, sizeof( buff ), 0 );
        if( net_io_res == -1 )
        {
            std::cerr << "recv failed" << strerror(errno) << "\n";
            close( client_fd );
            continue;
        }
        net_io_res = send( client_fd, buff, net_io_res, MSG_NOSIGNAL );
        if( net_io_res == -1 )
        {
            std::cerr << "send failed" << strerror(errno) << "\n";
            close( client_fd );
            continue;
        }
        std::cout << "sent back " << net_io_res << " bytes" << std::endl;
        close( client_fd );
    }

    return 0;
}

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

#include <unistd.h>
#include <sys/syscall.h>

#include <csignal>

extern "C"
{

int syscall_io_uring_setup( unsigned entries, struct io_uring_params* p );
long syscall_io_uring_enter( int fd, unsigned to_submit,
                             unsigned min_complete, unsigned flags, sigset_t* sig );
long syscall_io_uring_register( int fd, unsigned int opcode, const void* arg,
                                unsigned int nr_args );
}

inline int syscall_io_uring_setup( unsigned entries, struct io_uring_params* p )
{
    return (int)syscall( __NR_io_uring_setup, entries, p);
}

inline long syscall_io_uring_enter( int fd, unsigned to_submit,
                                    unsigned min_complete, unsigned flags, sigset_t* sig )
{
return syscall( __NR_io_uring_enter, fd, to_submit, min_complete,
        flags, sig, _NSIG / 8);
}

inline long syscall_io_uring_register( int fd, unsigned int opcode, const void* arg,
                                unsigned int nr_args )
{
    return syscall( __NR_io_uring_register, fd, opcode, arg, nr_args);
}

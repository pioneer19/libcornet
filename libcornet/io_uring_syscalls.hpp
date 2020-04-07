/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
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

/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#pragma once

#include <libcornet/config.hpp>
#if USE_IO_URING

#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/io_uring.h>

#include <cstdint>
#include <cstddef>
#include <atomic>
#include <deque>
#include <experimental/coroutine>

namespace pioneer19::cornet
{

struct NetUringCb
{
    int result{};
    std::experimental::coroutine_handle<> coro_to_resume;
};

class NetUring
{
public:
    NetUring();
    ~NetUring() noexcept;

    NetUring( const NetUring& ) = delete;
    NetUring( NetUring&& ) = delete;
    NetUring& operator=( const NetUring& ) = delete;
    NetUring& operator=( NetUring&& ) = delete;

    static NetUring& instance();

    auto async_read(  int sock, void* buffer, uint32_t buffer_size );
    auto async_write( int sock, const void* buffer, uint32_t buffer_size );
    uint32_t process_requests();
    void cancel_request( NetUringCb* net_uring_cb );
    void debug_print_queues();
    void debug_print_cqes();

    struct SendQueue
    {
        std::atomic<unsigned>* head = nullptr;
        std::atomic<unsigned>* tail = nullptr;
        unsigned* ring_mask = nullptr;
        unsigned* ring_entries = nullptr;
        unsigned* flags = nullptr;
        unsigned* dropped = nullptr;
        unsigned* index_array = nullptr;
        io_uring_sqe* sqes = nullptr;

        size_t ring_size = 0;
        void* ring_ptr = nullptr;
    };
    struct CompletionQueue
    {
        std::atomic<unsigned>* head = nullptr;
        std::atomic<unsigned>* tail = nullptr;
        unsigned* ring_mask = nullptr;
        unsigned* ring_entries = nullptr;
        unsigned* overflow = nullptr;
        io_uring_cqe* cqes = nullptr;

        size_t ring_size = 0;
        void* ring_ptr = nullptr;
    };

private:
    static constexpr uint32_t ENTRIES_COUNT = 32u;
    static constexpr uint32_t ENTRIES_MASK = ENTRIES_COUNT - 1;
    int init_queue( uint32_t entries, uint32_t flags = 0 );
    void enqueue_recvmsg( NetUringCb* net_uring_cb, int sock, void* buffer, uint32_t buffer_size );
    void enqueue_sendmsg( NetUringCb* net_uring_cb, int sock, const void* buffer, uint32_t buffer_size );
    void enqueue_in_kernel( NetUringCb* net_uring_cb, int sock, const void* buffer, uint32_t buffer_size
            , uint8_t opcode );
    /**
     * submit requests to kernel up to batch size and get completed events
     * @return queue size not submitted (ready to submit)
     */
    long submit_queue();
    void process_completed_events();

    SendQueue m_send_queue;
    CompletionQueue m_comp_queue;
    int m_io_uring_fd = -1;
    uint16_t m_ready_counter = 0;
    uint16_t m_iov_index = 0;
    msghdr m_msg_hdr[ 2 * ENTRIES_COUNT ] = {};
    iovec  m_io_vec [ 2 * ENTRIES_COUNT ] = {};

    struct IoRequest
    {
        NetUringCb* net_uring_cb;
        void*       buffer;
        uint32_t    buffer_size;
        int         sock;
        uint8_t     opcode;
    };
    std::deque<IoRequest> m_extra_requests;

    inline static NetUringCb nop_uring_cb = {0,std::experimental::noop_coroutine() };
};

inline NetUring& NetUring::instance()
{
    static thread_local NetUring net_uring;

    return net_uring;
}

inline auto NetUring::async_read( int sock, void* buffer, uint32_t buffer_size )
{
    struct Awaiter
    {
        NetUring& net_uring;
        void*    buffer = nullptr;
        uint32_t buffer_size = 0;
        int      sock = -1;
        NetUringCb net_uring_cb;

        bool await_ready() { return false; }
        void await_suspend( std::experimental::coroutine_handle<> coro_handle )
        {
            net_uring_cb.coro_to_resume = coro_handle;
            net_uring.enqueue_recvmsg( &net_uring_cb, sock, buffer, buffer_size );
        }
        ssize_t await_resume() { return net_uring_cb.result; }
    };
    return Awaiter{ *this, buffer, buffer_size, sock, {} };
}

inline auto NetUring::async_write( int sock, const void* buffer, uint32_t buffer_size )
{
    struct Awaiter
    {
        NetUring&   net_uring;
        const void* buffer = nullptr;
        uint32_t    buffer_size = 0;
        int         sock = -1;
        NetUringCb  net_uring_cb;

        bool await_ready() { return false; }
        void await_suspend( std::experimental::coroutine_handle<> coro_handle )
        {
            net_uring_cb.coro_to_resume = coro_handle;
            net_uring.enqueue_sendmsg( &net_uring_cb, sock, buffer, buffer_size );
        }
        ssize_t await_resume() { return net_uring_cb.result; }
    };

    return Awaiter{ *this, buffer, buffer_size, sock, {} };
}

}

#endif

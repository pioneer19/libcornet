/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#include <libcornet/config.hpp>
#if defined(USE_IO_URING)

#include <libcornet/net_uring.hpp>

#include <sys/mman.h>
#include <unistd.h>
#include <sys/socket.h>

#include <cassert>
#include <cerrno>
#include <cstdio>
#include <algorithm>
#include <system_error>

#include <libcornet/io_uring_syscalls.hpp>

namespace pioneer19::cornet
{
// to disable warning unused function
//static void print_params( io_uring_params* params )
//{
//    printf( "sq_entries %u\n", params->sq_entries );
//    printf( "cq_entries %u\n", params->cq_entries );
//    printf( "flags %u\n", params->flags );
//    printf( "sq_thread_cpu %u\n", params->sq_thread_cpu );
//    printf( "sq_thread_idle %u\n", params->sq_thread_idle );
//    if( params->features & IORING_FEAT_SINGLE_MMAP)
//        printf( "features: IORING_FEAT_SINGLE_MMAP\n" );
//    else
//        printf( "features %u\n", params->features );
//    // io_sqring_offsets sq_off;
//    printf( "=== io_sqring_offsets ===\n" );
//    printf( "head %u\n", params->sq_off.head );
//    printf( "tail %u\n", params->sq_off.tail );
//    printf( "ring_mask %u\n", params->sq_off.ring_mask );
//    printf( "ring_entries %u\n", params->sq_off.ring_entries );
//    printf( "flags %u\n", params->sq_off.flags );
//    printf( "dropped %u\n", params->sq_off.dropped );
//    printf( "array %u\n", params->sq_off.array );
//    // io_cqring_offsets cq_off;
//    printf( "=== io_cqring_offsets ===\n" );
//    printf( "head %u\n", params->cq_off.head );
//    printf( "tail %u\n", params->cq_off.tail );
//    printf( "ring_mask %u\n", params->cq_off.ring_mask );
//    printf( "ring_entries %u\n", params->cq_off.ring_entries );
//    printf( "overflow %u\n", params->cq_off.overflow );
//    printf( "cqes %u\n", params->cq_off.cqes );
//}

static void print_send_queue( const NetUring::SendQueue* send_queue )
{
    printf( "== enqueue_sendmsg queue ===\n" );

    printf( "head      %u\n", send_queue->head->load( std::memory_order_relaxed ));
    printf( "tail      %u\n", send_queue->tail->load( std::memory_order_relaxed ));
    printf( "ring_mask %u\n", *send_queue->ring_mask );
    printf( "ring_entries %u\n", *send_queue->ring_entries );
    printf( "flags     %u\n", *send_queue->flags );
    printf( "dropped   %u\n", *send_queue->dropped );
    printf( "index_array %p\n", (void*)send_queue->index_array );

    printf( "ring_size %ld\n", send_queue->ring_size );
    printf( "ring_ptr  %p\n", send_queue->ring_ptr );
}

static void* mmap_sq_ring( NetUring::SendQueue& send_queue, io_uring_params* params, int uring_fd )
{
    size_t sq_ring_mmap_size = params->sq_off.array + params->sq_entries * sizeof( __u32 );

    auto sq_ring_ptr = (uint8_t*)mmap( nullptr, sq_ring_mmap_size
            , PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE
                                       , uring_fd, IORING_OFF_SQ_RING );
    if( sq_ring_ptr == MAP_FAILED)
        return nullptr;

    send_queue.ring_ptr = sq_ring_ptr;
    send_queue.ring_size = sq_ring_mmap_size;

    send_queue.head = reinterpret_cast<std::atomic<uint32_t>*>(sq_ring_ptr + params->sq_off.head);
    send_queue.tail = reinterpret_cast<std::atomic<uint32_t>*>(sq_ring_ptr + params->sq_off.tail);
    send_queue.ring_mask = reinterpret_cast<uint32_t*>(sq_ring_ptr + params->sq_off.ring_mask);
    send_queue.ring_entries = reinterpret_cast<uint32_t*>(sq_ring_ptr + params->sq_off.ring_entries);
    send_queue.flags = reinterpret_cast<uint32_t*>(sq_ring_ptr + params->sq_off.flags);
    send_queue.dropped = reinterpret_cast<uint32_t*>(sq_ring_ptr + params->sq_off.dropped);
    send_queue.index_array = reinterpret_cast<uint32_t*>(sq_ring_ptr + params->sq_off.array);

    return sq_ring_ptr;
}

static void munmap_sq_ring( NetUring::SendQueue& send_queue )
{
    if( send_queue.ring_ptr )
        munmap( send_queue.ring_ptr, send_queue.ring_size );
}

static void* mmap_sqes( NetUring::SendQueue& send_queue, io_uring_params* params, int uring_fd )
{
    void* sqes_ptr = mmap( nullptr, params->sq_entries * sizeof( struct io_uring_sqe )
            , PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_POPULATE, uring_fd, IORING_OFF_SQES );
    if( sqes_ptr == MAP_FAILED)
        return nullptr;

    send_queue.sqes = reinterpret_cast<io_uring_sqe*>( sqes_ptr );

    return sqes_ptr;
}

static void munmap_sqes( NetUring::SendQueue& send_queue )
{
    if( send_queue.sqes )
        ::munmap( send_queue.sqes, *send_queue.ring_entries * sizeof( struct io_uring_sqe ));
}

static void print_comp_queue( const NetUring::CompletionQueue* comp_queue )
{
    printf( "== completion queue ===\n" );

    printf( "head      %u\n", comp_queue->head->load( std::memory_order_relaxed ));
    printf( "tail      %u\n", comp_queue->tail->load( std::memory_order_relaxed ));
    printf( "ring_mask %u\n", *comp_queue->ring_mask );
    printf( "ring_entries %u\n", *comp_queue->ring_entries );
    printf( "overflow  %u\n", *comp_queue->overflow );
    printf( "cqes      %p\n", (void*)comp_queue->cqes );

    printf( "\nring_size %ld\n", comp_queue->ring_size );
    printf( "ring_ptr  %p\n", comp_queue->ring_ptr );
}

static void* mmap_cqes( NetUring::CompletionQueue& comp_queue, io_uring_params* params, int uring_fd )
{
    size_t cq_ring_mmap_size = params->cq_off.cqes + params->cq_entries * sizeof( struct io_uring_cqe );
    auto* cq_ring_ptr = (uint8_t*)mmap( nullptr, cq_ring_mmap_size
            , PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE
                                        , uring_fd, IORING_OFF_CQ_RING );
    if( cq_ring_ptr == MAP_FAILED)
        return nullptr;

    comp_queue.ring_ptr = cq_ring_ptr;
    comp_queue.ring_size = cq_ring_mmap_size;

    comp_queue.head = reinterpret_cast<std::atomic<uint32_t>*>(cq_ring_ptr + params->cq_off.head);
    comp_queue.tail = reinterpret_cast<std::atomic<uint32_t>*>(cq_ring_ptr + params->cq_off.tail);
    comp_queue.ring_mask = reinterpret_cast<uint32_t*>(cq_ring_ptr + params->cq_off.ring_mask);
    comp_queue.ring_entries = reinterpret_cast<uint32_t*>(cq_ring_ptr + params->cq_off.ring_entries);
    comp_queue.overflow = reinterpret_cast<uint32_t*>(cq_ring_ptr + params->cq_off.overflow);
    comp_queue.cqes = reinterpret_cast<io_uring_cqe*>(cq_ring_ptr + params->cq_off.cqes);

    return cq_ring_ptr;
}

static void munmap_cqes( NetUring::CompletionQueue& comp_queue )
{
    if( comp_queue.ring_ptr )
        ::munmap( comp_queue.ring_ptr, comp_queue.ring_size );
}

static int mmap_queues( NetUring::SendQueue& send_queue
        , NetUring::CompletionQueue& comp_queue, io_uring_params* params,
                        int uring_fd )
{
    if( mmap_sq_ring( send_queue, params, uring_fd )
        && mmap_sqes( send_queue, params, uring_fd )
        && mmap_cqes( comp_queue, params, uring_fd ) )
    {
        return 0;
    }

    return 1;
}

int NetUring::init_queue( unsigned entries, unsigned flags )
{
    io_uring_params params{};
    std::fill_n( (uint8_t*)&params, sizeof( params ), 0 );
    params.flags = flags;

    m_io_uring_fd = syscall_io_uring_setup( entries, &params );
    if( m_io_uring_fd < 0 )
    {
        printf( "syscall_io_uring_setup error: %s\n", strerror(errno));
        return -errno;
    }
    if( auto res = mmap_queues( m_send_queue, m_comp_queue, &params, m_io_uring_fd ); res != 0 )
        return res;

    for( unsigned i = 0; i < *m_send_queue.ring_entries; ++i )
        m_send_queue.index_array[i] = i;

    return 0;
}

NetUring::NetUring()
{
    if( init_queue( ENTRIES_COUNT ) != 0 )
        throw std::system_error(errno, std::system_category(), "NetUring constructor failed" );
}

NetUring::~NetUring() noexcept
{
    munmap_cqes( m_comp_queue );
    munmap_sqes( m_send_queue );
    munmap_sq_ring( m_send_queue );
    if( m_io_uring_fd != -1 )
        ::close( m_io_uring_fd );
}

static io_uring_sqe* next_sqe( NetUring::SendQueue& sq )
{
    uint32_t tail = sq.tail->load( std::memory_order_relaxed );
    uint32_t next = tail + 1;
    uint32_t head = sq.head->load( std::memory_order_relaxed );
    if((next - head) > *sq.ring_entries )
        return nullptr;

    io_uring_sqe* sqe = sq.sqes + (tail & *sq.ring_mask);

    return sqe;
}

static void commit_sqe( NetUring::SendQueue& sq )
{
    sq.tail->fetch_add( 1, std::memory_order_acq_rel );
}

void NetUring::enqueue_sendmsg( NetUringCb* net_uring_cb
        , int sock, const void* buffer, uint32_t buffer_size )
{
    if( m_ready_counter < ENTRIES_COUNT )
        enqueue_in_kernel( net_uring_cb, sock, buffer, buffer_size, IORING_OP_SENDMSG );
    else
    {
        m_extra_requests.emplace_back(
                IoRequest{net_uring_cb, const_cast<void*>(buffer), buffer_size, sock, IORING_OP_SENDMSG} );
    }
}

void NetUring::enqueue_recvmsg( NetUringCb* net_uring_cb, int sock, void* buffer, uint32_t buffer_size )
{
    if( m_ready_counter < ENTRIES_COUNT )
        enqueue_in_kernel( net_uring_cb, sock, buffer, buffer_size, IORING_OP_RECVMSG );
    else
    {
        m_extra_requests.emplace_back(
                IoRequest{net_uring_cb, buffer, buffer_size, sock, IORING_OP_RECVMSG} );
    }
}

static io_uring_cqe* next_cqe( NetUring::CompletionQueue& cq )
{
    uint32_t tail = cq.tail->load( std::memory_order_relaxed );
    uint32_t head = cq.head->load( std::memory_order_acquire );
    if( head == tail )
        return nullptr;

    return cq.cqes + (head & *cq.ring_mask);
}

static void commit_cqe( NetUring::CompletionQueue& cq )
{
    cq.head->fetch_add( 1, std::memory_order_acq_rel );
}

static void print_cqe( io_uring_cqe* cqe )
{
    printf( "=== io_uring_cqe ===\n" );
    printf( "user_data 0x%llx\n", cqe->user_data );
    printf( "res       %d\n", cqe->res );
    printf( "flags     %u\n", cqe->flags );
}

long NetUring::submit_queue()
{
    long submitted_count = 0;
    if( m_ready_counter != 0 )
    {
        uint32_t send_head = m_send_queue.head->load( std::memory_order_relaxed );
        m_send_queue.sqes[send_head & *m_send_queue.ring_mask].flags |= IOSQE_IO_DRAIN;

        submitted_count = syscall_io_uring_enter( m_io_uring_fd,
                m_ready_counter, 1, IORING_ENTER_GETEVENTS, nullptr );
        if( submitted_count < 0 )
            throw std::system_error(errno, std::system_category(), "syscall_io_uring_enter" );

        m_ready_counter -= submitted_count;
    }

    if( !m_extra_requests.empty() )
    {
        uint32_t events_to_move = std::min( ENTRIES_COUNT - m_ready_counter
                                            , (uint32_t)m_extra_requests.size());
        for( uint32_t i = 0; i < events_to_move; ++i )
        {
            auto& head = m_extra_requests.front();
            enqueue_in_kernel( head.net_uring_cb, head.sock, head.buffer, head.buffer_size, head.opcode );
            m_extra_requests.pop_front();
        }
    }

    return submitted_count;
}

uint32_t NetUring::process_requests()
{   // I want process_request loop until m_ready_count == max batch size
    // but if it's less, let poller epoll_wait with 0 timeout to get more
    // events
    assert( next_cqe( m_comp_queue ) == nullptr );
    while( true )
    {
        submit_queue();
        process_completed_events();

        if( m_ready_counter < ENTRIES_COUNT )
            break;
    }
    // process one more time with short send queue (sqe) before epoll_wait
    if( m_ready_counter != 0 )
    {
        submit_queue();
        process_completed_events();
    }
    return m_ready_counter;
}

void NetUring::process_completed_events()
{
    io_uring_cqe* cqe = nullptr;
    while( (cqe = next_cqe(m_comp_queue) ) != nullptr )
    {
        auto* uring_cb = reinterpret_cast<NetUringCb*>(cqe->user_data);
        uring_cb->result = cqe->res;
        commit_cqe( m_comp_queue );

        uring_cb->coro_to_resume.resume();
    }
}

void NetUring::enqueue_in_kernel( NetUringCb* net_uring_cb
        , int sock, const void* buffer, uint32_t buffer_size, uint8_t opcode )
{
    io_uring_sqe* sqe = next_sqe( m_send_queue );
    if( !sqe )
        throw std::system_error(errno, std::system_category(), "next_sqe" );

    uint32_t iov_index = m_iov_index & ENTRIES_MASK;
    m_io_vec[iov_index].iov_base = const_cast<void*>(buffer);
    m_io_vec[iov_index].iov_len = buffer_size;

    m_msg_hdr[iov_index].msg_name = nullptr;
    m_msg_hdr[iov_index].msg_namelen = 0;
    m_msg_hdr[iov_index].msg_control = nullptr;
    m_msg_hdr[iov_index].msg_controllen = 0;
    m_msg_hdr[iov_index].msg_flags = 0;
    m_msg_hdr[iov_index].msg_iov = m_io_vec + iov_index;
    m_msg_hdr[iov_index].msg_iovlen = 1;

    std::fill_n((uint8_t*)sqe, sizeof( *sqe ), 0 );
    sqe->opcode = opcode;
    sqe->fd = sock;
    sqe->addr = reinterpret_cast<unsigned long>(m_msg_hdr + iov_index);
    sqe->len = 1;
    sqe->msg_flags = MSG_DONTWAIT;
    sqe->user_data = reinterpret_cast<uint64_t>(net_uring_cb);

    commit_sqe( m_send_queue );

    ++m_iov_index;
    ++m_ready_counter;
}

void NetUring::cancel_request( NetUringCb* net_uring_cb )
{
    // remove request from extra requests queue
    if( !m_extra_requests.empty())
    {
        auto it = m_extra_requests.begin();
        while( it != m_extra_requests.end())
        {
            if( it->net_uring_cb == net_uring_cb )
                it = m_extra_requests.erase( it );
            else
                ++it;
        }
    }
    // if request already in send queue (even not submitted),
    // i will set op = NOP and user_data to nop_uring_cb
    if( m_ready_counter != 0 )
    {
        uint32_t tail_index = m_send_queue.tail->load( std::memory_order_relaxed );
        for( uint32_t i = 0; i < m_ready_counter; ++i )
        {
            io_uring_sqe& sqe = m_send_queue.sqes[(tail_index - 1 - i) & *m_send_queue.ring_mask];
            if( sqe.user_data == reinterpret_cast<uint64_t>(net_uring_cb))
            {
                sqe.opcode = IORING_OP_NOP;
                sqe.user_data = reinterpret_cast<uint64_t>(&nop_uring_cb);
            }
        }
    }
    // detect how much already in kernel requests not finished and finish them
    // then set user_data to nop_coroutine
    uint32_t sent_head_index = m_send_queue.head->load( std::memory_order_relaxed );
    // sent_head_index - is last submitted request+1, completion queue tail will be equal
    // when all requests will be processed in kernel
    while( m_comp_queue.tail->load( std::memory_order_acquire ) != sent_head_index )
    {
        printf( "cancel_request will run in kernel queue\n" );
        auto submitted_count = syscall_io_uring_enter( m_io_uring_fd
                , 0, 1, IORING_ENTER_GETEVENTS, nullptr );
        if( submitted_count < 0 )
            throw std::system_error(errno, std::system_category()
                                    , "cancel_request syscall_io_uring_enter" );
    }
    // in kernel request queue is empty
    uint32_t comp_tail = m_comp_queue.tail->load( std::memory_order_acquire );
    uint32_t curr_index = m_comp_queue.head->load( std::memory_order_relaxed );
    while( curr_index != comp_tail )
    {
        io_uring_cqe& cqe = m_comp_queue.cqes[curr_index & *m_comp_queue.ring_mask];
        if( cqe.user_data == reinterpret_cast<uint64_t>(net_uring_cb))
            cqe.user_data = reinterpret_cast<uint64_t>(&nop_uring_cb);
        ++curr_index;
    }
}

void NetUring::debug_print_queues()
{
    print_send_queue( &m_send_queue );
    print_comp_queue( &m_comp_queue );
}

void NetUring::debug_print_cqes()
{
    io_uring_cqe* cqe = next_cqe( m_comp_queue );
    while( cqe )
    {
        print_cqe( cqe );
        commit_cqe( m_comp_queue );
        cqe = next_cqe( m_comp_queue );
    }
}

}

#endif

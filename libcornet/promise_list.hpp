/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#pragma once

namespace pioneer19::coroutines
{

template<typename PromiseType>
class PromiseNode
{
    using Node = PromiseType;
public:
    virtual ~PromiseNode();

private:
    template<typename>
    friend class PromiseList;

    void unlink();

    Node* m_next = nullptr;
    Node* m_prev = nullptr;
};

template<typename PromiseType>
class PromiseList
{
    using Node = PromiseType;
public:
    ~PromiseList();
    void push_front( Node* node );

private:
    Node m_head;
};

template<typename PromiseType>
void PromiseNode<PromiseType>::unlink()
{
    if( m_prev == nullptr )
        return;

    m_prev->m_next = m_next;
    if( m_next )
        m_next->m_prev = m_prev;

    m_prev = nullptr;
    m_next = nullptr;
}

template<typename PromiseType>
PromiseNode<PromiseType>::~PromiseNode()
{
    unlink();
}

template<typename PromiseType>
void PromiseList<PromiseType>::push_front( PromiseList::Node* node )
{
    node->m_next = m_head.m_next;
    m_head.m_next = node;

    node->m_prev = &m_head;
    if( node->m_next )
        node->m_next->m_prev = node;
}

template<typename PromiseType>
PromiseList<PromiseType>::~PromiseList()
{
    using coro_handler = std::experimental::coroutine_handle<PromiseType>;

    Node* node = m_head.m_next;
    while( node )
    {
        Node* next_node = node->m_next;
        node->m_prev = nullptr;
        coro_handler::from_promise(*node).destroy();
        // delete node;

        node = next_node;
    }
}

}

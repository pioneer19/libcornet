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

namespace pioneer19::cornet
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

//------------------------------------------------------------------------------------
// MIT License
//
// Copyright (c) 2020 Alexandr Sergienko
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//------------------------------------------------------------------------------------
// thread_context.cc author Oleksandr Serhiienko <sergienko.9711@gmail.com>

#include "thread_context.h"

std::vector<SlotPair> ThreadContext::state_slots;

void ThreadContext::init_slots(const size_t num)
{ 
    state_slots.reserve(num);
    for ( size_t count = 0; count < num; ++count )
    {
        SlotPair pair;
        pair.first = std::make_unique<std::mutex>();
        pair.second = TS_NOT_STARTED;
        state_slots.push_back(std::move(pair));
    }
}

void ThreadContext::set_state(const size_t index, const ThreadState state)
{
    SlotPair& slot = state_slots[index];

    slot.first->lock();
    slot.second = state;
    slot.first->unlock();
}


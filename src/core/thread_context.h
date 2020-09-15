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
// thread_context.h author Oleksandr Serhiienko <sergienko.9711@gmail.com>

#ifndef THREAD_CONTEXT_H
#define THREAD_CONTEXT_H

#include <vector>
#include <memory>
#include <mutex>

enum ThreadState
{
    TS_NOT_STARTED = 0,
    TS_TERMINATED,
    TS_STOPPED,
    TS_RUNNING
};

using SlotPair = std::pair<std::unique_ptr<std::mutex>, ThreadState>;

class ThreadContext
{
public:
    static void init_slots(const size_t num);

    static ThreadState get_state(const size_t index)
    { return state_slots[index].second; }

    static void set_state(const size_t index, const ThreadState state);

private:
    static std::vector<SlotPair> state_slots;

};

#endif // THREAD_CONTEXT_H


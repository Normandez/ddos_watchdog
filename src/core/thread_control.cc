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
// thread_control.cc author Oleksandr Serhiienko <sergienko.9711@gmail.com>

#include "thread_control.h"

#include "config.h"
#include "inline_set.h"
#include "thread_context.h"

ThreadControl::ThreadControl(size_t num_of_bridges)
{
    bridges.reserve(num_of_bridges);

    Config* conf = Config::get_instance();
    while ( count_bridges != num_of_bridges )
    {
        bridges.push_back(new LiveBridge(conf->ext_iface.c_str(), conf->int_iface.c_str(),
            count_bridges));

        count_bridges++;
    }

    ThreadContext::init_slots(num_of_bridges);
}

ThreadControl::~ThreadControl()
{
    for ( auto& bridge : bridges )
        delete bridge;
}

bool ThreadControl::open_bridges()
{
    for ( auto& bridge : bridges )
    {
        if ( !bridge->open() )
            return false;
    }

    return true;
}

void ThreadControl::start_live()
{
    for ( auto& bridge : bridges )
        bridge->live();
}

bool ThreadControl::is_ok() const
{
    for ( size_t index = 0; index < count_bridges; ++index )
    {
        if ( ThreadContext::get_state(index) == TS_TERMINATED )
            return false;
    }

    return true;
}

void ThreadControl::stop_all() const
{
    for ( size_t index = 0; index < count_bridges; ++index )
        ThreadContext::set_state(index, TS_STOPPED);

    std::chrono::milliseconds ms(500);
    std::this_thread::sleep_for(ms);
}


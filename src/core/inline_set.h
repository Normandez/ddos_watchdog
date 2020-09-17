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
// inline_set.h author Oleksandr Serhiienko <sergienko.9711@gmail.com>

#ifndef INLINE_SET_H
#define INLINE_SET_H

#include <atomic>
#include <thread>

class Sniffer;

class InlineSet
{
public:
    InlineSet(const char* ext_iface, const char* int_iface, size_t bridge_id,
        std::atomic_ullong& pkt_counter);

    virtual ~InlineSet();

    bool open();
    virtual void live() = 0;

protected:
    Sniffer* ext_sniffer = nullptr;
    Sniffer* int_sniffer = nullptr;
    size_t id;

};

class LiveBridge
{
public:
    LiveBridge(const char* ext_iface, const char* int_iface, int bridge_id);
    ~LiveBridge();

    bool open();
    void live();

private:
    InlineSet* ext_to_int = nullptr;
    InlineSet* int_to_ext = nullptr;
    size_t id;
    std::atomic_ullong pkt_counter;

    std::thread* etoi = nullptr;
    std::thread* itoe = nullptr;

};

#endif // INLINE_SET_H


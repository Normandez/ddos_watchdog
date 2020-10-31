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
// sniffer.h author Oleksandr Serhiienko <sergienko.9711@gmail.com>

#ifndef SNIFFER_H
#define SNIFFER_H

#include <atomic>
#include <pcap/pcap.h>

enum SnifferType
{
    ST_EXT = 0,
    ST_INT
};

class Sniffer
{
public:
    Sniffer(const char* iface_name, SnifferType type, size_t bridge_id,
        std::atomic_ullong& pkt_counter_);

    ~Sniffer();

    void set_dst(Sniffer* s)
    { dst = s; }

    SnifferType get_type() const
    { return tp; }

    bool open_live();
    void sniff();

private:
    void dispatch(const struct pcap_pkthdr*, const u_char*);
    void accept_pkt(const u_char*, unsigned);

private:
    const char* iface;
    SnifferType tp;
    size_t id;
    std::atomic_ullong& pkt_counter;

    pcap_t* handle = nullptr;
    Sniffer* dst = nullptr;

};

#endif // SNIFFER_H


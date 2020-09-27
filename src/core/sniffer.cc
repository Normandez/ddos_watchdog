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
// sniffer.cc author Oleksandr Serhiienko <sergienko.9711@gmail.com>

#include "sniffer.h"

#include "detector_manager.h"
#include "logger.h"
#include "net_defines.h"
#include "thread_context.h"

Sniffer::Sniffer(const char* iface_name, SnifferType type, size_t bridge_id,
    std::atomic_ullong& pkt_counter_)
    : iface(iface_name),
      tp(type),
      id(bridge_id),
      pkt_counter(pkt_counter_)
{

}

Sniffer::~Sniffer()
{
    pcap_close(handle);
}

bool Sniffer::open_live()
{
    char err_buf[PCAP_ERRBUF_SIZE];
    const char* dev = iface;

    // FIXIT: maybe we don't need promiscuous mode is set
    handle = pcap_open_live(dev, BUFSIZ, 1, 1, err_buf);
    if ( !handle )
    {
        Logger::error("couldn't open device: %s: %s", dev, err_buf);
        return false;
    }
    if ( pcap_setnonblock(handle, 1, err_buf) )
    {
        Logger::error("couldn't set non-block state for device: %s: %s", dev, err_buf);
        return false;
    }
    if ( pcap_setdirection(handle, PCAP_D_IN) == PCAP_ERROR )
    {
        Logger::error("couldn't set direction for device: %s: %s", dev, pcap_geterr(handle));
        return false;
    }

    Logger::log("device opened: %s", dev);

    return true;
}

void Sniffer::sniff()
{
    while ( ThreadContext::get_state(id) == TS_RUNNING )
    {
        struct pcap_pkthdr frame_hdr;
        if ( const u_char* frame = pcap_next(handle, &frame_hdr) )
        {
            dispatch(&frame_hdr, frame);
        }
    }
}

void Sniffer::dispatch(const struct pcap_pkthdr* frame_hdr, const u_char* frame)
{
    const unsigned int frame_len = frame_hdr->len;
    
    const unsigned long long pkt_num = ++pkt_counter;
    const PktDirection dir = ( tp == ST_EXT ) ? EXT_TO_INT : INT_TO_EXT;
    if ( DetectorManager::execute(frame, frame_len, pkt_num, dir, id) )
        dst->accept_pkt(frame, frame_len);
}

void Sniffer::accept_pkt(const u_char* frame, unsigned frame_len)
{
    if ( pcap_inject(handle, frame, frame_len) == PCAP_ERROR )
    {
        Logger::error("bridge #%zu: sniffer type %s: iface %s: %s", id,
            ( tp ? "internal" : "external" ), iface, pcap_geterr(handle));

        ThreadContext::set_state(id, TS_TERMINATED);
    }
}


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
// inline_set.cc author Oleksandr Serhiienko <sergienko.9711@gmail.com>

#include "inline_set.h"

#include "detector_manager.h"
#include "logger.h"
#include "sniffer.h"
#include "thread_context.h"

// Inline sets

InlineSet::InlineSet(const char* ext_iface, const char* int_iface, size_t bridge_id,
    std::atomic_ullong& pkt_counter)
    : id(bridge_id)
{
    ext_sniffer = new Sniffer(ext_iface, SnifferType::ST_EXT, bridge_id, pkt_counter);
    int_sniffer = new Sniffer(int_iface, SnifferType::ST_INT, bridge_id, pkt_counter);

    ext_sniffer->set_dst(int_sniffer);
    int_sniffer->set_dst(ext_sniffer);
}

InlineSet::~InlineSet()
{
    delete ext_sniffer;
    delete int_sniffer;
}

bool InlineSet::open()
{
    if ( !ext_sniffer->open_live() or !int_sniffer->open_live() )
        return false;

    return true;
}

class ExtToInt : public InlineSet
{
public:
    ExtToInt(const char* ext_iface, const char* int_iface, size_t bridge_id,
        std::atomic_ullong& pkt_counter)
        : InlineSet(ext_iface, int_iface, bridge_id, pkt_counter)
    { }
    ~ExtToInt() { }

    void live() override;

};

void ExtToInt::live()
{
    DetectorManager::init_pipeline();
    Logger::msg("Detectors initialized: bridge #%zu(ext->int): count %zu:%s", id,
        DetectorManager::get_pipeline_len(), DetectorManager::get_pipeline_names().c_str());

    ext_sniffer->sniff();
    DetectorManager::cleanup_pipeline();
}

class IntToExt : public InlineSet
{
public:
    IntToExt(const char* ext_iface, const char* int_iface, size_t bridge_id,
        std::atomic_ullong& pkt_counter)
        : InlineSet(ext_iface, int_iface, bridge_id, pkt_counter)
    { }
    ~IntToExt() { }

    void live() override;

};

void IntToExt::live()
{
    int_sniffer->sniff();
}

// Live bridge

LiveBridge::LiveBridge(const char* ext_iface, const char* int_iface, int bridge_id)
    : id(bridge_id)
{
    ext_to_int = new ExtToInt(ext_iface, int_iface, bridge_id, pkt_counter);
    int_to_ext = new IntToExt(ext_iface, int_iface, bridge_id, pkt_counter);
}

LiveBridge::~LiveBridge()
{
    delete ext_to_int;
    delete int_to_ext;

    delete etoi;
    delete itoe;
}

bool LiveBridge::open()
{
    Logger::log("openning bridge: #%zu", id);
    if ( !ext_to_int->open() or !int_to_ext->open() )
    {
        Logger::error("couldn't open bridge: #%zu", id);
        return false;
    }

    Logger::log("bridge opened: #%zu", id);
    return true;
}

void LiveBridge::live()
{
    ThreadContext::set_state(id, TS_RUNNING);

    etoi = new std::thread(&InlineSet::live, ext_to_int);
    itoe = new std::thread(&InlineSet::live, int_to_ext);

    etoi->detach();
    itoe->detach();
}


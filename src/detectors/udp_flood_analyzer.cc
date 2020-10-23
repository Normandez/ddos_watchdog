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
// udp_flood_analyzer.cc author Oleksandr Serhiienko <sergienko.9711@gmail.com>

#include "udp_flood_analyzer.h"

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "core/logger.h"

#define DEFAULT_TIME_WINDOW 2    // in seconds
#define DEFAULT_THRESHOLD_PKT_NUM 30
#define DEFAULT_ACTION_TYPE UdpFloodAnalyzer::ActionType::ALERT

UdpFloodAnalyzer::UdpFloodAnalyzer(const int time_window, const long threshold,
    const std::string& _action_type)
    : Detector(udp_flood_analyzer_name),
      analyze_time_window(( time_window > 0 ) ? time_window : DEFAULT_TIME_WINDOW),
      threshold_pkt_num(( threshold > 0 ) ? threshold : DEFAULT_THRESHOLD_PKT_NUM),
      evaluation_thrd(&UdpFloodAnalyzer::evaluate, this)
{
    if ( _action_type == "alert" )
        action_type = ALERT;
    else if ( _action_type == "block" )
        action_type = BLOCK;
    else
        action_type = DEFAULT_ACTION_TYPE;

    evaluation_thrd.detach();
}

bool UdpFloodAnalyzer::analyze(const u_char* pkt, const unsigned int,
    const unsigned long long, const PktDirection, const size_t)
{
    const ether_header* ethr_frame = (const ether_header*)pkt;
    uint16_t eth_type = ntohs(ethr_frame->ether_type);

    if ( eth_type == ETHERTYPE_IP )
    {
        const ip* ip_hdr = (const ip*)(pkt + ETHER_HDR_LEN);
        if ( ip_hdr->ip_p == IPPROTO_UDP )
        {
            const udphdr* udp = (const udphdr*)(pkt + ETHER_HDR_LEN
                + (ip_hdr->ip_hl * BYTES_IN_OCTET));

            const uint32_t ip = ip_hdr->ip_src.s_addr;
            const uint16_t port = udp->source;

            if ( is_blocked(ip, port) )
                return false;

            insert_udp(ip, port, udp->check);
        }
    }

    return true;
}

bool UdpFloodAnalyzer::is_blocked(const uint32_t ip, const uint16_t port)
{
    const auto& it_pair = blocked_udp.equal_range(ip);
    for ( auto it = it_pair.first; it != it_pair.second; it++ )
    {
        if ( it->second == port )
            return true;
    }

    return false;
}

void UdpFloodAnalyzer::insert_udp(const uint32_t ip, const uint16_t port, const uint16_t checksum)
{
    bool is_same_checksum = false;

    if ( !mtx.try_lock() )
        return;

    // Insert and analyze checksum
    if ( checksum_dict.count(ip) != 0 )
    {
        auto& flow = checksum_dict[ip];
        if ( flow.count(port) != 0 )
            is_same_checksum = ( flow[port] == checksum );

        flow[port] = checksum;
    }
    else
        checksum_dict[ip][port] = checksum;

    // Insert UDP flow
    if ( is_same_checksum )
    {
        if ( udp_flow_dict.count(ip) != 0 )
        {
            auto& flow = udp_flow_dict[ip];
            if ( flow.count(port) != 0 )
                flow[port]++;
            else
                flow[port] = 1;
        }
        else
            udp_flow_dict[ip][port] = 1;
    }

    mtx.unlock();
}

void UdpFloodAnalyzer::clear_dict()
{
    std::lock_guard<std::mutex> lock(mtx);
    udp_flow_dict.clear();
    checksum_dict.clear();
}

void UdpFloodAnalyzer::evaluate()
{
    while ( true )
    {
        std::this_thread::sleep_for(std::chrono::seconds(analyze_time_window));
        detect_anomaly();
        clear_dict();
    }
}

void UdpFloodAnalyzer::detect_anomaly()
{
    UdpFlowDict udp_dict = udp_flow_dict;
    for ( const auto& flow : udp_dict )
    {
        for ( const auto& port : flow.second )
        {
            if ( port.second >= threshold_pkt_num )
                action(flow.first, port.first);
        }
    }
}

void UdpFloodAnalyzer::action(const uint32_t ip, const uint16_t port)
{
    switch ( action_type )
    {
    case ALERT:
        alert(ip, port);
    break;
    case BLOCK:
        block(ip, port);
    break;
    }
}

void UdpFloodAnalyzer::alert(uint32_t ip, const uint16_t port)
{
    Logger::msg("UDP_FLOOD: ANOMALY DETECTED, IP %s, PORT %d", inet_ntoa(in_addr({ip})), ntohs(port));
}

void UdpFloodAnalyzer::block(const uint32_t ip, const uint16_t port)
{
    blocked_udp.insert(std::make_pair<uint32_t, uint16_t>((uint32_t)ip, (uint16_t)port));
    Logger::msg("UDP_FLOOD: ANOMALY BLOCKED, IP %s, PORT %d", inet_ntoa(in_addr({ip})), ntohs(port));
}


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
// ip_flood_analyzer.cc author Oleksandr Serhiienko <sergienko.9711@gmail.com>

#include "ip_flood_analyzer.h"

#include <cmath>

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>

#include "core/logger.h"

#define DEFAULT_TIME_WINDOW 2   // in seconds
#define DEFAULT_THRESHOLD_VECTOR_SIZE 15
#define DEFAULT_ENTROPY_THRESHOLD 2.0

#define START_VECTOR_POS 0
#define THRESHOLD_LOW_BORDER -1
#define THRESHOLD_TOP_BORDER 1

IpFloodAnalyzer::IpFloodAnalyzer(int time_window, short vector_size, float threshold)
    : Detector(ip_flood_analyzer_name),
      vector_pos(START_VECTOR_POS),
      pkt_count(0),
      evaluation_thrd(&IpFloodAnalyzer::evaluate, this)
{
    analyze_time_window = ( time_window > 0 ) ? time_window : DEFAULT_TIME_WINDOW;
    threshold_vec_size = ( vector_size > 0 ) ? vector_size : DEFAULT_THRESHOLD_VECTOR_SIZE;
    entropy_threshold = ( threshold > 0.0 ) ? threshold : DEFAULT_ENTROPY_THRESHOLD;

    threshold_vec.reserve(threshold_vec_size);
    threshold_vec.assign(threshold_vec_size, THRESHOLD_LOW_BORDER);

    evaluation_thrd.detach();
}

bool IpFloodAnalyzer::analyze(const u_char* pkt, const unsigned int,
    const unsigned long long, const PktDirection, const size_t)
{
    const ether_header* ethr_frame = (const ether_header*)pkt;
    uint16_t eth_type = ntohs(ethr_frame->ether_type);

    if ( eth_type == ETHERTYPE_IP )
    {
        const ip* ip_pkt = (const ip*)(pkt + ETHER_HDR_LEN);
        insert_ip(ip_pkt->ip_src.s_addr);
    }

    return true;
}

void IpFloodAnalyzer::insert_ip(uint32_t ip)
{
    if ( mtx.try_lock() )
    {
        pkt_count++;
        if ( ip_dict.count(ip) != 0 )
            ip_dict[ip]++;
        else
            ip_dict[ip] = 1;

        mtx.unlock();
    }
}

void IpFloodAnalyzer::clear_dict()
{
    std::lock_guard<std::mutex> lock(mtx);
    ip_dict.clear();
    pkt_count = 0;
}

void IpFloodAnalyzer::evaluate_entropy()
{
    long long total_count = pkt_count;
    IpDict dict = ip_dict;

    if ( total_count == 0 )
        return;

    float entropy = 0.0;
    for ( const auto& ip : dict )
    {
        float ip_prob = (float)ip.second / (float)total_count;
        entropy += -(ip_prob * log2(ip_prob));
    }

    bool thresholded = entropy > entropy_threshold;
    auto& value = threshold_vec[vector_pos];
    if ( thresholded and value != THRESHOLD_TOP_BORDER )
        value++;
    else if ( !thresholded and value != THRESHOLD_LOW_BORDER )
        value--;
}

void IpFloodAnalyzer::detect_anomaly()
{
    short anomaly_count = 0;
    for ( auto& v : threshold_vec )
    {
        if ( v == THRESHOLD_TOP_BORDER )
            anomaly_count++;
    }
    if ( anomaly_count == threshold_vec_size )
        Logger::msg("IP_FLOOD: ANOMALY DETECTED!");
}

void IpFloodAnalyzer::evaluate()
{
    while ( true )
    {
        while ( vector_pos < threshold_vec_size )
        {
            std::this_thread::sleep_for(std::chrono::seconds(analyze_time_window));

            evaluate_entropy();
            clear_dict();

            vector_pos++;
        }

        detect_anomaly();
        vector_pos = START_VECTOR_POS;
    }
}


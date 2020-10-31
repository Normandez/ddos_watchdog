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
// udp_flood_analyzer.h author Oleksandr Serhiienko <sergienko.9711@gmail.com>

#ifndef UDP_FLOOD_ANALYZER_H
#define UDP_FLOOD_ANALYZER_H

#include <mutex>
#include <thread>
#include <unordered_map>

#include "detector.h"

#define udp_flood_analyzer_name "udp_flood_analyzer"

class UdpFloodAnalyzer : public Detector
{
public:
    enum ActionType
    {
        ALERT = 0,
        BLOCK
    };

public:
    UdpFloodAnalyzer(const int time_window, const long threshold, const std::string& action_type);
    ~UdpFloodAnalyzer() = default;

    bool analyze(const u_char* pkt, const unsigned int pkt_len,
        const unsigned long long pkt_num, const PktDirection dir, const size_t bridge_id) override;

private:
    bool is_blocked(const uint32_t ip, const uint16_t port);
    void insert_udp(const uint32_t ip, const uint16_t port, const uint16_t checksum);
    void clear_dict();

    void evaluate();
    void detect_anomaly();

    void action(const uint32_t ip, const uint16_t port);
    void alert(const uint32_t ip, const uint16_t port);
    void block(const uint32_t ip, const uint16_t port);

private:
    // <IP-address, <PORT, emergence count>>
    using UdpFlowDict = std::unordered_map<uint32_t, std::unordered_map<uint16_t, unsigned long>>;
    // <IP-address, <PORT, previous checksum hash>>
    using UdpCheckSumDict = std::unordered_map<uint32_t, std::unordered_map<uint16_t, uint16_t>>;
    // <IP-address, PORT>
    using UdpBlockedMap = std::unordered_multimap<uint32_t, uint16_t>;

    UdpFlowDict udp_flow_dict;
    UdpCheckSumDict checksum_dict;
    UdpBlockedMap blocked_udp;
    const long threshold_pkt_num;
    const int analyze_time_window;    // in seconds
    ActionType action_type;

    std::mutex mtx;
    std::thread evaluation_thrd;
};

#endif // UDP_FLOOD_ANALYZER_H


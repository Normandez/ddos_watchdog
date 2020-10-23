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
// ip_flood_analyzer.h author Oleksandr Serhiienko <sergienko.9711@gmail.com>

#ifndef IP_FLOOD_ANALYZER_H
#define IP_FLOOD_ANALYZER_H

#include "detector.h"

#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

#define ip_flood_analyzer_name "ip_flood_analyzer"

class IpFloodAnalyzer : public Detector
{
public:
    IpFloodAnalyzer(int time_window, short vector_size, float threshold);
    ~IpFloodAnalyzer() = default;

    bool analyze(const u_char* pkt, const unsigned int pkt_len,
        const unsigned long long pkt_num, const PktDirection dir, const size_t bridge_id) override;

private:
    void insert_ip(uint32_t ip);
    void clear_dict();

    void evaluate_entropy();

    void evaluate();
    void detect_anomaly();

private:
    // <IP adress, emergence count>
    using IpDict = std::unordered_map<uint32_t, long long>;

    IpDict ip_dict;
    std::vector<short> threshold_vec;
    int analyze_time_window;    // in seconds
    short threshold_vec_size;

    short vector_pos;
    long long pkt_count;

    float entropy_threshold;

    std::mutex mtx;
    std::thread evaluation_thrd;
};

#endif // IP_FLOOD_ANALYZER_H


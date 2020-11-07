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
// config.h author Oleksandr Serhiienko <sergienko.9711@gmail.com>

#ifndef CONFIG_H
#define CONFIG_H

#include <string>

struct Config
{
public:
    Config() = default;
    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;

    static Config* get_instance()
    {
        static Config conf;
        return &conf;
    }

public:
    bool load_config(const char* file_name);

public:
    std::string int_iface;
    std::string ext_iface;
    std::string detectors;

    // network_analyzer config
    int max_print_threads = 0;

    // ip_flood_analyzer config
    int analyze_time_window_ip = 0;        // in seconds
    short threshold_vector_size = 0;
    float entropy_threshold = 0.0;

    // udp_flood_analyzer config
    int analyze_time_window_udp = 0;    // in seconds
    long threshold_pkt_num = 0;
    std::string action_type = "";       // "alert"|"block"

};

#endif // CONFIG_H


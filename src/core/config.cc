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
// config.cc author Oleksandr Serhiienko <sergienko.9711@gmail.com>

#include "config.h"

#include <fstream>

#include "logger.h"

// Commmon config
static const std::string int_iface_conf_key = "INT_IFACE=";
static const std::string ext_iface_conf_key = "EXT_IFACE=";
static const std::string detectors_key = "DETECTORS=";

// NetworkAnalyzer config
static const std::string max_print_threads_key = "MAX_PRINT_THREADS=";

// IpFloodAnalyzer config
static const std::string analyze_time_window_ip_key = "ANALYZE_TIME_WINDOW_IP=";
static const std::string threshold_vector_size_key = "THRESHOLD_VECTOR_SIZE=";
static const std::string entropy_threshold_key = "ENTROPY_THRESHOLD=";

// UdpFloodAnalyzer config
static const std::string analyze_time_window_udp_key = "ANALYZE_TIME_WINDOW_UDP=";
static const std::string threshold_pkt_num_key = "THRESHOLD_PKT_NUM=";
static const std::string action_type_key = "ACTION_TYPE=";

bool Config::load_config(const char* file_name)
{
    std::ifstream file;
    file.open(file_name);

    if ( !file.is_open() )
    {
        Logger::error("can't open config file: %s", file_name);
        return false;
    }

    std::string buf = "";
    while ( file >> buf )
    {
        if( buf.find(int_iface_conf_key) != std::string::npos )
            int_iface = buf.substr(int_iface_conf_key.size());
        else if ( buf.find(ext_iface_conf_key) != std::string::npos )
            ext_iface = buf.substr(ext_iface_conf_key.size());
        else if ( buf.find(detectors_key) != std::string::npos )
            detectors = buf.substr(detectors_key.size());
        else if ( buf.find(max_print_threads_key) != std::string::npos )
            max_print_threads = std::stoi(buf.substr(max_print_threads_key.size()));
        else if ( buf.find(analyze_time_window_ip_key) != std::string::npos )
            analyze_time_window_ip = std::stoi(buf.substr(analyze_time_window_ip_key.size()));
        else if ( buf.find(threshold_vector_size_key) != std::string::npos )
            threshold_vector_size = std::stoi(buf.substr(threshold_vector_size_key.size()));
        else if ( buf.find(entropy_threshold_key) != std::string::npos )
            entropy_threshold = std::stof(buf.substr(entropy_threshold_key.size()));
        else if ( buf.find(analyze_time_window_udp_key) != std::string::npos )
            analyze_time_window_udp = std::stoi(buf.substr(analyze_time_window_udp_key.size()));
        else if ( buf.find(threshold_pkt_num_key) != std::string::npos )
            threshold_pkt_num = std::stol(buf.substr(threshold_pkt_num_key.size()));
        else if ( buf.find(action_type_key) != std::string::npos )
            action_type = buf.substr(action_type_key.size());
    }

    file.close();
    Logger::log("config file loaded: %s", file_name);

    return true;
}


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
// detector_manager.cc author Oleksandr Serhiienko <sergienko.9711@gmail.com>

#include "detector_manager.h"

#include <list>

#include "detectors/detector.h"
#include "detectors/network_analyzer.h"
#include "detectors/ip_flood_analyzer.h"
#include "detectors/udp_flood_analyzer.h"

#include "config.h"

thread_local std::list<Detector*> s_detectors;

void DetectorManager::init_pipeline(const size_t bridge_id, const PktDirection dir)
{
    Config* conf = Config::get_instance();

    if ( conf->detectors.find(udp_flood_analyzer_name) != std::string::npos )
    {
        s_detectors.push_back(
            new UdpFloodAnalyzer(bridge_id, dir, conf->analyze_time_window_udp,
                conf->threshold_pkt_num, conf->action_type));
    }

    if ( conf->detectors.find(ip_flood_analyzer_name) != std::string::npos )
    {
        s_detectors.push_back(
            new IpFloodAnalyzer(bridge_id, dir, conf->analyze_time_window_ip,
                conf->threshold_vector_size, conf->entropy_threshold));
    }

    if ( conf->detectors.find(network_analyzer_name) != std::string::npos )
        s_detectors.push_back(new NetworkAnalyzer(bridge_id, dir, conf->max_print_threads));
}

void DetectorManager::cleanup_pipeline()
{
    for ( auto detector : s_detectors )
        delete detector;
}

bool DetectorManager::execute(const u_char* pkt, const unsigned int pkt_len,
    const unsigned long long pkt_num)
{
    for ( auto& detector : s_detectors )
    {
        if ( !detector->analyze(pkt, pkt_len, pkt_num) )
            return false;
    }

    return true;
}

size_t DetectorManager::get_pipeline_len()
{ return s_detectors.size(); }

std::string DetectorManager::get_pipeline_names()
{
    std::string list_names = " ";
    for ( auto& detector : s_detectors )
    {
        std::string name = detector->get_name();
        name += " ";
        list_names.append(name);
    }

    return list_names;
}


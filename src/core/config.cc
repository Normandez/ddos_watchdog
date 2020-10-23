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

static const std::string int_iface_conf_key = "INT_IFACE=";
static const std::string ext_iface_conf_key = "EXT_IFACE=";
static const std::string detectors_key = "DETECTORS=";
static const std::string analyse_time_window_key = "ANALYSE_TIME_WINDOW=";
static const std::string threshold_vector_size_key = "THRESHOLD_VECTOR_SIZE=";
static const std::string entropy_threshold_key = "ENTROPY_THRESHOLD=";

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
        else if ( buf.find(analyse_time_window_key) != std::string::npos )
            analyse_time_window = std::stoi(buf.substr(analyse_time_window_key.size()));
        else if ( buf.find(threshold_vector_size_key) != std::string::npos )
            threshold_vector_size = std::stoi(buf.substr(threshold_vector_size_key.size()));
        else if ( buf.find(entropy_threshold_key) != std::string::npos )
            entropy_threshold = std::stof(buf.substr(entropy_threshold_key.size()));
    }

    file.close();
    Logger::log("config file loaded: %s", file_name);

    return true;
}


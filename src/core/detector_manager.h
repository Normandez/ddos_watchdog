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
// detector_manager.h author Oleksandr Serhiienko <sergienko.9711@gmail.com>

#ifndef DETECTOR_MANAGER_H
#define DETECTOR_MANAGER_H

#include <string>
#include <sys/types.h>

#include "net_defines.h"

class DetectorManager
{
public:
    static void init_pipeline(const size_t bridge_id, const PktDirection dir);
    static void cleanup_pipeline();

    static bool execute(const u_char* pkt, const unsigned int pkt_len,
        const unsigned long long pkt_num);

    static size_t get_pipeline_len();
    static std::string get_pipeline_names();

};

#endif // DETECTOR_MANAGER_H


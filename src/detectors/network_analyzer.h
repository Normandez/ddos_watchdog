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
// network_analyzer.h author Oleksandr Serhiienko <sergienko.9711@gmail.com>

#ifndef NETWORK_ANALYZER_H
#define NETWORK_ANALYZER_H

#include "detector.h"

#define network_analyzer_name "network_analyzer"

class NetworkAnalyzer : public Detector
{
public:
    NetworkAnalyzer(const size_t bridge_id, const PktDirection dir)
        : Detector(network_analyzer_name, bridge_id, dir)
    { }
    ~NetworkAnalyzer() = default;

    bool analyze(const u_char* pkt, const unsigned int pkt_len,
        const unsigned long long pkt_num) override;

};

#endif // NETWORK_ANALYZER_H


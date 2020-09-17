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

thread_local std::list<Detector*> s_detectors;

void DetectorManager::init_pipeline()
{

}

void DetectorManager::cleanup_pipeline()
{

}

bool DetectorManager::execute(const u_char* pkt, const unsigned int pkt_len)
{
    for ( auto& detector : s_detectors )
    {
        if ( !detector->analyze(pkt, pkt_len) )
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
        list_names.append(detector->get_name());

    return list_names;
}


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
// logger.cc author Oleksandr Serhiienko <sergienko.9711@gmail.com>

#include "logger.h"

#include <cstdarg>
#include <cstdio>
#include <string>

#define STD_BUF_SIZE 1024

static void printout(FILE* out, const char* fmt, va_list ap)
{
    char buf[STD_BUF_SIZE];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    fputs(buf, out);
}

void Logger::msg(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    std::string l_fmt = fmt;
    l_fmt += "\n";

    printout(stdout, l_fmt.c_str(), ap);

    va_end(ap);
}

void Logger::log(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    std::string l_fmt = "LOG: ";
    l_fmt += fmt;
    l_fmt += "\n";

    printout(stdout, l_fmt.c_str(), ap);

    va_end(ap);
}

void Logger::error(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    std::string l_fmt = "ERROR: ";
    l_fmt += fmt;
    l_fmt += "\n";

    printout(stderr, l_fmt.c_str(), ap);

    va_end(ap);
}


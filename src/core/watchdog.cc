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
// watchdog.cc author Oleksandr Serhiienko <sergienko.9711@gmail.com>

#include "watchdog.h"

#include <cstring>
#include <thread>

#include "config.h"
#include "logger.h"
#include "thread_control.h"

// FIXIT: make this dynamic
#define NUM_OF_BRIDGES 1

Watchdog::~Watchdog()
{
    delete control;
}

// FIXIT: refactor this into separate help component
#define CLI_HELP "USAGE: watchdog -c <config_file.env> [--help]"

bool Watchdog::init(int argc, char* argv[])
{
    bool parse_err = false;
    bool conf_loaded = false;

    for ( int opt = 1, par_val = 0; opt < argc; ++opt )
    {
        if ( !strcmp(argv[opt], "-c") and ( opt + 1 ) < argc )
        {
            conf_loaded = Config::get_instance()->load_config(argv[opt + 1]);
            ++par_val;

            continue;
        }
        else if ( !strcmp(argv[opt], "--help") )
        {
            Logger::msg(CLI_HELP);
            exit(0);
        }
        else if ( !par_val )
        {
            Logger::error("invalid CLI option provided: %s", argv[opt]);
            parse_err = true;
        }

        --par_val;
    }

    if ( parse_err )
        Logger::msg("run with '--help' to see available arguments");

    if ( !conf_loaded and !parse_err )
        Logger::error("config file not loaded");

    return !parse_err and conf_loaded;
}

bool Watchdog::init_live_bridges()
{
    control = new ThreadControl(NUM_OF_BRIDGES);

    if ( !control->open_bridges() )
        return false;

    Logger::log("live bridges initialized");
    return true;
}

int Watchdog::exec()
{
    control->start_live();
    Logger::msg("Watchdog is online\nYour network is under defense now");
    while ( true )
    {
        if ( !control->is_ok() )
        {
            control->stop_all();
            return 5;
        }

        // Iteration timeout 1 sec
        std::chrono::seconds sec(1);
        std::this_thread::sleep_for(sec);
    }
    return 0;
}


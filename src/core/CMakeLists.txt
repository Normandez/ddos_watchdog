set ( CORE_SOURCES
    config.cc
    config.h
    detector_manager.cc
    detector_manager.h
    inline_set.cc
    inline_set.h
    logger.cc
    logger.h
    net_defines.h
    sniffer.cc
    sniffer.h
    thread_context.cc
    thread_context.h
    thread_control.cc
    thread_control.h
    watchdog.cc
    watchdog.h
)

add_library ( core OBJECT
    ${CORE_SOURCES}
)


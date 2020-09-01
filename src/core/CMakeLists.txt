set ( CORE_SOURCES
    config.cc
    config.h
    logger.cc
    logger.h
    watchdog.cc
    watchdog.h
)

add_library ( core OBJECT
    ${CORE_SOURCES}
)


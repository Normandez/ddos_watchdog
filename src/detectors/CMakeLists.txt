set ( DETECTORS_SOURCES
    detector.h
    network_analyzer.cc
    network_analyzer.h
)

add_library ( detectors OBJECT
    ${DETECTORS_SOURCES}
)


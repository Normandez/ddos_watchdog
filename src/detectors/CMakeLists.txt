set ( DETECTORS_SOURCES
    detector.h
    ip_flood_analyzer.cc
    ip_flood_analyzer.h
    network_analyzer.cc
    network_analyzer.h
    udp_flood_analyzer.cc
    udp_flood_analyzer.h
)

add_library ( detectors OBJECT
    ${DETECTORS_SOURCES}
)


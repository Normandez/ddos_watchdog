set ( EXTERNAL_LIBRARIES ${PCAP_LIBRARIES} )
set ( EXTERNAL_INCLUDES ${PCAP_INCLUDE_DIR} )

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(core)
add_subdirectory(detectors)

add_executable( watchdog
    main.cc
    $<TARGET_OBJECTS:core>
    $<TARGET_OBJECTS:detectors>
)

target_link_libraries( watchdog
    ${EXTERNAL_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
)

install (TARGETS watchdog
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)


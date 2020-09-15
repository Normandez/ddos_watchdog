set ( EXTERNAL_LIBRARIES ${PCAP_LIBRARIES} )
set ( EXTERNAL_INCLUDES ${PCAP_INCLUDE_DIR} )

add_subdirectory(core)

add_executable( watchdog
    main.cc
    $<TARGET_OBJECTS:core>
)

target_link_libraries( watchdog
    ${EXTERNAL_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
)

install (TARGETS watchdog
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)


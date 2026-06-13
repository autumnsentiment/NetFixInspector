cmake_minimum_required(VERSION 3.20)

project(NetFixInspectorCpp VERSION 1.0.0 LANGUAGES CXX)

option(NETFIX_WITH_NPCAP "Deprecated: Npcap is now loaded dynamically at runtime" OFF)
set(NPCAP_ROOT "" CACHE PATH "Npcap SDK root directory")

add_executable(NetFixInspector
    src/main.cpp
    src/cli.cpp
    src/report.cpp
    src/net_win.cpp
    src/probe.cpp
    src/pcap_checks.cpp
)

target_compile_features(NetFixInspector PRIVATE cxx_std_17)
target_include_directories(NetFixInspector PRIVATE include)
target_compile_definitions(NetFixInspector PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _WIN32_WINNT=0x0A00
    NTDDI_VERSION=0x0A000000
    NETFIX_VERSION_TEXT="${PROJECT_VERSION}"
)

if(MSVC)
    target_compile_options(NetFixInspector PRIVATE /W4 /permissive- /EHsc)
    target_link_options(NetFixInspector PRIVATE /ENTRY:wmainCRTStartup)
else()
    target_compile_options(NetFixInspector PRIVATE -Wall -Wextra -Wpedantic)
endif()

target_link_libraries(NetFixInspector PRIVATE
    Ws2_32
    Iphlpapi
    Winhttp
)

if(NETFIX_WITH_NPCAP)
    message(STATUS "NETFIX_WITH_NPCAP is no longer required; this build loads Npcap/wpcap.dll dynamically at runtime.")
endif()

set_target_properties(NetFixInspector PROPERTIES
    OUTPUT_NAME "NetFixInspector"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/dist"
)

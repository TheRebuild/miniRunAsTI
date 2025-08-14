cmake_minimum_required(VERSION 3.20)
project(miniRunAsTI VERSION 0.0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

set(SOURCES
        src/main.cpp
        src/utils.cpp
        src/execution.cpp
        src/loader.cpp
)
add_executable(${PROJECT_NAME} ${SOURCES})

configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/headers/version.h.in"
        "${CMAKE_CURRENT_BINARY_DIR}/version.h"
)

if (WIN32)
    target_precompile_headers(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/headers/pch.hpp)
endif ()

target_include_directories(${PROJECT_NAME} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/headers" "${CMAKE_CURRENT_BINARY_DIR}")

if (MSVC)
    target_compile_definitions(${PROJECT_NAME} PRIVATE
            UNICODE
            _UNICODE
    )

    target_compile_options(${PROJECT_NAME} PRIVATE /utf-8)
elseif (CMAKE_COMPILER_IS_GNUCXX)
    target_compile_definitions(${PROJECT_NAME} PRIVATE _WIN32_WINNT=0x0600)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++ -mconsole -municode")
endif ()

if (WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE
            user32
            shell32
            advapi32
            wtsapi32
    )
endif ()


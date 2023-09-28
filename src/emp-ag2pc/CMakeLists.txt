cmake_minimum_required (VERSION 2.8.11)
project (emp-ag2pc)
set(NAME "emp-ag2pc")

find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
include(${CMAKE_FOLDER}/cmake/emp-base.cmake)

FIND_PACKAGE(emp-ot REQUIRED)
INCLUDE_DIRECTORIES(${EMP-OT_INCLUDE_DIRS})

# Installation
install(FILES cmake/emp-ag2pc-config.cmake DESTINATION cmake/)
install(DIRECTORY emp-ag2pc DESTINATION include)

ENABLE_TESTING()
ADD_SUBDIRECTORY(test)

cmake_minimum_required(VERSION 2.8)
project(pam_memcached C)

if(CMAKE_BINARY_DIR STREQUAL ${CMAKE_SOURCE_DIR})
        message( FATAL_ERROR "Building in source dir prohibited. Remove CMakeCache.txt and try 'mkdir build && cd build && cmake ..'." )
endif()

if (NOT CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE EQUAL "")
    message(STATUS "No build type selected, default to RelWithDebInfo")
    set(CMAKE_BUILD_TYPE "RelWithDebInfo")
endif()

SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake/modules)

find_package(Libmemcached REQUIRED)
find_package(OpenSSL REQUIRED)

set(INCLUDES ${LIBMEMCACHED_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})

set(LIBS ${LIBMEMCACHED_LIBRARIES} ${OPENSSL_LIBRARIES})

set(SOURCES pam_memcached.c)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-function")
add_definitions(-D_GNU_SOURCE -DFORTIFY_SOURCE=2)

include_directories(${INCLUDES})

add_library(pam_memcached SHARED ${SOURCES})
set_target_properties(pam_memcached PROPERTIES PREFIX "")
target_link_libraries(pam_memcached ${LIBS})

install(TARGETS pam_memcached LIBRARY DESTINATION lib/security/)

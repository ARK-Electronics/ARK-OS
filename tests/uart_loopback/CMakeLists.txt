cmake_minimum_required(VERSION 3.10)
project(uart_loopback_test VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O2")

# Find required packages
find_package(Threads REQUIRED)

# Main executable
add_executable(uart_loopback_test
    src/main.cpp
)

target_link_libraries(uart_loopback_test
    PRIVATE
    Threads::Threads
)

# Install target
install(TARGETS uart_loopback_test
    RUNTIME DESTINATION bin
)

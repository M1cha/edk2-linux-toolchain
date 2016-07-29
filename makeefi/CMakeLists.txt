cmake_minimum_required(VERSION 2.8)
project(makeefi)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror -Wshadow -Os")

# dtbtool
add_executable(makeefi
    src/main.c
)
target_link_libraries(makeefi popt)

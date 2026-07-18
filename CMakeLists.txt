
cmake_minimum_required(VERSION 3.20)
project(CrownClownSpeed LANGUAGES CXX)

add_library(CrownClownSpeed SHARED CrownClownSpeed.cpp)

target_compile_features(CrownClownSpeed PRIVATE cxx_std_17)
target_compile_definitions(CrownClownSpeed PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(CrownClownSpeed PRIVATE winmm)

set_target_properties(CrownClownSpeed PROPERTIES
    OUTPUT_NAME "XINPUT9_1_0"
    PREFIX ""
)

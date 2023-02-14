# Copyright (c) 2023 Joel Winarske
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.24)
project(profiler_cli)

set(CMAKE_CXX_STANDARD 17)

find_package(PkgConfig REQUIRED)
pkg_check_modules(USB REQUIRED libusb-1.0)

set(CMAKE_THREAD_PREFER_PTHREAD ON)
include(FindThreads)

include_directories(${USB_INCLUDE_DIRS})

add_executable(profiler_cli main.cpp)
target_link_libraries(profiler_cli ${USB_LINK_LIBRARIES})
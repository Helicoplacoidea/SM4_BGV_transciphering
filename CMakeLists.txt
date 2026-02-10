# Copyright (C) 2019-2020 IBM Corp.
# This program is Licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
#   http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License. See accompanying LICENSE file.

add_executable(BGV_sm4 BGV_sm4.cpp)
add_executable(BGV_sm4_noBT BGV_sm4_noBT.cpp)
add_executable(bench benchmark.cpp)

target_link_libraries(BGV_sm4 helib)
target_link_libraries(BGV_sm4_noBT helib)
target_link_libraries(bench helib)

find_package(OpenMP REQUIRED)
# 🔽 添加这行以链接 OpenMP
target_link_libraries(BGV_sm4 OpenMP::OpenMP_CXX)
target_link_libraries(bench OpenMP::OpenMP_CXX)

target_compile_options(BGV_sm4 PRIVATE -O3 -DNDEBUG)
target_compile_options(BGV_sm4_noBT PRIVATE -O3 -DNDEBUG)
target_compile_options(bench PRIVATE -O3 -DNDEBUG)

# find_package(HEXL 1.2.6
#     REQUIRED)

# target_link_libraries(BGV_sm4 HEXL::hexl)
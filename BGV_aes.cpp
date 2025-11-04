/* Copyright (C) 2019-2021 IBM Corp.
 * This program is Licensed under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. See accompanying LICENSE file.
 */

// This is a sample program for education purposes only.
// It attempts to show the various basic mathematical
// operations that can be performed on both ciphertexts
// and plaintexts.

#include <iostream>
#include <chrono>

#include <helib/helib.h>
#include <helib/binaryArith.h>
#include <helib/intraSlot.h>
#include <helib/zzX.h>
#include <NTL/vector.h>
#include <span>
#include <omp.h>

uint8_t SM4_SBOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2,
    0x28, 0xfb, 0x2c, 0x05, 0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
    0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9c, 0x42, 0x50, 0xf4,
    0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa,
    0x75, 0x8f, 0x3f, 0xa6, 0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
    0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8, 0x68, 0x6b, 0x81, 0xb2,
    0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b,
    0x01, 0x21, 0x78, 0x87, 0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
    0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e, 0xea, 0xbf, 0x8a, 0xd2,
    0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30,
    0xf5, 0x8c, 0xb1, 0xe3, 0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
    0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f, 0xd5, 0xdb, 0x37, 0x45,
    0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41,
    0x1f, 0x10, 0x5a, 0xd8, 0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
    0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0, 0x89, 0x69, 0x97, 0x4a,
    0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e,
    0xd7, 0xcb, 0x39, 0x48};

char SBox0[255] = {
    0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1,
    0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1,
    1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0,
    0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1,
    0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1,
    0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1,
    1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1,
    0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0,
    1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0,
    1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0,
    1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0};
char SBox1[255] = {
    1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0,
    0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0,
    1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0,
    0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0,
    0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1,
    0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1,
    0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1,
    1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0,
    0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0};
char SBox2[255] = {
    1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0,
    1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1,
    0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1,
    1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0,
    0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1,
    1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1,
    0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0,
    1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1,
    1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0,
    0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1,
    1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0};
char SBox3[255] = {
    0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0,
    0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0,
    0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0,
    1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0,
    0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1,
    1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0,
    0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1,
    1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0,
    0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1,
    0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0,
    0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0};
char SBox4[255] = {
    0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0,
    0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0,
    0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0,
    1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1,
    0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1,
    1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1,
    1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1,
    0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0,
    1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0};
char SBox5[255] = {
    0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0,
    0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0,
    0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0,
    1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0,
    1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1,
    1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1,
    0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1,
    0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1,
    0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1,
    1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1,
    0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0};
char SBox6[255] = {
    1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1,
    1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0,
    0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0,
    1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0,
    1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1,
    1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1,
    0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1,
    1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0,
    1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0,
    0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0};
char SBox7[255] = {
    0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0,
    0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1,
    1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0,
    0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0,
    1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1,
    0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1,
    0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1,
    1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1,
    0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1,
    1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0};

std::vector<const char*> SBOX_TABLES =
    {SBox0, SBox1, SBox2, SBox3, SBox4, SBox5, SBox6, SBox7};

char constants[8] = {0, 1, 1, 0, 1, 0, 1, 1};

int num = 0;

// 递归辅助函数
std::vector<helib::Ctxt> recurse(const std::vector<helib::Ctxt>& bits)
{
  if (bits.size() == 2) {
    helib::Ctxt tmp = bits[0];
    // tmp.multLowLvl(bits[1]);
    tmp.multiplyBy(bits[1]);
    num++;
    return {bits[0], bits[1], tmp};
  }

  size_t mid = bits.size() / 2;
  std::vector<helib::Ctxt> left(bits.begin(), bits.begin() + mid);
  std::vector<helib::Ctxt> right(bits.begin() + mid, bits.end());

  std::vector<helib::Ctxt> left_res = recurse(left);
  std::vector<helib::Ctxt> right_res = recurse(right);

  // std::cout << "test" << std::endl;

  std::vector<helib::Ctxt> combined;
  if (bits.size() == 4)
    for (helib::Ctxt l : left_res) {
      for (helib::Ctxt r : right_res) {
        helib::Ctxt tmp = l;

        tmp.multiplyBy(r);
        num++;
        combined.push_back(tmp);
      }
    }
  else
    for (helib::Ctxt l : left_res) {
      for (helib::Ctxt r : right_res) {
        helib::Ctxt tmp = l;

        tmp.multLowLvl(r);
        // num++;
        combined.push_back(tmp);
      }
    }
  // 拼接 combined + left + right
  combined.insert(combined.end(), left_res.begin(), left_res.end());
  combined.insert(combined.end(), right_res.begin(), right_res.end());
  // std::cout << "test" << std::endl;
  return combined;
}

// 主函数：输入长度为8的比特列表，输出255个monomial值
std::vector<helib::Ctxt> layered_combine_bin(
    const std::vector<helib::Ctxt>& bits)
{
  if (bits.size() != 8) {
    throw std::invalid_argument("Input must be 8 bits");
  }
  return recurse(bits);
}

// --- 生成递归 LayeredCombineBin 的 monomial bitmask 顺序 ---
std::vector<int> generate_bitmasks(const std::vector<int>& vars)
{
  if (vars.size() == 2) {
    return {vars[0], vars[1], vars[0] | vars[1]};
  }

  size_t mid = vars.size() / 2;
  std::vector<int> left(vars.begin(), vars.begin() + mid);
  std::vector<int> right(vars.begin() + mid, vars.end());

  std::vector<int> left_masks = generate_bitmasks(left);
  std::vector<int> right_masks = generate_bitmasks(right);

  std::vector<int> combined;
  for (int l : left_masks) {
    for (int r : right_masks) {
      combined.push_back(l | r);
    }
  }

  // 合并顺序：combined + left + right
  combined.insert(combined.end(), left_masks.begin(), left_masks.end());
  combined.insert(combined.end(), right_masks.begin(), right_masks.end());

  return combined;
}

std::vector<helib::Ctxt> reorder_to_bitmask_order(
    const std::vector<helib::Ctxt>& values)
{
  if (values.size() != 255) {
    throw std::invalid_argument(
        "Input must contain exactly 255 monomial values");
  }

  // 构造 bitmask 顺序（1 << i 表示 xi）
  std::vector<int> var_bitmasks;
  for (int i = 0; i < 8; ++i) {
    var_bitmasks.push_back(1 << i);
  }

  // 获取原始顺序对应的 bitmask 表达
  std::vector<int> original_order = generate_bitmasks(var_bitmasks);

  // 构建 bitmask -> 值 的映射
  std::unordered_map<int, helib::Ctxt> bitmask_to_value;
  for (size_t i = 0; i < 255; ++i) {
    bitmask_to_value.insert({original_order[i], values[i]});
  }

  // 重新按 bitmask 升序排列
  std::vector<int> sorted_bitmasks;
  for (const auto& [mask, _] : bitmask_to_value) {
    sorted_bitmasks.push_back(mask);
  }
  std::sort(sorted_bitmasks.begin(), sorted_bitmasks.end());

  // 输出按 bitmask 升序排列的 Ctxt 值
  std::vector<helib::Ctxt> reordered;
  for (int mask : sorted_bitmasks) {
    reordered.push_back(bitmask_to_value.at(mask));
  }

  return reordered;
}

helib::Ctxt sm4_SBoxLUT_bit(helib::Ctxt const_enc,
                            std::vector<helib::Ctxt>& monomials,
                            int index)
{
  const char* selected_sbox = SBOX_TABLES[index];

  helib::Ctxt ctmp = const_enc;
  ctmp *= (long)constants[index];

  for (int j = 0; j < monomials.size(); j++) {
    if (selected_sbox[j] == 0)
      continue;
    // helib::Ctxt tmp = monomials[j];             // 复制一个副本
    // tmp.multByConstant((long)selected_sbox[j]); // 原地乘常数
    // ctmp += tmp;                                // 累加到输出中
    ctmp += monomials[j];
  }
  return ctmp;
}

void sm4_SBoxLUT_byte(std::vector<helib::Ctxt>& bit,
                      helib::Ctxt ctmp,
                      std::vector<helib::Ctxt>& monomials)
{
  if (bit.size() != 8) {
    std::cout << "The input length of the Sbox is wrong (8bit)!!" << std::endl;
  };
#pragma omp parallel for
  for (int i = 0; i < 8; i++) {
    // printf("[OMP] Thread %d working on bit %d\n", omp_get_thread_num(), i);
    bit[i] = sm4_SBoxLUT_bit(ctmp, monomials, i);
    bit[i].reLinearize(); // <-- 重新线性化
  }
}

void SubByte(std::vector<helib::Ctxt>& tmp,
             const helib::PubKey& public_key,
             helib::Ctxt ctmp)
{
  std::vector<helib::Ctxt> monomials(255, helib::Ctxt(public_key));
  for (int i = 0; i < 4; i++) {
    std::vector<helib::Ctxt> bit(tmp.begin() + 8 * i,
                                 tmp.begin() + 8 * (i + 1));
    std::reverse(bit.begin(), bit.end()); // <-- 加这一行，改成大端顺序
    monomials = layered_combine_bin(bit);
    std::cout << "NUM:" << num << std::endl;
    num = 0;
    monomials = reorder_to_bitmask_order(monomials);
    sm4_SBoxLUT_byte(bit, ctmp, monomials);
    std::reverse(bit.begin(),
                 bit.end()); // <-- 加这一行，改成大端顺序
    std::copy(bit.begin(), bit.end(), tmp.begin() + 8 * i);
  }
}

void invertSingle(helib::Ctxt& ctxt)
{
  helib::Ctxt tmp1(ctxt);     // tmp1   = data[i] = X
  tmp1.frobeniusAutomorph(1); // tmp1   = X^2   after Z -> Z^2
  ctxt.multiplyBy(tmp1);      // data[i]= X^3
  helib::Ctxt tmp2(ctxt);     // tmp2   = X^3
  tmp2.frobeniusAutomorph(2); // tmp2   = X^12  after Z -> Z^4
  tmp1.multiplyBy(tmp2);      // tmp1   = X^14
  ctxt.multiplyBy(tmp2);      // data[i]= X^15
  ctxt.frobeniusAutomorph(4); // data[i]= X^240 after Z -> Z^16
  ctxt.multiplyBy(tmp1);      // data[i]= X^254
}

void sm4_L(std::vector<helib::Ctxt>& ctxt, const helib::PubKey& public_key)
{
  std::vector<helib::Ctxt> tmp(32, helib::Ctxt(public_key));

  for (int i = 0; i < 32; i++) {
    helib::Ctxt acc = ctxt[i]; // 👈 明确累加器
    acc += ctxt[(i + 2) % 32];
    acc += ctxt[(i + 10) % 32];
    acc += ctxt[(i + 18) % 32];
    acc += ctxt[(i + 24) % 32];
    tmp[i] = acc;
  }

  ctxt = tmp; // 👈 整体替换
}

void sm4_F(std::span<helib::Ctxt> ctxt0,
           std::span<helib::Ctxt> ctxt1,
           std::span<helib::Ctxt> ctxt2,
           std::span<helib::Ctxt> ctxt3,
           std::vector<helib::Ctxt>& rk,
           const helib::PubKey& public_key,
           helib::Ctxt ctmp,
           std::vector<helib::Ctxt>& F_out)
{
  std::vector<helib::Ctxt> tmp(32, helib::Ctxt(public_key));
  // std::vector<helib::Ctxt> monomials(255, helib::Ctxt(public_key));

  for (int i = 0; i < 32; i++) {
    tmp[i] = ctxt1[i];
    tmp[i] += ctxt2[i];
    tmp[i] += ctxt3[i];
    tmp[i] += rk[i];
  }
  auto start = std::chrono::high_resolution_clock::now();
  SubByte(tmp, public_key, ctmp);
  // invertSingle(tmp);
  auto end = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double, std::milli> duration_ms = end - start;
  std::cout << "1 Subbyte took " << duration_ms.count() << " ms." << std::endl;

  sm4_L(tmp, public_key);
  for (int i = 0; i < 32; ++i) {
    tmp[i] += ctxt0[i];
    F_out[i] = tmp[i];
  }
}

void sm4_round(std::vector<helib::Ctxt>& ctxt, // 128比特明文密文，共4组32位
               std::vector<helib::Ctxt>& rk,   // 当前轮的32比特密钥
               const helib::PubKey& public_key,
               helib::Ctxt& const_one) // 常数密文，用于乘法常量等
{
  // 输入划分为 X0,X1,X2,X3 四个分组
  std::span<helib::Ctxt> X0(ctxt.data() + 0, 32);
  std::span<helib::Ctxt> X1(ctxt.data() + 32, 32);
  std::span<helib::Ctxt> X2(ctxt.data() + 64, 32);
  std::span<helib::Ctxt> X3(ctxt.data() + 96, 32);

  // 用于存放F函数的输出
  std::vector<helib::Ctxt> F_out(32, helib::Ctxt(public_key));

  // 执行 F(X1, X2, X3, rk) => F_out
  sm4_F(X0, X1, X2, X3, rk, public_key, const_one, F_out);

  // 左移组：X1 -> X0, X2 -> X1, X3 -> X2, X0_new -> X3
  std::vector<helib::Ctxt> new_ctxt(128, helib::Ctxt(public_key));
  for (int i = 0; i < 32; ++i) {
    new_ctxt[i] = ctxt[32 + i];      // X1
    new_ctxt[32 + i] = ctxt[64 + i]; // X2
    new_ctxt[64 + i] = ctxt[96 + i]; // X3
    new_ctxt[96 + i] = F_out[i];     // X0_new
  }

  // 更新 ctxt（注意不能直接用 std::swap，因为要保持原始结构）
  ctxt = std::move(new_ctxt);
}

void sm4_bitwise_L(const uint8_t in[32], uint8_t out[32])
{
  for (int i = 0; i < 32; ++i) {
    // 每一位 = 原位 ⊕ ROL2 ⊕ ROL10 ⊕ ROL18 ⊕ ROL24
    int i2 = (i + 2) % 32;
    int i10 = (i + 10) % 32;
    int i18 = (i + 18) % 32;
    int i24 = (i + 24) % 32;

    out[i] = in[i] ^ in[i2] ^ in[i10] ^ in[i18] ^ in[i24];
  }
}

// SM4 线性变换 F 的比特级实现
void sm4_bitwise_F(const uint8_t in0[32],
                   const uint8_t in1[32],
                   const uint8_t in2[32],
                   const uint8_t in3[32],
                   const uint8_t rk[32],
                   uint8_t out[32])
{
  uint8_t tmp[32] = {0};
  for (int i = 0; i < 32; i++) {
    tmp[i] ^= in1[i];
    tmp[i] ^= in2[i];
    tmp[i] ^= in3[i];
    tmp[i] ^= rk[i];
  }
  for (int i = 0; i < 4; i++) {
    uint8_t S_input = tmp[i * 8 + 7] | tmp[i * 8 + 6] << 1 |
                      tmp[i * 8 + 5] << 2 | tmp[i * 8 + 4] << 3 |
                      tmp[i * 8 + 3] << 4 | tmp[i * 8 + 2] << 5 |
                      tmp[i * 8 + 1] << 6 | tmp[i * 8 + 0] << 7;

    uint8_t S_output = SM4_SBOX[S_input];
    tmp[i * 8] = (S_output >> 7) & 0x01;
    tmp[i * 8 + 1] = (S_output >> 6) & 0x01;
    tmp[i * 8 + 2] = (S_output >> 5) & 0x01;
    tmp[i * 8 + 3] = (S_output >> 4) & 0x01;
    tmp[i * 8 + 4] = (S_output >> 3) & 0x01;
    tmp[i * 8 + 5] = (S_output >> 2) & 0x01;
    tmp[i * 8 + 6] = (S_output >> 1) & 0x01;
    tmp[i * 8 + 7] = (S_output) & 0x01;
  }
  sm4_bitwise_L(tmp, out);
  for (int i = 0; i < 32; ++i) {
    out[i] = in0[i] ^ out[i];
  }
}

uint32_t test_plain[4] = {0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210};

uint8_t test_rk[128] = {
    0xf1, 0x21, 0x86, 0xf9, 0x41, 0x66, 0x2b, 0x61, 0x5a, 0x6a, 0xb1, 0x9a,
    0x7b, 0xa9, 0x20, 0x77, 0x36, 0x73, 0x60, 0xf4, 0x77, 0x6a, 0x0c, 0x61,
    0xb6, 0xbb, 0x89, 0xb3, 0x24, 0x76, 0x31, 0x51, 0xa5, 0x20, 0x30, 0x7c,
    0xb7, 0x58, 0x4d, 0xbd, 0xc3, 0x07, 0x53, 0xed, 0x7e, 0xe5, 0x5b, 0x57,
    0x69, 0x88, 0x60, 0x8c, 0x30, 0xd8, 0x95, 0xb7, 0x44, 0xba, 0x14, 0xaf,
    0x10, 0x44, 0x95, 0xa1, 0xd1, 0x20, 0xb4, 0x28, 0x73, 0xb5, 0x5f, 0xa3,
    0xcc, 0x87, 0x49, 0x66, 0x92, 0x24, 0x44, 0x39, 0xe8, 0x9e, 0x64, 0x1f,
    0x98, 0xca, 0x01, 0x5a, 0xc7, 0x15, 0x90, 0x60, 0x99, 0xe1, 0xfd, 0x2e,
    0xb7, 0x9b, 0xd8, 0x0c, 0x1d, 0x21, 0x15, 0xb0, 0x0e, 0x22, 0x8a, 0xeb,
    0xf1, 0x78, 0x0c, 0x81, 0x42, 0x8d, 0x36, 0x54, 0x62, 0x29, 0x34, 0x96,
    0x01, 0xcf, 0x72, 0xe5, 0x91, 0x24, 0xa0, 0x12};

void Encode_RK(std::vector<uint8_t>& rk)
{
  for (int i = 0; i < 128; i++) {
    for (int j = 0; j < 8; j++) {
      rk[i * 8 + j] = (test_rk[i] >> (7 - j)) & 0x01;
    }
  }
}

void Encode_Plain(std::vector<uint8_t>& in_vec, int ctr)
{
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 32; j++) {
      if (i == 3)
        in_vec[i * 32 + j] = ((test_plain[i] + ctr) >> (31 - j)) & 0x01;
      else
        in_vec[i * 32 + j] = (test_plain[i] >> (31 - j)) & 0x01;
    }
  }
}

void SM4_CTR(int block_num, std::vector<std::vector<uint8_t>>& bit_mask)
{
  std::vector<uint32_t> plain(block_num * 4);
  std::vector<uint8_t> roundKeys(128 * 8);
  Encode_RK(roundKeys);

  for (int i = 0; i < block_num; i++) {
    plain[i * 4 + 0] = test_plain[0];
    plain[i * 4 + 1] = test_plain[1];
    plain[i * 4 + 2] = test_plain[2];
    plain[i * 4 + 3] = test_plain[3] + i;
  }
  for (int i = 0; i < block_num; i++) {
    std::vector<uint8_t> state(128);
    uint8_t X[36][32];
    for (int j = 0; j < 4; j++) {
      for (int b = 0; b < 32; b++) {
        state[j * 32 + b] = (plain[i * 4 + j] >> (31 - b)) & 0x01;
      }
    }
    std::vector<uint8_t> sm4_output_bytes(4, 0);
    // 初始化 X0–X3
    for (int j = 0; j < 4; j++) {
      for (int b = 0; b < 32; b++)
        X[j][b] = state[j * 32 + b];
    }
    for (int j = 0; j < 32; j++) {
      sm4_bitwise_F(X[j],
                    X[j + 1],
                    X[j + 2],
                    X[j + 3],
                    &roundKeys[j * 32],
                    X[j + 4]);
      for (int byte = 0; byte < 4; ++byte) {
        uint8_t val = 0;
        for (int bit = 0; bit < 8; ++bit) {
          int idx = byte * 8 + bit;
          int bit_val = static_cast<long>(X[j + 4][idx]);

          val |= (bit_val & 0x1) << (7 - bit);
        }
        sm4_output_bytes[byte] = val;
      }
      // std::cout << "Round " << i + 1 << ":" << std::endl;
      // std::cout << "SM4 F OUTPUT (big-endian bytes): ";
      // for (uint8_t b : sm4_output_bytes) {
      //   std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b
      //             << " ";
      // }
    }
    for (int j = 0; j < 4; j++) {
      for (int b = 0; b < 32; b++)
        bit_mask[i][j * 32 + b] = X[35 - j][b];
    }
  }
}

int main(int argc, char* argv[])
{
  int block_num = 1200;
  std::vector<std::vector<uint8_t>> bit_mask(block_num,
                                             std::vector<uint8_t>(128, 0));
  std::vector<std::vector<uint8_t>> message(block_num,
                                            std::vector<uint8_t>(128, 0));
  SM4_CTR(block_num, bit_mask);
  for (int i = 0; i < block_num; i++) {
    for (int j = 0; j < 128; j++) {
      message[i][j] ^= bit_mask[i][j];
    }
  }

  // if (hexl::IsSupported()) {
  //   std::cout << "HEXL available, CPU features: " << hexl::CPUFeatures()
  //             << "\n";
  // } else {
  //   std::cout << "HEXL not available\n";
  // }
  // omp_set_num_threads(1);          // OpenMP 外层线程数
  // omp_set_nested(1);               // 允许嵌套并行（关键！！）
  NTL::SetNumThreads(64);          // 设置使用 4 个线程
  int n = NTL::AvailableThreads(); // 获取最大可用线程数
  std::cout << "Using " << n << " threads.\n";
  srand(time(0));
  /*  Example of BGV scheme  */

  // Plaintext prime modulus
  unsigned long p = 2;
  // Cyclotomic polynomial - defines phi(m)
  unsigned long m = 31775;
  // Hensel lifting (default = 1)
  unsigned long r = 1;
  // Number of bits of the modulus chain
  unsigned long bits = 680;
  // Number of columns of Key-Switching matrix (default = 2 or 3)
  unsigned long c = 3;

  std::vector<long> mvec = {41, 775};
  // Generating set of Zm* group.
  std::vector<long> gens = {6976, 24806};
  // Orders of the previous generators.
  std::vector<long> ords = {40, 30};

  std::cout << "\n*********************************************************";
  std::cout << "\n*         Basic Mathematical Operations Example         *";
  std::cout << "\n*         =====================================         *";
  std::cout << "\n*                                                       *";
  std::cout << "\n* This is a sample program for education purposes only. *";
  std::cout << "\n* It attempts to show the various basic mathematical    *";
  std::cout << "\n* operations that can be performed on both ciphertexts  *";
  std::cout << "\n* and plaintexts.                                       *";
  std::cout << "\n*                                                       *";
  std::cout << "\n*********************************************************";
  std::cout << std::endl;

  std::cout << "Initialising context object..." << std::endl;
  // Initialize context
  // This object will hold information about the algebra created from the
  // previously set parameters
  helib::Context context = helib::ContextBuilder<helib::BGV>()
                               .m(m)
                               .p(p)
                               .r(r)
                               .gens(gens)
                               .ords(ords)
                               .bits(bits)
                               .c(c)
                               .bootstrappable(true)
                               .skHwt(120)
                               .mvec(mvec)
                               .thickboot()
                               .build();

  NTL::Vec<long> Mvec;
  append(Mvec, mvec[0]);
  append(Mvec, mvec[1]);

  context.enableBootStrapping(Mvec,
                              true,
                              /*alsoThick=*/true);

  // Print the context
  context.printout();
  std::cout << std::endl;

  // Print the security level
  std::cout << "Security: " << context.securityLevel() << std::endl;

  // Secret key management
  std::cout << "Creating secret key..." << std::endl;
  // Create a secret key associated with the context
  helib::SecKey secret_key(context);
  // Generate the secret key
  secret_key.GenSecKey();
  std::cout << "Generating key-switching matrices..." << std::endl;
  // Compute key-switching matrices that we need
  helib::addSome1DMatrices(secret_key);
  helib::addFrbMatrices(secret_key);

  // Generate bootstrapping data
  secret_key.genRecryptData();

  // Public key management
  // Set the secret key (upcast: SecKey is a subclass of PubKey)
  helib::PubKey& public_key = secret_key;

  // Get the EncryptedArray of the context
  const helib::EncryptedArray& ea = context.getEA();

  int d = ea.getDegree();
  std::cout << ceil(((double)128) / d) << std::endl;

  // Get the number of slot (phi(m))
  long nslots = ea.size();

  std::cout << "Number of slots: " << nslots << std::endl;

  std::cout << "d: " << ea.getDegree() << std::endl;

  std::vector<uint8_t> in_vec(128), rk(1024);

  // encode(in_vec, rk);
  Encode_RK(rk);

  // Create a vector of long with nslots elements
  std::vector<helib::Ptxt<helib::BGV>> ptxt(128,
                                            helib::Ptxt<helib::BGV>(context)),
      ptrk(32, helib::Ptxt<helib::BGV>(context));
  // Set it with numbers 0..nslots - 1
  // ptxt = [0] [1] [2] ... [nslots-2] [nslots-1]
  // for (int i = 0; i < 128; i++)
  //   for (int j = 0; j < ptxt[0].size(); ++j) {
  //     ptxt[i][j] = (int)in_vec[i];
  //   }

  for (int j = 0; j < ptxt[0].size(); ++j) {
    Encode_Plain(in_vec, j);
    for (int i = 0; i < 128; i++) {
      ptxt[i][j] = (int)in_vec[i];
    }
  }
  std::cout << std::endl;
  // Create a ciphertext object
  std::vector<helib::Ctxt> ctxt(128, helib::Ctxt(public_key)),
      ctrk(32, helib::Ctxt(public_key)), ctxt_out(32, helib::Ctxt(public_key));
  helib::Ctxt ct_pack(public_key);
  // Encrypt the plaintext using the public_key
  for (int i = 0; i < 128; i++)
    public_key.Encrypt(ctxt[i], ptxt[i]);

  // Create a plaintext for decryption
  std::vector<helib::Ptxt<helib::BGV>> plaintext_result(
      128,
      helib::Ptxt<helib::BGV>(context));

  std::cout << "Remaining noise budget: " << ctxt[0].capacity() << " bits"
            << std::endl;

  helib::Ptxt<helib::BGV> ptmp(context);
  helib::Ctxt ctmp(public_key);
  for (int k = 0; k < ptmp.size(); ++k) {
    ptmp[k] = (int)1;
  }

  public_key.Encrypt(ctmp, ptmp);

  // std::span<helib::Ctxt> ctxt0(ctxt.data() + 0, 32);
  // std::span<helib::Ctxt> ctxt1(ctxt.data() + 32, 32);
  // std::span<helib::Ctxt> ctxt2(ctxt.data() + 64, 32);
  // std::span<helib::Ctxt> ctxt3(ctxt.data() + 96, 32);

  // sm4_F(ctxt0, ctxt1, ctxt2, ctxt3, ctrk, public_key, ctmp, ctxt_out);

  std::vector<uint8_t> sm4_output_bytes(4, 0);
  std::vector<helib::Ctxt> ctxt_unpack1(d, helib::Ctxt(public_key)),
      ctxt_unpack2(d, helib::Ctxt(public_key));

  std::vector<helib::zzX> unpackSlotEncoding(d);
  helib::buildUnpackSlotEncoding(unpackSlotEncoding, ea);
  int cnt = 0;

  for (int i = 0; i < 32; i++) {
    // use one ctrk to save memory
    for (int k = 0; k < 32; k++)
      for (int j = 0; j < ptrk[0].size(); ++j) {
        ptrk[k][j] = (int)rk[k + i * 32];
      }

    for (int j = 0; j < 32; j++)
      public_key.Encrypt(ctrk[j], ptrk[j]);

    if (ctxt[96].capacity() < 85) {
      cnt++;
      std::cout << "Recrypting round " << cnt << std::endl;
      auto start = std::chrono::high_resolution_clock::now();

      for (int j = 0; j < ceil(((double)128) / d); j++) {
        if (j == ceil(((double)128) / d) - 1)
          for (int k = 0; k < 128 - j * d; k++)
            ctxt_unpack1[k] = ctxt[k + j * d];
        else
          for (int k = 0; k < d; k++)
            ctxt_unpack1[k] = ctxt[k + j * d];
        std::cout << "j = " << j << std::endl;
        helib::repack(ct_pack, helib::CtPtrs_vectorCt(ctxt_unpack1), ea);

        public_key.reCrypt(ct_pack);

        helib::unpack(helib::CtPtrs_vectorCt(ctxt_unpack2),
                      ct_pack,
                      ea,
                      unpackSlotEncoding);
        if (j == ceil(((double)128) / d) - 1)
          for (int k = 0; k < 128 - j * d; k++)
            ctxt[k + j * d] = ctxt_unpack2[k];
        else
          for (int k = 0; k < d; k++)
            ctxt[k + j * d] = ctxt_unpack2[k];
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> duration_ms = end - start;
        std::cout << "1 Recrypt took " << duration_ms.count() << " ms."
                  << std::endl;
      }
    }
    auto start = std::chrono::high_resolution_clock::now();
    sm4_round(ctxt, ctrk, public_key, ctmp);

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration_ms = end - start;
    std::cout << "1 Round took " << duration_ms.count() << " ms." << std::endl;

    for (int j = 0; j < 32; j++) {
      // secret_key.Decrypt(plaintext_result[i], ctxt_out[i]);
      secret_key.Decrypt(plaintext_result[j], ctxt[96 + j]);
    }

    // 大端：bit0 是 MSB，bit7 是 LSB
    for (int byte = 0; byte < 4; ++byte) {
      uint8_t val = 0;
      for (int bit = 0; bit < 8; ++bit) {
        int idx = byte * 8 + bit;
        int bit_val = static_cast<long>(plaintext_result[idx][1]);

        val |= (bit_val & 0x1) << (7 - bit);
      }
      sm4_output_bytes[byte] = val;
    }
    std::cout << "Round " << i + 1 << ":" << std::endl;
    std::cout << "SM4 F OUTPUT (big-endian bytes): ";
    for (uint8_t b : sm4_output_bytes) {
      std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b
                << " ";
    }
    std::cout << std::endl;
    std::cout << "Remaining noise budget: " << ctxt[0].capacity() << " bits"
              << std::endl;
    std::cout << "Remaining noise budget: " << ctxt[32].capacity() << " bits"
              << std::endl;
    std::cout << "Remaining noise budget: " << ctxt[64].capacity() << " bits"
              << std::endl;
    std::cout << "Remaining noise budget: " << ctxt[96].capacity() << " bits"
              << std::endl;
    std::cout << std::dec << std::endl;
  }

  std::vector<helib::Ptxt<helib::BGV>> ptxt_message(
      128,
      helib::Ptxt<helib::BGV>(context));
  for (int i = 0; i < 128; i++) {
    for (int j = 0; j < ptxt_message[0].size(); ++j) {
      ptxt_message[i][j] = (int)message[j][i];
    }
  }
  bool match = true;
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 32; j++) {
      ctxt[(3 - i) * 32 + j] += ptxt_message[i * 32 + j];
    }
  }
  for (int i = 0; i < 128; i++) {
    secret_key.Decrypt(plaintext_result[i], ctxt[i]);
    for (int j = 0; j < plaintext_result[0].size(); ++j) {
      if (plaintext_result[i][j] != 0) {
        match = false;
        break;
      }
    }
  }
  if (match)
    std::cout << "Decryption successful, plaintexts match!" << std::endl;
  else
    std::cout << "Decryption failed, plaintexts do not match!" << std::endl;
  return 0;
}

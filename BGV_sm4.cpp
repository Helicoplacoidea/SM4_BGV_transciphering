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

#include "BGV_sm4.h"

int main(int argc, char* argv[])
{

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
  unsigned long m = 32767;
  // Hensel lifting (default = 1)
  unsigned long r = 1;
  // Number of bits of the modulus chain
  unsigned long bits = 680;
  // Number of columns of Key-Switching matrix (default = 2 or 3)
  unsigned long c = 3;

  std::vector<long> mvec = {31, 7, 151}; // 第一层 m1=7, 第二层 m2=31*151
  std::vector<long> gens = {11628, 28087, 25824};
  std::vector<long> ords = {30, 6, -10};

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
  append(Mvec, mvec[2]);

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

  int block_num = nslots;
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
        int bit_val = static_cast<long>(plaintext_result[idx][0]);

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

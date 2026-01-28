
#include "BGV_sm4.h"

void SboxLazy(int thread_num,
              helib::Context& context,
              helib::PubKey& public_key)
{

  std::vector<uint8_t> in_vec(32);
  for (int i = 0; i < 32; i++) {
    in_vec[i] = rand() % 2;
  }

  // Create a vector of long with nslots elements
  std::vector<helib::Ptxt<helib::BGV>> ptxt(32,
                                            helib::Ptxt<helib::BGV>(context));

  for (int j = 0; j < ptxt[0].size(); ++j) {
    for (int i = 0; i < 32; i++) {
      ptxt[i][j] = (int)in_vec[i];
    }
  }
  std::cout << std::endl;
  // Create a ciphertext object
  std::vector<helib::Ctxt> ctxt(32, helib::Ctxt(public_key));
  // Encrypt the plaintext using the public_key
  for (int i = 0; i < 32; i++)
    public_key.Encrypt(ctxt[i], ptxt[i]);

  std::cout << "Remaining noise budget: " << ctxt[0].capacity() << " bits"
            << std::endl;

  helib::Ptxt<helib::BGV> ptmp(context);
  helib::Ctxt ctmp(public_key);
  for (int k = 0; k < ptmp.size(); ++k) {
    ptmp[k] = (int)1;
  }

  public_key.Encrypt(ctmp, ptmp);

  auto start = std::chrono::high_resolution_clock::now();
  SubByte_Lazy(ctxt, public_key, ctmp);
  auto end = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double, std::milli> duration_ms = end - start;
  std::cout << "1 S-box took " << duration_ms.count() << " ms." << std::endl;

  std::cout << "Remaining noise budget: " << ctxt[0].capacity() << " bits"
            << std::endl;
}

void SboxRaw(int thread_num, helib::Context& context, helib::PubKey& public_key)
{

  std::vector<uint8_t> in_vec(32);
  for (int i = 0; i < 32; i++) {
    in_vec[i] = rand() % 2;
  }

  // Create a vector of long with nslots elements
  std::vector<helib::Ptxt<helib::BGV>> ptxt(32,
                                            helib::Ptxt<helib::BGV>(context));

  for (int j = 0; j < ptxt[0].size(); ++j) {
    for (int i = 0; i < 32; i++) {
      ptxt[i][j] = (int)in_vec[i];
    }
  }
  std::cout << std::endl;
  // Create a ciphertext object
  std::vector<helib::Ctxt> ctxt(32, helib::Ctxt(public_key));
  // Encrypt the plaintext using the public_key
  for (int i = 0; i < 32; i++)
    public_key.Encrypt(ctxt[i], ptxt[i]);

  std::cout << "Remaining noise budget: " << ctxt[0].capacity() << " bits"
            << std::endl;

  helib::Ptxt<helib::BGV> ptmp(context);
  helib::Ctxt ctmp(public_key);
  for (int k = 0; k < ptmp.size(); ++k) {
    ptmp[k] = (int)1;
  }

  public_key.Encrypt(ctmp, ptmp);

  auto start = std::chrono::high_resolution_clock::now();
  SubByte_raw(ctxt, public_key, ctmp);
  auto end = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double, std::milli> duration_ms = end - start;
  std::cout << "1 S-box took " << duration_ms.count() << " ms." << std::endl;

  std::cout << "Remaining noise budget: " << ctxt[0].capacity() << " bits"
            << std::endl;
}

void batchRecrypt(int thread_num,
                  int d,
                  const helib::EncryptedArray& ea,
                  helib::Context& context,
                  helib::PubKey& public_key)
{

  std::vector<uint8_t> in_vec(d);
  for (int i = 0; i < d; i++) {
    in_vec[i] = rand() % 2;
  }

  // Create a vector of long with nslots elements
  std::vector<helib::Ptxt<helib::BGV>> ptxt(d,
                                            helib::Ptxt<helib::BGV>(context));

  for (int j = 0; j < ptxt[0].size(); ++j) {
    for (int i = 0; i < d; i++) {
      ptxt[i][j] = (int)in_vec[i];
    }
  }
  std::cout << std::endl;
  // Create a ciphertext object
  std::vector<helib::Ctxt> ctxt(d, helib::Ctxt(public_key));
  // Encrypt the plaintext using the public_key
  for (int i = 0; i < d; i++)
    public_key.Encrypt(ctxt[i], ptxt[i]);

  std::cout << "Remaining noise budget: " << ctxt[0].capacity() << " bits"
            << std::endl;

  if (ctxt[0].capacity() > 50) {
    for (int i = 0; i < d; i++)
      ctxt[i].square();
  }

  helib::Ctxt ct_pack(public_key);
  std::vector<helib::zzX> unpackSlotEncoding(d);
  helib::buildUnpackSlotEncoding(unpackSlotEncoding, ea);

  auto start = std::chrono::high_resolution_clock::now();
  helib::repack(ct_pack, helib::CtPtrs_vectorCt(ctxt), ea);

  public_key.reCrypt(ct_pack);

  helib::unpack(helib::CtPtrs_vectorCt(ctxt), ct_pack, ea, unpackSlotEncoding);
  auto end = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double, std::milli> duration_ms = end - start;
  std::cout << "1 Recryption took " << duration_ms.count() << " ms."
            << std::endl;

  std::cout << "Remaining noise budget: " << ctxt[0].capacity() << " bits"
            << std::endl;
}

int main()
{
  int thread_num = 1; // 设置线程数
  std::cout << "请输入线程数：";
  std::cin >> thread_num;

  NTL::SetNumThreads(thread_num);  // 设置使用 4 个线程
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

  batchRecrypt(thread_num, d, ea, context, public_key);
  SboxLazy(thread_num, context, public_key);
  SboxRaw(thread_num, context, public_key);
  return 0;
}
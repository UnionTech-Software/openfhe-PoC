***\*1、Question\****

The PoC test code is as follows：

```c++
#include <iostream>

#include <string>

#include <stack>

#include <cstdlib>

#include <ctime>

#include <memory>

#include <fstream>

#include <iomanip>

#include "openfhe.h"

 

using namespace lbcrypto;

 

int main() {

  auto cc = BinFHEContext();

  cc.GenerateBinFHEContext(MEDIUM);

  auto sk = cc.KeyGen();

  cc.BTKeyGen(sk);

 

  auto ct = cc.EvalFloor(nullptr, 1);

  return 0;

}
```

After compiling the code, the execution reports a segmentation error：

> /home/dou/gerrit/CVE/PoC/openfhe/openfhe/openfhe/openfhe-development/src/binfhe/lib/binfhe-base-scheme.cpp:311:38: runtime error: member call on null pointer of type 'const struct element_type'

> AddressSanitizer:DEADLYSIGNAL

> =================================================================

> ==12869==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x7fd3e9efa986 bp 0x0fffe636630c sp 0x7fff31b31720 T0)

> ==12869==The signal is caused by a READ memory access.

> ==12869==Hint: address points to the zero page.

>  \#0 0x7fd3e9efa985 in lbcrypto::BinFHEScheme::EvalFloor(std::shared_ptr<lbcrypto::BinFHECryptoParams> const&, lbcrypto::RingGSWBTKey const&, std::shared_ptr<lbcrypto::LWECiphertextImpl const> const&, intnat::NativeIntegerT<unsigned long> const&, unsigned int) const /home/dou/gerrit/CVE/PoC/openfhe/openfhe/openfhe/openfhe-development/src/binfhe/lib/binfhe-base-scheme.cpp:311

>  \#1 0x7fd3e9ff1f73 in lbcrypto::BinFHEContext::EvalFloor(std::shared_ptr<lbcrypto::LWECiphertextImpl const> const&, unsigned int) const /home/dou/gerrit/CVE/PoC/openfhe/openfhe/openfhe/openfhe-development/src/binfhe/lib/binfhecontext.cpp:312

>  \#2 0x406546 in main /home/dou/gerrit/CVE/PoC/openfhe/openfhe/openfhe/poc/poc7/test.cpp:18

>  \#3 0x7fd3e2a801fa in __libc_start_main ../csu/libc-start.c:308

>  \#4 0x4075e9 in _start (/home/dou/gerrit/CVE/PoC/openfhe/openfhe/openfhe/poc/poc7/build/test+0x4075e9)

>

> AddressSanitizer can not provide additional info.

> SUMMARY: AddressSanitizer: SEGV /home/dou/gerrit/CVE/PoC/openfhe/openfhe/openfhe/openfhe-development/src/binfhe/lib/binfhe-base-scheme.cpp:311 in lbcrypto::BinFHEScheme::EvalFloor(std::shared_ptr<lbcrypto::BinFHECryptoParams> const&, lbcrypto::RingGSWBTKey const&, std::shared_ptr<lbcrypto::LWECiphertextImpl const> const&, intnat::NativeIntegerT<unsigned long> const&, unsigned int) const

> ==12869==ABORTING

 

 

***\*2、Analyze\****

According to the error message above, it can be known that the program is trying to access a null pointer, which causes a segmentation fault.

In the PoC code, a null pointer (nullptr) is indeed passed to `BinFHEContext::EvalFloor`, but `BinFHEContext::EvalFloor` does not handle the null pointer type, resulting in a segmentation fault.
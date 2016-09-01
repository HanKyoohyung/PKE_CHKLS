#include "PKECtxt.h"
#include <iostream>

PKECtxt::PKECtxt(PKEKey& pk, VectorXi& c1, VectorXi& c2, VectorXi& c3, VectorXi& c4, uint64_t c5) :
	pk(pk), c1(c1), c2(c2), c3(c3), c4(c4), c5(c5)
{
}

std::ostream& operator<<(std::ostream& os, const PKECtxt& c) {
    os << "* Ciphertext size = " << c.pk.logq * c.pk.n + 3 * c.pk.ell + 16 << ", c5 = " << c.c5;
    return os;
}
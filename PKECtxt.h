#ifndef __PKE__CTXT
#define __PKE__CTXT

#include <ostream>
#include <Eigen/Dense>
#include "PKEKey.h"

using namespace Eigen;

typedef Matrix<bool, Dynamic, Dynamic> MatrixXb;
typedef Matrix<bool, Dynamic, 1> VectorXb;

class PKEKey;

class PKECtxt {
public:
	PKEKey& pk;
	VectorXi c1;
	VectorXi c2, c3, c4;
	uint64_t c5;
	PKECtxt(PKEKey&, VectorXi&, VectorXi&, VectorXi&, VectorXi&, uint64_t);
	friend std::ostream& operator<<(std::ostream&, const PKECtxt&);
};

#endif
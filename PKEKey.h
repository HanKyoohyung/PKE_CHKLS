#ifndef __PKE__KEY
#define __PKE__KEY

#include <stdlib.h>
#include <stdint.h>
#include <ostream>
#include <Eigen/Dense>
#include <Eigen/Core>
#include <omp.h>
#include <cryptopp/sha3.h>
#include "PKECtxt.h"

using namespace Eigen;

typedef Matrix<bool, Dynamic, Dynamic> MatrixXb;
typedef Matrix<bool, Dynamic, 1> VectorXb;

struct PKEParams {
    unsigned long lambda, ell, n, q, errorbound, theta;
};

//Parameters from security parameters 72 ~ 128//
const struct PKEParams PKE_1 = {72, 128, 280, 565, 8, 10};
const struct PKEParams PKE_2 = {93, 128, 350, 745, 4, 15};
const struct PKEParams PKE_3 = {107, 128, 400, 901, 8, 16};
const struct PKEParams PKE_4 = {120, 128, 450, 1013, 8, 18};
const struct PKEParams PKE_5 = {128, 128, 490, 1125, 4, 20};

class PKECtxt;

class PKEKey {
	protected:
	MatrixXi S;

	public:
	MatrixXi A, B;
	unsigned long m, n, errorbound, theta, blocksize, logq, ell;
	long q;

	PKEKey(const struct PKEParams& params);
	void Decap(VectorXi&, VectorXi&, VectorXi&, MatrixXi&);
	PKECtxt Encrypt_with_sigma(std::vector<bool>&, std::vector<bool>&);
	PKECtxt Encrypt(std::vector<bool>&);
	bool EQTest(PKECtxt&, PKECtxt&);
	void Decrypt(std::vector<bool>&, PKECtxt& c);
	friend std::ostream& operator<<(std::ostream&, const PKEKey&);
};

#endif

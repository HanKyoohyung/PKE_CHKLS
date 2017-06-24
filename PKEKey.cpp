#include <iostream>
#include <ctime>
#include <sys/time.h>
#include <Eigen/Dense>
#include <vector>

#include "PKEKey.h"
#include "common.h"
#include "Keccak.h"

#define ABS(x)		(((x)<0)?(-(x)):(x))
#define SKIP_HASH_TEST

PKEKey::PKEKey(const struct PKEParams& params){
	unsigned long i, j;
	int temp;
	
	//ell should be multiple of 64
	srand(time(NULL));
	n = params.n;		q = params.q;		errorbound = params.errorbound;
	theta = params.theta;	ell = params.ell;	blocksize = n / theta;
	temp = 1;
	for(i = 0; i < 16; i++){
		temp <<= 1;
		if(q < temp){logq = i + 1; break;}
	}
	
	//Generate S to be n by ell matrix, Each column is sparse binary vector with hemming weigh theta//
	S.resize(n, ell);
	for(i = 0; i < n; i++){for(j = 0; j < ell; j++){S(i,j) = 0;}} //Initialize
	for(i = 0; i < ell; i++){
		for(j = 0; j < theta; j++){
			temp = rand() % blocksize;
			S(j * blocksize + temp, i) = 1;
		}
	}
	
	//Generate uniform random A matrix//
	A.resize(n, n);
	for(i = 0; i < n; i++){for(j = 0; j < n; j++){A(i,j) = (rand() % q);}}
	
	//Generate error E marix//
	MatrixXi E(n, ell);
	for(i = 0; i < n; i++){
		for(j = 0; j < ell; j++){
			E(i,j) = (int)((rand() % (2 * errorbound)) - errorbound);
		}
	}
	
	//Compute B = A * S + E//
	B.resize(n, ell);
	B = A * S + E;
	E.resize(0,0); //clear matrix E
}

PKECtxt PKEKey::Encrypt_with_sigma(std::vector<bool>& m, std::vector<bool>& sigma){
	unsigned long i, j;
	srand(time(NULL));
	
	//sigmamessage = ( sigma  |  message )
	std::vector<bool> sigmamessage;
	sigmamessage.resize(2 * ell);
	for(i = 0; i < ell; i++){sigmamessage[i] = sigma[i]; sigmamessage[i + ell] = m[i];}

	//Hash Computation1: input sigmamessage
	uint64_t **seed = (uint64_t **)calloc(5, sizeof(uint64_t*)); //Set seed to be 5 by 5 matrix of uint64_t
	for(i = 0; i < 5; i++) seed[i] = (uint64_t *)calloc(5,sizeof(uint64_t));
	for(i = 0; i < 5; i++){
		for(j = 0; j < 5; j++){
			seed[i][j] = 0;
		}
	}
	for(i = 0; i < ell / 32; i++){
		for(j = 0; j < 64; j++){
			if(sigmamessage[j + i * 64] == 1) seed[0][i] += (1 << j);
		}
	}
	seed = keccak_f(seed); //Hash Computation: this part take about 5% of encryption (you can use another HASH if you want)
	
	//Seed Setting
	unsigned int seed1 = (unsigned int) seed[0][0];
	unsigned int seed2 = (unsigned int) seed[0][1];
	unsigned int seed3 = (unsigned int) seed[1][0];

	//Hash Computation2: input sigma
	uint64_t **hash=(uint64_t **)calloc(5,sizeof(uint64_t*));
	for(i = 0; i < 5; i++) hash[i] = (uint64_t *)calloc(5,sizeof(uint64_t));
	for(i = 0; i < 5; i++){
		for(j = 0; j < 5; j++){
			hash[i][j] = 0;
		}
	}
	for(i = 0; i < ell / 64; i++){
		for(j = 0; j < 64; j++){
			if(sigma[j + i * 64] == 1) hash[0][i] += (1 << j);
		}
	}
	hash = keccak_f(hash); //Hash Computation: this part take about 5% of encryption (you can use another HASH if you want)
	
	//Seed Setting//
	unsigned int seed4 = (unsigned int) hash[1][1];

	//Compute key1, key2, key3, key4, h from seed1 ~ seed4
	VectorXi key1(theta);
	VectorXi key2(n);
	VectorXi key3(ell);
	VectorXi key4(ell);
	srand(seed1);
	for(i = 0; i < theta; i++){key1(i) = rand() % blocksize;}
	srand(seed2);
	for(i = 0; i < n; i++){key2(i) = (int)((rand() % (2 * errorbound)) - errorbound);}
	srand(seed3);
	for(i = 0; i < ell; i++){key3(i) = (int)((rand() % (2 * errorbound)) - errorbound); key4(i) = mod2(rand());}
	srand(seed4);
	VectorXi h(ell);
	for(i = 0; i < ell; i++) h[i] = mod2(rand());
	
	//Choose u from key1//
	VectorXi u(n);
	for(i = 0; i < n; i++){u(i) = 0;}
	for(i = 0; i < theta; i++){u(i * blocksize + key1(i)) = 1;}	
	
	//Compute c1 and v//
	//c1 = A.transpose() * u + key2 modq
	//v = B.traspose() * u + key3 modq
	VectorXi c1(n);
	VectorXi v(ell);
	c1 = key2;
	v = key3;
	for(i = 0; i < n; i++){//Hammaing weight of u is small so we need only few rows of A and B
		if(u(i) == 1){
			c1 += A.row(i);
			v += B.row(i);
		}
	}
	for(i = 0; i < n; i++) c1(i) = modnear(c1(i), q);
	for(i = 0; i < ell; i++) v(i) = modnear(v(i), q);
	
	//Compute barv, mu, c2//
	VectorXi barv(ell);
	VectorXi mu(ell);
	VectorXi c2(ell);
	for(i = 0; i < ell; i++){
		barv(i) = 2 * v(i) + key4(i);
		mu(i) = 1 - mod2((barv(i) + ((3 * q)/2)) / q);
		c2(i) = mod2(((2 * barv(i)) + (2 * q)) / q);
	}
	
	//Compute c3, c4, c5 value//
	VectorXi c3(ell);
	VectorXi c4(ell);
	for(i = 0; i < ell; i++){
		c3(i) = sigma[i] ^ (int)mu(i);
		c4(i) = (int)h(i) ^ m[i];
	}
	uint64_t c5 = hash[0][0];
	
	//Clear used memories//
	mu.resize(0); sigma.resize(0); v.resize(0); barv.resize(0); u.resize(0);
	return PKECtxt(*this, c1, c2, c3, c4, c5);
}

PKECtxt PKEKey::Encrypt(std::vector<bool>& m){
	unsigned int i;
	std::vector<bool> sigma;
	sigma.resize(ell);
	//Choose random bit string sigma
	for(i = 0; i < ell; i++)
		sigma[i] = rand() % 2;
	return PKEKey::Encrypt_with_sigma(m, sigma);
}

//Decap function is to find mu vector form c1 and c2 and S
void PKEKey::Decap(VectorXi& mu, VectorXi& c1, VectorXi& c2, MatrixXi& S){
	unsigned long i;
	VectorXi w(ell);
	w = S.transpose() * c1;
	for(i = 0; i < ell; i++){
		w(i) = modnear(w(i), q);
		w(i) *= 2;
		if(c2(i) == 0){
			if(((-1) * (q/4)) < w(i) && w(i) < (3 * q) / 4){mu(i) = 0;}
			else{mu(i) = 1;}
		}
		else{
			if((-1) * ((3 * q) / 4) < w(i) && w(i) < (q/4)){mu(i) = 0;}
			else{mu(i) = 1;}
		}
	}
	w.resize(0);
}

//EQTest is in decyprtion, check whether c1 and c2 is same of not
bool PKEKey::EQTest(PKECtxt& a, PKECtxt& b){
	if(a.c1 == b.c1){
		if(a.c2 == b.c2){
			return 1;
		}
		else{
			return 0;
		}
	}
	else{
		return 0;
	}
}

//For IND-CCA we need to encrpt in decyprt and EQTest. Sometimes decrypt return vector with size 0.
void PKEKey::Decrypt(std::vector<bool>& m, PKECtxt& c){
	unsigned long i, j;
	VectorXi mu(ell);
	VectorXi c1(n);
	VectorXi c2(ell);
	std::vector<bool> sigma;
	sigma.resize(ell);
	c1 = c.c1;	c2 = c.c2;
	
	//Find mu value from c1 and c2
	PKEKey::Decap(mu, c1, c2, S);
	
	//Find sigma value from c3 and mu
	for(i = 0; i < ell; i++)
		sigma[i] = (int)c.c3(i) ^ (int)mu(i);
	
	//Compute hash value of sigma
	uint64_t **sigmahash=(uint64_t **)calloc(5,sizeof(uint64_t*));
	for(i = 0; i < 5; i++) sigmahash[i] = (uint64_t *)calloc(5,sizeof(uint64_t));
	for(i = 0; i < 5; i++){
		for(j = 0; j < 5; j++){
			sigmahash[i][j] = 0;
		}
	}
	for(i = 0; i < ell / 64; i++){
		for(j = 0; j < 64; j++){
			sigmahash[0][i] += (1 << j) * sigma[j + i * 64];	
		}
	}
	sigmahash = keccak_f(sigmahash);
	
	//Find h value from sigma
	unsigned int seed = (unsigned int)sigmahash[1][1];
	srand(seed);
	VectorXi h(ell);
	for(i = 0; i < ell; i++){h[i] = rand() % 2;}
	
	//Find message from h
	for(i = 0; i < ell; i++){m[i] = (int)c.c4(i) ^ (int)h(i);}
	
	//Encrypt with computed sigma and message//
	PKECtxt c_test = PKEKey::Encrypt_with_sigma(m,sigma);
	
	//Check c_test.c1 = c.c1 & c_test.c2 = c.c2 & c_test.c5 = c.c5//
	if(PKEKey::EQTest(c, c_test) == 1){
		if(c.c5 != sigmahash[0][0]){
			m.resize(0);
		}
	}
	else{
		m.resize(0);
	}	
}

std::ostream& operator<<(std::ostream& os, const PKEKey& key) {
    os << "* Key with parameter n = " << key.n << ", q = " << key.q << ", ell = " << key.ell;
    return os;
}

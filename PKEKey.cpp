#include "PKEKey.h"
#include <iostream>
#include <ctime>
#include <sys/time.h>
#include <Eigen/Dense>
//#include <Eigen/Core>
#include <omp.h>
#include <vector>

#define ABS(x)		(((x)<0)?(-(x)):(x))
#define SKIP_HASH_TEST

static __inline__ unsigned long long rdtsc(void)
{
    unsigned hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
}

//mod function
inline int mod (int a, int b){
	if(b < 0)
		return mod(-a, -b);
	int ret = a % b;
	if(ret < 0)
		ret += b;
	return ret;
}
//mod2 function
inline bool mod2(int x){
	if(ABS(x) % 2 == 0){
		return 0;
	}
	else{return 1;}
}
//return x mod y for x in [0, y)//
inline int modplus(int x, int y){
	int z;
	if(x >= 0){z = x % y;}
	else{z = (y - ((-x) % y));}
	if(z < y){return z;}
	else{return 0;}
}
//return x mod y for x in [-y/2, y/2)//
inline int modnear(int x, int y){
	int z;
	x += (y / 2);
	z = modplus(x, y);
	z -= (y / 2);
	return z;
}
//Hash function (Keccak)
const uint64_t r[5][5]={ {0,36,3,41,18}, {1,44,10,45,2}, {62,6,43,15,61}, {28,55,25,21,56},{27,20,39,8,14}};

uint64_t **sha3_round(uint64_t **A, uint64_t RC){
	uint8_t x, y;
	uint64_t C[5];
	uint64_t D[5];
	uint64_t B[5][5];

	/* Theta step */
	for(x = 0; x < 5; x++){
		C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4];
	}
	for(x = 0; x < 5; x++){
		D[x] = C[(x + 4) % 5] ^ ((C[(x + 1) % 5] << 1) | (C[(x + 1) % 5] >> 63));
	}
	for(x = 0; x < 5; x++){
		for(y = 0; y < 5; y++){
			A[x][y] = A[x][y] ^ D[x];
		}
	}

	/* Rho and pi steps */
	for(x = 0;x < 5; x++){
		for(y = 0; y < 5; y++){
			B[y][mod((2 * x + 3 * y),5)] = ((A[x][y] << r[x][y]) | (A[x][y] >> (64-r[x][y])));
		}
	}

	/* Xi state */
	for(x = 0; x < 5; x++){
		for(y = 0; y < 5; y++){
			A[x][y] = B[x][y] ^ ((~B[mod((x+1),5)][y]) & B[mod((x+2),5)][y]);
		}
	}

	/* Last step */
	A[0][0] = A[0][0] ^ RC;

	return A;
}
//Round constant in keccak//
const uint64_t RC[24]={ 0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
		       			0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
		       			0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
		       			0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
		       			0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
		       			0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

uint64_t **keccak_f(uint64_t **A){
  for(int32_t i = 0; i < 24; i++){
    A = sha3_round(A,RC[i]);
  }
  return A;
}

//Sk Key and Pk Key Gen//
PKEKey::PKEKey(const struct PKEParams& params){
	unsigned long i, j;
	
	srand(time(NULL));
	n = params.n;
	q = params.q;		errorbound = params.errorbound;
	theta = params.theta;	ell = params.ell;
	blocksize = n / theta;
	//Ell should be multiple of 64//
	int temp;
	temp = 1;
	for(i = 0; i < 16; i++){
		temp <<= 1;
		if(q < temp){logq = i + 1; break;}
	}
	//Set S to be n by ell matrix, Each column is sparse binary vector weigh : theta//
	S.resize(n, ell);
	for(i = 0; i < n; i++){
		for(j = 0; j < ell; j++){
			S(i,j) = 0;
		}
	}
	for(i = 0; i < ell; i++){
		for(j = 0; j < theta; j++){
			int index;
			index = rand() % blocksize;
			S(j * blocksize + index, i) = 1;
		}
	}
	//random A matrix//
	A.resize(n, n);
	for(i = 0; i < n; i++){
		for(j = 0; j < n; j++){
			A(i,j) = (long)(rand() % q);
		}
	}
	//Error E marix//
	MatrixXi E(n, ell);
	for(i = 0; i < n; i++){
		for(j = 0; j < ell; j++){
			//E(i,j) = (int)((rand() % (2 * errorbound)) - errorbound);
			E(i,j) = errorbound;
		}
	}
	//B = AS + E//
	B.resize(n, ell);
	B = A * S + E;
	/*
	for(i = 0; i < n; i++){
		for(j = 0; j < ell; j++){
			B(i,j) = 0;
			for(k = 0; k < n; k++){
				if(S(k,j) != 0) B(i,j) += A(i,k);
			}
			B(i,j) += E(i,j);
			B(i,j) = modnear(B(i,j), q);
		}
	}
	*/
	E.resize(0,0);
	//Hash Time : 0.004 ms//
}

PKECtxt PKEKey::Encrypt_with_sigma(std::vector<bool>& m, std::vector<bool>& sigma){
	unsigned long i, j;
	srand(time(NULL));
	std::vector<bool> sigmamessage;
	sigmamessage.resize(2 * ell);
	for(i = 0; i < ell; i++){sigmamessage[i] = sigma[i]; sigmamessage[i + ell] = m[i];}

	//Hash Computation1//
	uint64_t **seed = (uint64_t **)calloc(5, sizeof(uint64_t*));
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
	seed = keccak_f(seed);
	
	//Seed Setting//
	unsigned int seed1 = (unsigned int) seed[0][0];
	unsigned int seed2 = (unsigned int) seed[0][1];
	unsigned int seed3 = (unsigned int) seed[1][0];

	//Hash Computation2//
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
	hash = keccak_f(hash);
	
	//Seed Setting//
	unsigned int seed4 = (unsigned int) hash[1][1];

	//key1, key2, key3, key4, h compute//
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
	//c1 = A.transpose() * u + key2
	//v = B.traspose() * u + key3
	VectorXi c1(n);
	VectorXi v(ell);
	c1 = key2;
	v = key3;
	for(i = 0; i < n; i++){
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
	for(i = 0; i < ell; i++){
		sigma[i] = rand() % 2;
	}
	return PKEKey::Encrypt_with_sigma(m, sigma);
}

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
	/*
	for(i = 0; i < ell; i++){
		w(i) = 0;
		for(j = 0; j < n; j++){
			if(S(j,i) != 0) w(i) += c1[j];
		}
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
	*/
	w.resize(0);
}

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

void PKEKey::Decrypt(std::vector<bool>& m, PKECtxt& c){
	unsigned long i, j;
	VectorXi mu(ell);
	VectorXi c1(n);
	VectorXi c2(ell);
	std::vector<bool> sigma;
	sigma.resize(ell);
	c1 = c.c1;	c2 = c.c2;
	//Find mu value//
	PKEKey::Decap(mu, c1, c2, S);
	//Find sigma value//
	for(i = 0; i < ell; i++){
		sigma[i] = (int)c.c3(i) ^ (int)mu(i);
	}
	//Compute hash value of sigma//
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
	//Find h value//
	unsigned int seed = (unsigned int)sigmahash[1][1];
	srand(seed);
	VectorXi h(ell);
	for(i = 0; i < ell; i++){h[i] = rand() % 2;}
	//Find message//
	for(i = 0; i < ell; i++){m[i] = (int)c.c4(i) ^ (int)h(i);}
	//Encrypt with given sigma and message//
	PKECtxt c_test = PKEKey::Encrypt_with_sigma(m,sigma);
	//Test for CCA secure//
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
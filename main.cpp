#include <iostream>
#include <Eigen/Dense>
#include "PKEKey.h"
#include <ctime>
#include <sys/time.h>
#include <string>
#include <math.h>

#define Test_Num 1000

using namespace std;

//Parameter//
const PKEParams& params(PKE_5);

int main(){
	unsigned long i, j;
	//Cycles//
	//unsigned long long t;
	//Real Times//
	struct timeval t1, t2;
	double e;
	double e1, e2, e3;
	e1 = 0; e2 = 0; e3 = 0;
    vector<bool> m;
    vector<bool> decm;
    	

	for(i = 0; i < Test_Num; i++){
		//Benchmark//
		//KeyGen//
		gettimeofday(&t1, 0);
		PKEKey key(params);
		gettimeofday(&t2, 0);
		e = (t2.tv_sec - t1.tv_sec) * 1000.0;
	    e += (t2.tv_usec - t1.tv_usec) / 1000.0;
    	e1 += e;	

    	//Message Select//
		m.resize(key.ell);
		decm.resize(key.ell);
		for(j = 0; j < key.ell; j++){
			m[j] = rand() % 2;
		}

    	//Encryption//
		gettimeofday(&t1, 0);
		PKECtxt c = key.Encrypt(m);
		gettimeofday(&t2, 0);
		e = (t2.tv_sec - t1.tv_sec) * 1000.0;
	    e += (t2.tv_usec - t1.tv_usec) / 1000.0;
    	e2 += e;

    	//Decryption//
    	gettimeofday(&t1, 0);
    	key.Decrypt(decm, c);
    	gettimeofday(&t2, 0);
		e = (t2.tv_sec - t1.tv_sec) * 1000.0;
	    e += (t2.tv_usec - t1.tv_usec) / 1000.0;
    	e3 += e;

    	if(i == 0){
    		cout << key << std::endl;
    		cout << c << std::endl;
    	}
    	//Debug for Enc/Dec TEST//
    	for(j = 0; j < key.ell; j++){if(m[j] != decm[j]){std::cerr << "Enc/Dec Error!!!\n";}}
	}
	cout << "* KeyGen Time : " << e1 / Test_Num << "ms" << endl;
	cout << "* Encrypt Time : " << e2 / Test_Num << "ms" << endl;
	cout << "* Decrypt Time : " << e3 / Test_Num << "ms" << endl;

	return 0;
}
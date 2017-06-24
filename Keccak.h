#include <stdio.h>
#include <iosteam>
#include <stdint.h>

const uint64_t r[5][5]={ {0,36,3,41,18}, {1,44,10,45,2}, {62,6,43,15,61}, {28,55,25,21,56},{27,20,39,8,14}};
uint64_t **sha3_round(uint64_t **A, uint64_t RC){
	uint8_t x, y;
	uint64_t C[5];
	uint64_t D[5];
	uint64_t B[5][5];
	// theta step
	for(x = 0; x < 5; x++){C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4];}
	for(x = 0; x < 5; x++){D[x] = C[(x + 4) % 5] ^ ((C[(x + 1) % 5] << 1) | (C[(x + 1) % 5] >> 63));}
	for(x = 0; x < 5; x++){for(y = 0; y < 5; y++){A[x][y] = A[x][y] ^ D[x];}}
	// rho and phi step
	for(x = 0;x < 5; x++){for(y = 0; y < 5; y++){B[y][mod((2 * x + 3 * y),5)] = ((A[x][y] << r[x][y]) | (A[x][y] >> (64-r[x][y])));}}
	// xi step
	for(x = 0; x < 5; x++){for(y = 0; y < 5; y++){A[x][y] = B[x][y] ^ ((~B[mod((x+1),5)][y]) & B[mod((x+2),5)][y]);}}
	// XOR step
	A[0][0] = A[0][0] ^ RC;
	return A;
}

//Round constant in keccak//
const uint64_t RC[24]={ 0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
		       			0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
		       			0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
		       			0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
		       			0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
		       			0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008};

//keccak fuction with sha3 round function: input and output is 5 by 5 uint64 matrix
uint64_t **keccak_f(uint64_t **A){
  for(int32_t i = 0; i < 24; i++){
    A = sha3_round(A,RC[i]);
  }
  return A;
}
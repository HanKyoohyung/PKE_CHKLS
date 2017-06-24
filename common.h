#include <iostream>
#include <stdio.h>

inline int mod (int a, int b){
	if(b < 0)
		return mod(-a, -b);
	int ret = a % b;
	if(ret < 0)
		ret += b;
	return ret;
}

inline bool mod2(int x){
	if(ABS(x) % 2 == 0){
		return 0;
	}
	else{return 1;}
}

inline int modplus(int x, int y){
	int z;
	if(x >= 0){z = x % y;}
	else{z = (y - ((-x) % y));}
	if(z < y){return z;}
	else{return 0;}
}

inline int modnear(int x, int y){
	int z;
	x += (y / 2);
	z = modplus(x, y);
	z -= (y / 2);
	return z;
}
#include <stdio.h>
#include <stdint.h>

#define MAX_FDS 1024 

void print_bits(uint64_t bitmap) {
	for (int i = MAX_FDS-1; i >= 0; i--) {
        putchar((bitmap & (1ULL << i)) ? '1' : '0');
    }
    putchar('\n');
}

int main(void) {

	uint64_t bitmap [MAX_FDS/64];

	// set b = 122'th bit 
	for (int word = 0; word < MAX_FDS; word++) {
		uint64_t b64 = bitmap[word];
		for (int bit = 0; bit < 64; bit++) {
			int fd = (word << 6) + bit;
			/*
			 * (word << 6) == word * 2^6
			 * gives the starting FD no. for 
			 * each word 
			 * (e.g.) word 1 is bits 64-127
			 * , or the 2nd uint64_t in array
			 * 1 << 6 == 1 * 64 = bit 64, exactly
			 * arr[1]
			 *
			 * '+ bit' just moves through 
			 * each bit 0..63 in each word 
			 *
			*/
			if (fd == 122) {
				// set it 
				bitmap[word] |= 1ULL << bit;
				// clear it 
				bitmap[word] &= ~(1ULL << bit);
				// check if set 
				int8_t set = bitmap[word] & (1ULL << bit)
					? 1 : 0;
			}
		}
	}

	return 0;
}

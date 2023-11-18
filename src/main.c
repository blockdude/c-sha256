#include <stdio.h>
#include <stdint.h>
#include <string.h>

/*
 * sha256 implimentation in c
 */

/*
 * Resources:
 * https://csrc.nist.gov/pubs/fips/180-4/upd1/final
 * https://en.wikipedia.org/wiki/SHA-2
 * https://datatracker.ietf.org/doc/html/rfc6234
 *
 * https://www.youtube.com/watch?v=orIgy2MjqrA
 *
 * https://rbtblog.com/posts/SHA256-Algorithm-Implementation-in-C/
 * https://github.com/B-Con/crypto-algorithms/blob/master/sha256.c
 * https://opensource.apple.com/source/clamav/clamav-158/clamav.Bin/clamav-0.98/libclamav/sha256.c.auto.html
 * https://github.com/amosnier/sha-2/blob/master/sha-256.c
 * https://github.com/openssl/openssl/blob/master/crypto/sha/sha256.c
 * https://android.googlesource.com/platform/system/core/+/669ecc2f5e80ff924fa20ce7445354a7c5bcfd98/libmincrypt/sha256.c
 */

void print_message_block( uint8_t *m )
{
	for ( size_t i = 0; i < 64; i += 4 )
	{
		printf( "%.2x", m[ i + 3 ] ); printf( " " );
		printf( "%.2x", m[ i + 2 ] ); printf( " " );
		printf( "%.2x", m[ i + 1 ] ); printf( " " );
		printf( "%.2x", m[ i     ] ); printf( " " );
		printf( "\n" );
	}
}

void print_hash( const uint8_t *hash )
{
	for ( size_t i = 0; i < 32; i++ )
		printf( "%02x", hash[ i ] );
	printf( "\n" );
}

/*
 * Choose. Using the input from x we will choose which bits to take and return from y and z.
 * If a bit in x is 0 take the bit in the same place from z else take the bit from y.
 * Do this for all 32 bits and return the result.
 */

#define CH( x, y, z ) ( ( ( x ) & ( y ) ) ^ ( ~( x ) & ( z ) ) )

/*
 * Majority. Using the input from x, y and z, a resulting bit is determined by
 * the majority count of bit values in that column of bits. So, if a column has
 * a 1 for x, a 0 for y, and a 0 for z then the majority is 0 so return 0.
 */

#define MAJ( x, y, z ) ( ( ( x ) & ( y ) ) ^ ( ( x ) & ( z ) ) ^ ( ( y ) & ( z ) ) )

/*
 * Rotate right. Similar to right shift of bits but the least significant bit is
 * wrapped around to the most significant bit.
 */

#define ROTR( x, n ) ( ( ( x ) >> ( n ) ) | ( ( x ) << ( 32 - ( n ) ) ) )

/*
 * Rotate left. Similar to left shift of bits but the most significant bit is
 * wrapped around to the least significant bit.
 */

#define ROTL( x, n ) ( ( ( x ) << ( n ) ) | ( ( x ) >> ( 32 - ( n ) ) ) )

/*
 * big sigma functions provided by the sha docs
 */

#define e0( x ) ( ROTR( ( x ),  2 ) ^ ROTR( ( x ), 13 ) ^ ROTR( ( x ), 22 ) )
#define e1( x ) ( ROTR( ( x ),  6 ) ^ ROTR( ( x ), 11 ) ^ ROTR( ( x ), 25 ) )

/*
 * small sigma functions provided by the sha docs
 */

#define s0( x ) ( ROTR( ( x ),  7 ) ^ ROTR( ( x ), 18 ) ^ ( ( x ) >>  3 ) )
#define s1( x ) ( ROTR( ( x ), 17 ) ^ ROTR( ( x ), 19 ) ^ ( ( x ) >> 10 ) )

/*
 * helper macros
 */

#define BYTESWAP( x )	( ( ROTR( ( x ), 8) & 0xff00ff00 ) | ( ROTL( ( x ), 8 ) & 0x00ff00ffL ) )
#define MIN( a, b )		( ( a ) < ( b ) ? ( a ) : ( b ) )
#define MAX( a, b )		( ( a ) > ( b ) ? ( a ) : ( b ) )

/**
 * sha256 - produce a hash sum from data
 * @data: input data to be hashed into sha256
 * @len: length of data in number of bytes
 * @md: output message digest of length 256 bits that needs to be provided by caller
 *
 * Will generate a hash using the sha256 algorithm given an input with a bit
 * length of l, where 0 <= l < 2^64 bits.
 *
 * Return: pointer to the message digest
 */

uint8_t *sha256( const uint8_t *data, size_t len )
{

	/*
	 * These are 64, 32 bit constants for k. These words represent the first 32
	 * bits of the fractional parts of the cube roots of the first sixty-four prime
	 * numbers.
	 */
	
	static const uint32_t K[] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};

	/*
	 * Hash value. This will be what will hold the intermediate hash value after
	 * each message block is processed with the last iteration resulting in the
	 * final hash value. We initialized it with 8, 32 bit constants representing
	 * the initial hash value. These constants are the first 32 bits of the
	 * fractional parts of the square roots of the first eight prime numbers.
	 */

	uint32_t H[] = {
		0x6a09e667,
		0xbb67ae85,
		0x3c6ef372,
		0xa54ff53a,
		0x510e527f,
		0x9b05688c,
		0x1f83d9ab,
		0x5be0cd19
	};

	/*
	 * Begin processing each message block.
	 */

	size_t data_pos = 0;
	size_t N = ( len / 64 ) + 1 + ( len % 64 >= 56 ? 1 : 0 );
	for ( size_t i = 1; i <= N; i++ )
	{
		/*
		 * Message block. Each message block is the i'th block of 512 bits from our input
		 * data.
		 */

		uint32_t M[ 16 ] = { 0 };

		/*
		 * Message schedule. This to store our expanded message block. Not
		 * really sure of the finer details to why we expand it.
		 */

		uint32_t W[ 64 ];

		/*
		 * Working variables. Used as temporary variables to hold the values we will
		 * use to update our hash value after compressing our message schedule.
		 */

		uint32_t a, b, c, d, e, f, g, h, T1, T2;

		/*
		 * Prepare the message block using our input data and pad our message
		 * block if needed.
		 */

		// copy our data to our message block
		size_t msgblk_len = MIN( len - data_pos, 64 );
		if ( msgblk_len > 0 ) memcpy( M, &data[ data_pos ], msgblk_len );
		data_pos += msgblk_len;

		// pad message
		if ( ( msgblk_len < 64 && msgblk_len != 0 ) || ( len % 64 == 0 && i == N ) )
			( ( uint8_t * ) M )[ msgblk_len ] = 0x80;

		// convert the message to big endian
		for ( size_t w = 0; w < 16; w++ )
			M[ w ] = BYTESWAP( M[ w ] );

		// last 64 bits is the bit length of our message
		if ( i == N )
		{
			uint64_t bitlen = ( uint64_t ) len * 8;
			M[ 15 ] = bitlen;
			M[ 14 ] = bitlen >> 32;
		}

		/*
		 * Prepare the message schedule using the rules below.
		 * Wt = Mt												 0 <= t <= 15
		 *	  = s1(W(t-2)) + W(t-7) + s0(W(t-15)) + W(t-16)		16 <= t <= 63
		 */

		for ( size_t t =  0; t < 16; t++ ) W[ t ] = M[ t ];
		for ( size_t t = 16; t < 64; t++ ) W[ t ] = s1( W[ t - 2 ] ) + W[ t - 7 ] + s0( W[ t - 15 ] ) + W[ t - 16 ];

		/*
		 * Initialize our working variables with our intermediate hash values
		 */

		a = H[ 0 ];
		b = H[ 1 ];
		c = H[ 2 ];
		d = H[ 3 ];
		e = H[ 4 ];
		f = H[ 5 ];
		g = H[ 6 ];
		h = H[ 7 ];

		/*
		 * Compute the working variables. This compresses our message schedule.
		 */

		for ( int t = 0; t < 64; t++ )
		{
			T1 = h + e1( e ) + CH( e, f, g ) + K[ t ] + W[ t ];
			T2 = e0( a ) + MAJ( a, b, c );
			h  = g;
			g  = f;
			f  = e;
			e  = d + T1;
			d  = c;
			c  = b;
			b  = a;
			a  = T1 + T2;
		}

		/*
		 * Update the intermediate hash value with our compressed message block.
		 */

		H[ 0 ] += a;
		H[ 1 ] += b;
		H[ 2 ] += c;
		H[ 3 ] += d;
		H[ 4 ] += e;
		H[ 5 ] += f;
		H[ 6 ] += g;
		H[ 7 ] += h;
	}

	/*
	 * Copy our final hash value into the message digest and return it. Note
	 * that our final hash value is in little endian so I convert it to big
	 * endian before copying it to our message digest.
	 */

	H[ 0 ] = BYTESWAP( H[ 0 ] );
	H[ 1 ] = BYTESWAP( H[ 1 ] );
	H[ 2 ] = BYTESWAP( H[ 2 ] );
	H[ 3 ] = BYTESWAP( H[ 3 ] );
	H[ 4 ] = BYTESWAP( H[ 4 ] );
	H[ 5 ] = BYTESWAP( H[ 5 ] );
	H[ 6 ] = BYTESWAP( H[ 6 ] );
	H[ 7 ] = BYTESWAP( H[ 7 ] );

	static uint8_t md[ 32 ];
	memcpy( md, H, 32 );

	return md;
}

int main()
{
	uint8_t *hsh = NULL;

	const size_t msg_len = 1000;
	uint8_t msg[ msg_len ];
	for ( size_t i = 0; i < msg_len; i++ ) msg[ i ] = 'a';

	hsh = sha256( msg, msg_len );
	print_hash( hsh );

	return 0;
}

#! /usr/bin/env python
'''
	jsSHA HMAC Test Result Generator
	Version 1.0 Copyright Brian Turek 2009
	Distributed under the BSD License
	See http://jssha.sourceforge.net/ for more information
'''
import hashlib
import hmac

def main():
	'''
	main()

	Calculates the HMAC of the test vectors given in FIPS-198a for full
	length HMACs.  Uses double the key sizes for SHA-384 and SHA-512 as
	they have double the block size
	'''
	# shortKey tests for handling of key lengths less than the block size
	shortTxt = b'Sample #2'
	shortKey = bytes.fromhex('30313233 34353637 38393a3b 3c3d3e3f 40414243')

	# medKey tests for handling of keys lengths equal to the block size
	medTxt = b'Sample #1'
	medKey = bytes.fromhex('00010203 04050607 08090a0b 0c0d0e0f 10111213' +
		'14151617 18191a1b 1c1d1e1f 20212223 24252627 28292a2b 2c2d2e2f'+
		'30313233 34353637 38393a3b 3c3d3e3f')

	# largeKey tests for handling of keys lengths greater than the block size
	largeTxt = b'Sample #3'
	largeKey = bytes.fromhex('50515253 54555657 58595a5b 5c5d5e5f 60616263'+
		'64656667 68696a6b 6c6d6e6f 70717273 74757677 78797a7b 7c7d7e7f' +
		'80818283 84858687 88898a8b 8c8d8e8f 90919293 94959697 98999a9b' +
		'9c9d9e9f a0a1a2a3 a4a5a6a7 a8a9aaab acadaeaf b0b1b2b3')

	# Perform the SHA-1 Tests
	print('\nSHA-1 Short Key Result:')
	print(hmac.new(shortKey, shortTxt, hashlib.sha1).hexdigest())
	print('\nSHA-1 Medium Key Result:')
	print(hmac.new(medKey, medTxt, hashlib.sha1).hexdigest())
	print('\nSHA-1 Large Key Result:')
	print(hmac.new(largeKey, largeTxt, hashlib.sha1).hexdigest())

	# Perform the SHA-224 Tests
	print('\nSHA-224 Short Key Result:')
	print(hmac.new(shortKey, shortTxt, hashlib.sha224).hexdigest())
	print('\nSHA-224 Medium Key Result:')
	print(hmac.new(medKey, medTxt, hashlib.sha224).hexdigest())
	print('\nSHA-224 Large Key Result:')
	print(hmac.new(largeKey, largeTxt, hashlib.sha224).hexdigest())

	# Perform the SHA-256 Tests
	print('\nSHA-256 Short Key Result:')
	print(hmac.new(shortKey, shortTxt, hashlib.sha256).hexdigest())
	print('\nSHA-256 Medium Key Result:')
	print(hmac.new(medKey, medTxt, hashlib.sha256).hexdigest())
	print('\nSHA-256 Large Key Result:')
	print(hmac.new(largeKey, largeTxt, hashlib.sha256).hexdigest())

	# Since SHA-384 and SHA-512 take double the block size, double the key
	# length so the tests act against the same functions as above
	shortKey = shortKey * 2
	medKey = medKey * 2
	largeKey = largeKey * 2

	# Perform the SHA-384 Tests
	print('\nSHA-384 Short Key Result:')
	print(hmac.new(shortKey, shortTxt, hashlib.sha384).hexdigest())
	print('\nSHA-384 Medium Key Result:')
	print(hmac.new(medKey, medTxt, hashlib.sha384).hexdigest())
	print('\nSHA-384 Large Key Result:')
	print(hmac.new(largeKey, largeTxt, hashlib.sha384).hexdigest())

	# Perform the SHA-512 Tests
	print('\nSHA-512 Short Key Result:')
	print(hmac.new(shortKey, shortTxt, hashlib.sha512).hexdigest())
	print('\nSHA-512 Medium Key Result:')
	print(hmac.new(medKey, medTxt, hashlib.sha512).hexdigest())
	print('\nSHA-512 Large Key Result:')
	print(hmac.new(largeKey, largeTxt, hashlib.sha512).hexdigest())

if ('__main__' == __name__):
	main()

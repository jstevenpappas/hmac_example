#!/usr/bin/env python2.7

import base64
import hashlib
import hmac
"""
https://samritchie.net/2011/09/07/implementing-aws-authentication-for-your-own-rest-api/
How this is secure:

Because the server knows the secret key of the client making the request
it can calculate the signature itself on the request and see if it matches
that passed by the client.
Also, it can check the date header a/g server time to check for replay attacks.
"""

def main():
	authorization_scheme_name = 'AWS '
	access_key_id = '44CF9590006BF252F707'
	secret_access_key = 'OtxrzxIsfpFjA7SwPzILwy8Bw21TLhquhboDYROV'
	key_signature_delim = ':'

	# Canonicalization for Authorization Header Authentication Example
	#
	# NOTE:  the resource below is the bucket/key (e.g., quotes/nelson)
	#
	# use hash function HMAC-SHA1 to sign your request using your Secret Access Key
	# The string to be signed is formed by appending:
	#  1) the REST verb
	#  2) content-md5 value
	#  3) content-type value
	#  4) date value
	#  5) canonicalized x-amz headers

	# HMAC-SHA1 hash signature
	h = hmac.new(secret_access_key,
				 "PUT\n"
				 "c8fdb181845a4ca6b8fec737b3581d76\n"
				 "text/html\n"
				 "Thu, 17 Nov 2005 18:49:58 GMT\n"
				 "x-amz-magic:abracadabra\n"
				 "x-amz-meta-author:foo@bar.com\n"
				 "/quotes/nelson",
				 hashlib.sha1)

	# Base64 result and use as resultant signature
	signature = base64.encodestring(h.digest()).strip()

	print 'PUT /quotes/nelson HTTP/1.0'
	print 'Authorization: {scheme}{access_key_id}{delim}{sha1_sig}'.format(
		scheme=authorization_scheme_name,
		access_key_id=access_key_id,
		delim=key_signature_delim,
		sha1_sig=signature)
	print 'Content-Md5: c8fdb181845a4ca6b8fec737b3581d76'
	print 'Content-Type: text/html'
	print 'Date: Thu, 17 Nov 2005 18:49:58 GMT'
	print 'X-Amz-Meta-Author: foo@bar.com'
	print 'X-Amz-Magic: abracadabra'

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
>>> blinder = Blinder.generate(256)
>>> blinding_factor, blinded_msg = blinder.blind(b'msg')
>>> sig = blinder.sign(blinded_msg)
>>> blinder.verify(b'msg', sig, blinding_factor)
True
>>> blinder.verify(b'msg', b'invalid signature', blinding_factor)
False
>>> blinder.verify(b'msg', sig, bignum.BigNum(142978))
False
"""
import bignum
import msgpack
import hashlib

class Blinder:
	"""Make and verify blinded signatures."""

	@classmethod
	def generate(class_, bits):
		"""Generate a Blinder on the basis of an RSA key of bits bits."""
		
		# Generate two primes of bits/2. When multiplied, they'll make an RSA key of
		# bits bits.
		p = bignum.generate_prime(bits//2)
		q = bignum.generate_prime(bits//2)

		# Calculate the totient of p*q.
		φ = (p-1) * (q-1)

		# e *must* be less than φ(p*q). This should never be a problem if you choose
		# any reasonable value for bits, but it might be a problem in an example or
		# such.
		if 65537 > φ:
			e = bignum.BigNum(3)
		else:
			e = bignum.BigNum(65537)
			
		# Generate our private key.
		d = pow(e, -1, φ)

		return class_(n=p*q, e=e, d=d)

	@classmethod
	def deserialize(class_, serialized):
		"""Load a Blinder instance serialized with Blinder.serialize().
		
		>>> b = Blinder.generate(256)
		>>> b_ = Blinder.deserialize( b.serialize() )
		>>> all(getattr(b, _) == getattr(b_, _) for _ in 'ned')
		True
		"""

		data = msgpack.loads(serialized)
		return class_( data[b'n'], data[b'e'], data[b'd'] )

	def serialize(self):
		"""Return a bytes representation of ourselves."""

		return msgpack.dumps({
			attr: getattr(self, attr).serialize() for attr in 'ned'
		})

	def __init__(self, n, e, d=None):
		def b(_):
			if isinstance(_, bignum.BigNum):
				return _
			elif isinstance(_, int):
				return bignum.BigNum(_)
			elif isinstance(_, bytes):
				return bignum.BigNum.deserialize(_)
			else:
				raise TypeError("Blinder() arguments must be convertible to BigNums")

		self.n = b(n)
		self.e = b(e)
		self.d = (d and b(d))

	@property
	def public(self):
		"""Return a public key."""

		return type(self)(self.n, self.e)

	def is_public(self):
		"""Is this a public key?"""

		return not(self.d)

	def is_private(self):
		"""Is this a private key?"""

		return bool(self.d)

	def _bignum_digest(self, msg):
		"""Return the BigNum representation of a SHA512 digest of msg modulo N.

		>>> b = Blinder.generate(256)
		>>> b._bignum_digest(b"leni") == b._bignum_digest(b"leni")
		True
		>>> b._bignum_digest(b"hanging") == b._bignum_digest(b"tree")
		False
		"""
		
		return bignum.BigNum.deserialize( hashlib.sha512(msg).digest() ) % self.n

	def blind(self, msg):
		"""Blind a message msg to self (where msg is a bytes instance). We return a
		tuple (blinding_factor, blinded_sig). (blinding_factor is a BigNum and
		blinded_sig is a bytes instance.)"""
		
		m = self._bignum_digest(msg)
		r = bignum.generate_random_bignum(len(self.n))
		blinded = pow(r, self.e, self.n) * (m % self.n)

		return (r, blinded.serialize())

	def sign(self, blinded_msg):
		"""Sign a message blinded_msg that has already been blinded by blind().
		DANGER: If you don't pad the amount of time this takes to a fixed amount,
		you will reveal your secret key."""
		
		if not self.d:
			raise NotImplementedError("we can't sign stuff (we're not a private key)")
		
		m = bignum.BigNum.deserialize(blinded_msg)
		return pow(m, self.d, self.n).serialize()

	def _unblind(self, blinded_sig, blinding_factor):
		"""Unblind a signature blinded_sig of a message that has been blinded with
		blinding_factor."""
		
		bs = bignum.BigNum.deserialize(blinded_sig)
		s = bs * pow(blinding_factor, -1, self.n)
		return s.serialize()

	def _verify(self, message, signature):
		"""Verify a signature of an unblinded message signed by self. We return True
		if the signature is valid and False otherwise."""
		
		m = self._bignum_digest(message)
		s = bignum.BigNum.deserialize(signature)
		
		return (pow(s, self.e, self.n) == m)
	
	def verify(self, message, blinded_sig, blinding_factor):
		"""Verify that a blinded message signature (blinded_sig) is the result of
		self blindly signing the message message that has been blinded with
		blinding_factor.
		"""
		
		return self._verify(message, self._unblind(blinded_sig, blinding_factor))
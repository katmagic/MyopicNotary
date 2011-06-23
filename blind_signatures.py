#!/usr/bin/env python3
"""
>>> blinder = Blinder.generate(256)
>>> blinding_factor, blinded_msg = blinder.public.blind(b'msg')
>>> sig = blinder.public.unblind( blinder.sign(blinded_msg), blinding_factor )
>>> blinder.public.verify(b'msg', sig)
True
>>> blinder.public.verify(b'msg', b'invalid signature')
False
"""

from ctypes import *
from ctypes.util import find_library
import msgpack
import hashlib
import math

__libssl_name = find_library('ssl')
if not __libssl_name:
	raise ImportError("OpenSSL must be installed to use this module.")
libssl = CDLL(__libssl_name)
libssl.ERR_load_crypto_strings()

def randint(bits, entropy_source=open('/dev/urandom', 'rb')):
	"""Generate a random number with bits of entropy."""

	rlen, extra_len = divmod(bits, 8)
	if extra_len:
		extra = chr( ord(entropy_source.read(1)) & ((1 << extra_len) - 1) ).encode()
	else:
		extra = b''

	return int.from_bytes(extra + entropy_source.read(rlen), 'big')

def generate_prime(bits):
	"""Generate a prime with bits bits."""

	prime = c_void_p( libssl.BN_new() )
	libssl.BN_init(prime)

	libssl.BN_generate_prime(prime, c_int(bits), c_int(0), c_void_p(), c_void_p(),
	                         c_void_p(), c_void_p())
	
	prime_repr = create_string_buffer( math.ceil(libssl.BN_num_bits(prime)/8) )
	libssl.BN_bn2bin(prime, prime_repr)

	libssl.BN_clear_free(prime)

	return _b_to_i(prime_repr)

def mod_inverse(a, m):
	"""a¯¹ (mod m)

	>>> mod_inverse(1, 42978)
	1
	>>> mod_inverse(14, 2978)
	Traceback (most recent call last):
	...
	RuntimeError: b'no inverse'
	>>> mod_inverse(142, 978)
	Traceback (most recent call last):
	...
	RuntimeError: b'no inverse'
	>>> mod_inverse(1429, 78)
	25
	>>> mod_inverse(14297, 8)
	1
	"""

	if not (isinstance(a, int) and isinstance(m, int)):
		raise TypeError("Arguments to mod_inverse must be ints")

	def i_to_bn(i):
		"""Turn i into a BIGNUM."""

		i_repr = create_string_buffer(str(i).encode())
		i_bn = c_void_p()
		libssl.BN_dec2bn(pointer(i_bn), i_repr)
		return i_bn

	def bn_to_i(bn):
		"""Turn a bn into an int."""

		s = libssl.BN_bn2dec(bn)
		res = int(string_at(s))
		libssl.CRYPTO_free(s)
		return res

	ctx = libssl.BN_CTX_new()
	libssl.BN_CTX_init(ctx)

	a_bn = i_to_bn(a)
	m_bn = i_to_bn(m)

	res_bn = libssl.BN_mod_inverse(c_void_p(), a_bn, m_bn, ctx)
	if not res_bn:
		err = libssl.ERR_reason_error_string(libssl.ERR_get_error())
		raise RuntimeError( str(string_at(err)) )
	res = bn_to_i(res_bn)

	libssl.BN_CTX_free(ctx)
	for _ in a_bn, m_bn, res_bn:
		libssl.BN_clear_free(_)

	return res

def _i_to_b(i):
	if i is None:
		return None

	return i.to_bytes(math.ceil(i.bit_length()/8), 'big')

def _b_to_i(b):
	if b is None:
		return None

	return int.from_bytes(b, 'big')

class Blinder:
	"""Make and verify blinded signatures."""

	_pub_attrs = ('n', 'e')
	_priv_attrs = ('n', 'e', 'p', 'q', 'dP', 'dQ', 'qInv')

	@classmethod
	def generate(class_, bits):
		"""Generate a Blinder on the basis of an RSA key of bits bits."""

		res = class_.__new__(class_)

		# Generate two primes of bits/2. When multiplied, they'll make a semiprime
		# of bits bits, which will be the basis of our key.
		res.p = generate_prime(bits//2)
		res.q = generate_prime((bits+1)//2)
		res.n = res.p * res.q

		# Set e to a constant value.
		res.e = 65537

		# Compute values to use for signatures using the Chinese Remainder Theorem.
		res.dP = mod_inverse(res.e, res.p-1)
		res.dQ = mod_inverse(res.e, res.q-1)
		res.qInv = mod_inverse(res.q, res.p)

		return res

	@classmethod
	def deserialize(class_, serialized):
		"""Load a Blinder instance serialized with Blinder.serialize().

		>>> b = Blinder.generate(256)
		>>> b_ = Blinder.deserialize( b.serialize() )
		>>> all(getattr(b, _) == getattr(b_, _) for _ in Blinder._priv_attrs)
		True
		>>> p = b.public
		>>> p_ = Blinder.deserialize( p.public.serialize() )
		>>> all(getattr(p, _) == getattr(p_, _) for _ in Blinder._pub_attrs)
		True
		"""

		data = msgpack.loads(serialized)
		data = {k.decode(): v for k, v in data.items()}

		return class_(**{
			_: _b_to_i(data[_]) for _ in class_._priv_attrs
		})

	def serialize(self):
		"""Return a bytes representation of ourselves."""

		return msgpack.dumps({
			_: _i_to_b(getattr(self, _, None)) for _ in self._priv_attrs
		})

	def __init__(self, n, e, p=None, q=None, dP=None, dQ=None, qInv=None):
		for _ in self._priv_attrs:
			setattr(self, _, locals()[_])

			if (getattr(self, _) or 0).bit_length() > 4096:
				raise OverflowError(_ + " is too large")

	@property
	def public(self):
		"""Return a public key."""

		return type(self)(self.n, self.e)

	def is_public(self):
		"""Is this a public key?"""

		return not(self.is_private())

	def is_private(self):
		"""Is this a private key?"""

		for attr in self._priv_attrs:
			if not getattr(self, attr):
				return False

		return True

	def _int_digest(self, msg):
		"""Return the int representation of a SHA512 digest of msg modulo N.

		>>> b = Blinder.generate(256)
		>>> b._int_digest(b"leni") == b._int_digest(b"leni")
		True
		>>> b._int_digest(b"hanging") == b._int_digest(b"tree")
		False
		"""
		
		# Pad digests so that they have they have the same length as self.n.
		hasher = hashlib.sha512(msg)
		dgst = b''

		for i in range( math.ceil(self.n.bit_length()/(8 * hasher.digest_size)) ):
			hasher.update( bytes((i,)) )
			dgst += hasher.digest()

		# Mask dgst to the length of self.n.
		dgst = _b_to_i(dgst) % (1 << self.n.bit_length())
		# And then ensure that dgst is less than self.n.
		dgst = dgst % self.n

		return dgst

	def blind(self, msg):
		"""Blind a message msg to self (where msg is a bytes instance). We return a
		tuple (blinding_factor, blinded_sig). (blinding_factor is a BigNum and
		blinded_sig is a bytes instance.)"""

		m = self._int_digest(msg)
		r = randint(self.n.bit_length())
		blinded = pow(r, self.e, self.n) * (m % self.n)

		return (r, _i_to_b(blinded))

	def sign(self, blinded_msg):
		"""Sign a message blinded_msg that has already been blinded by blind().
		DANGER: If you don't pad the amount of time this takes to a fixed amount,
		you will reveal your secret key."""

		if not self.is_private():
			raise NotImplementedError("we can't sign stuff (we're not a private key)")

		m = _b_to_i(blinded_msg)

		s1 = pow(m, self.dP, self.p)
		s2 = pow(m, self.dQ, self.q)
		h = (self.qInv * (s1 - s2)) % self.p
		s = s2 + h*self.q

		return _i_to_b(s)

	def unblind(self, blinded_sig, blinding_factor):
		"""Unblind a signature blinded_sig of a message that has been blinded with
		blinding_factor."""

		bs = _b_to_i(blinded_sig)
		s = bs * mod_inverse(blinding_factor, self.n)
		return _i_to_b(s)

	def verify(self, message, signature):
		"""Verify a signature of an unblinded message signed by self. We return True
		if the signature is valid and False otherwise."""

		m = self._int_digest(message)
		s = _b_to_i(signature)

		return (pow(s, self.e, self.n) == m)


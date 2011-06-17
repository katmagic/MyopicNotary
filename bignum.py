#!/usr/bin/env python3
"""
Use BigNums from OpenSSL. You shouldn't usually need this because Python
supports arbitrarily large integers anyway.

>>> BigNum(5) + 6
BigNum(11)
>>> BigNum(11) * 2
BigNum(22)
>>> pow(BigNum(731), BigNum(297), BigNum(167))
BigNum(4)
"""
from ctypes import *
from ctypes.util import find_library
from threading import local
import functools
import math

__libssl_name = find_library('ssl')
if not __libssl_name:
	raise ImportError("OpenSSL must be installed to use this module.")
libssl = CDLL(__libssl_name)

for funcname, argtypes, *restype in (
	('new', 0, c_void_p),
	('init', 1, None),
	('bin2bn', (c_char_p, c_int, c_void_p), c_void_p),
	('bn2bin', (c_void_p, c_char_p)),
	('num_bits', 	1),
	('clear_free', 1, None),
	('add', 3),
	('sub', 3),
	('mul', 4),
	('sqr', 3),
	('mod_add', 5),
	('mod_sub', 5),
	('mod_mul', 5),
	('mod_sqr', 4),
	('exp', 4),
	('mod_exp', 5),
	('gcd', 4),
	('cmp', 2),
	('lshift', (c_void_p, c_void_p, c_int), c_int),
	('rshift', (c_void_p, c_void_p, c_int), c_int),
	('mod_inverse', 4, c_void_p),
	('CTX_new', 0, c_void_p),
	('CTX_init', 1, None),
	('CTX_free', 1, None),
	('is_prime', (c_void_p, c_int, c_void_p, c_void_p, c_void_p), c_void_p),
	('generate_prime', (c_void_p, c_int, c_int) + (c_void_p,)*4,  c_void_p)
):
	func = getattr(libssl, 'BN_' + funcname)

	if isinstance(argtypes, int):
		func.argtypes = (c_void_p,)*argtypes
	else:
		func.argtypes = argtypes

	if restype:
		func.restype = restype[0]
	else:
		func.restype = c_int

class __BN_CTX:
	"""This is an internal data structure used by OpenSSL."""

	def __init__(self):
		self._as_parameter_ = libssl.BN_CTX_new()
		libssl.BN_CTX_init(self)

	def __del__(self):
		if libssl:
			libssl.BN_CTX_free(self)

def ctx():
	"""Return a BN_CTX unique to this thread."""

	if not hasattr(ctx, 'local_data'):
		ctx.local_data = local()
		ctx.local_data.bn_ctx = __BN_CTX()

	return ctx.local_data.bn_ctx

@functools.total_ordering
class BigNum:
	"""Use an OpenSSL BIGNUM."""

	@classmethod
	def from_voidp(class_, voidp):
		"""Create a BigNum instance from a pointer to an OpenSSL BIGNUM.

		>>> voidp = libssl.BN_new()
		>>> libssl.BN_init(voidp)
		>>> libssl.BN_add(voidp, BigNum(142), BigNum(978))
		1
		>>> BigNum.from_voidp(voidp)
		BigNum(1120)
		"""

		bn = class_.__new__(class_)

		if isinstance(voidp, c_void_p):
			bn._as_parameter_ = voidp
		elif isinstance(voidp, int):
			bn._as_parameter_ = c_void_p(voidp)
		else:
			raise TypeError(
				"voidp must be a c_void_p or a c_int, not a %s" % type(voidp)
			)

		return bn

	def _ensure_arg_type(meth):
		"""Ensure that all the arguments of meth are BigNums."""

		def new_meth(*a, **kw):
			nonlocal meth

			args = list()
			kwargs = dict()

			for arg in a:
				if isinstance(arg, BigNum):
					args.append(arg)
				else:
					args.append( BigNum(arg) )

			for key, val in kw:
				if isinstance(val, BigNum):
					kwargs[key] = val
				else:
					kwargs[key] = BigNum(val)

			return meth(*args, **kwargs)

		return functools.update_wrapper(new_meth, meth)

	def __init__(self, i=0):
		"""Create a BigNum equal to i.

		>>> BigNum()
		BigNum(0)
		>>> BigNum(142978)
		BigNum(142978)
		>>> BigNum(-1)
		Traceback (most recent call last):
		...
		ValueError: BigNum() argument must be positive
		>>> BigNum('invalid')
		Traceback (most recent call last):
		...
		ValueError: BigNum() argument must be 'int', not 'str'
		"""

		if not isinstance(i, int):
			raise ValueError(
				"BigNum() argument must be 'int', not '%s'" % type(i).__name__
			)
		elif i < 0:
			raise ValueError("BigNum() argument must be positive")

		i_repr = i.to_bytes(math.ceil(i.bit_length()/8) or 1, 'big')
		self._as_parameter_ = libssl.BN_bin2bn(
			create_string_buffer(i_repr),
			len(i_repr),
			c_void_p()
		)

	def __del__(self):
		if libssl:
			libssl.BN_clear_free(self)

	@classmethod
	def from_param(class_, p):
		if isinstance(p, class_):
			raise ArgumentError("wrong type")

		return p

	def __int__(self):
		"""
		Return a native Python int.
		>>> int(BigNum(142978))
		142978
		"""

		i_repr_size = math.ceil(libssl.BN_num_bits(self)/8)
		i_repr = create_string_buffer(i_repr_size)
		libssl.BN_bn2bin(self, i_repr)
		return int.from_bytes(string_at(i_repr, i_repr_size), 'big')

	def __abs__(self):
		"""
		>>> b = BigNum(142978)
		>>> abs(b)
		BigNum(142978)
		>>> b is abs(b)
		True
		"""

		# We don't allow negative numbers.
		return self

	@_ensure_arg_type
	def __add__(self, x):
		"""
		>>> BigNum(142977) + 1
		BigNum(142978)
		>>> BigNum(142977) + BigNum(1)
		BigNum(142978)
		"""

		res = BigNum()
		libssl.BN_add(res, self, x)
		return res

	def __bool__(self):
		"""
		>>> bool(BigNum())
		False
		>>> bool(BigNum(0))
		False
		>>> bool(BigNum(1))
		True
		"""

		return (self != 0)

	def __ceil__(self):
		"""
		>>> b = BigNum(51)
		>>> b.__ceil__() is b
		True
		"""

		# We're always an integer.
		return self

	@_ensure_arg_type
	def __divmod__(self, x):
		"""
		>>> divmod(BigNum(1429), 78)
		(BigNum(18), BigNum(25))
		"""

		res = (BigNum(), BigNum())
		libssl.BN_div(res[0], res[1], self, x, ctx())
		return res

	def __eq__(self, x):
		"""
		>>> BigNum(142978) == BigNum(142978)
		True
		>>> BigNum(142) == BigNum(978)
		False
		>>> BigNum(142978) == 142978.0
		True
		>>> BigNum(142978) == (142978+0j)
		True
		>>> BigNum(142) == 978
		False
		>>> BigNum(142978) == 'blah'
		False
		>>> BigNum(142978) == -142978
		False
		>>> BigNum(142978) == (-142978+0j)
		False
		"""

		if isinstance(x, int) and (x >= 0):
			x = BigNum(x)
		elif isinstance(x, float) and x.is_integer() and (x >= 0):
			x = BigNum(int(x))
		elif isinstance(x, complex) and not(x.imag) and x.real.is_integer() and \
		     (x.real >= 0):
			x = BigNum(int(x.real))
		elif isinstance(x, BigNum):
			pass
		else:
			return False

		return (libssl.BN_cmp(self, x) == 0)

	def __float__(self):
		"""
		>>> float(BigNum(142978))
		142978.0
		"""

		return float(int(self))

	def __floor__(self):
		"""
		>>> b = BigNum(142978)
		>>> b.__floor__() is b
		True
		"""

		# We're always an integer.
		return self

	@_ensure_arg_type
	def __floordiv__(self, x):
		"""
		>>> BigNum(1429) // 78
		BigNum(18)
		"""

		return divmod(self, x)[0]

	def __format__(self, fs):
		return int(self).__format__(fs)

	@_ensure_arg_type
	def __gt__(self, x):
		"""
		>>> BigNum(142) > BigNum(978)
		False
		>>> BigNum(1429) > 78
		True
		"""

		return (libssl.BN_cmp(self, x) == 1)

	def __lshift__(self, x):
		"""
		>>> BigNum(14297) << 8
		BigNum(3660032)
		>>> BigNum(14297) << BigNum(8)
		Traceback (most recent call last):
			...
		TypeError: The right operand to an lshift must be an int.
		"""

		if not isinstance(x, int):
			raise TypeError("The right operand to an lshift must be an int.")

		res = BigNum()
		libssl.BN_lshift(res, self, x)
		return res

	@_ensure_arg_type
	def __mod__(self, x):
		"""
		>>> BigNum(1429) % 78
		BigNum(25)
		"""

		res = BigNum()
		libssl.BN_div(c_void_p(), res, self, x, ctx())
		return res

	@_ensure_arg_type
	def __mul__(self, x):
		"""
		>>> BigNum(142) * 978
		BigNum(138876)
		"""

		res = BigNum()
		libssl.BN_mul(res, self, x, ctx())
		return res

	def __pos__(self):
		"""
		>>> b = BigNum(5)
		>>> +b
		BigNum(5)
		>>> +b is b
		True
		"""

		return self

	def __pow__(self, x, y=None):
		"""
		>>> pow(BigNum(14), 29, 78)
		BigNum(14)
		>>> pow(BigNum(14297), 8)
		BigNum(1745658700859693673769171943693761)
		>>> pow(BigNum(1429), -1, 78)
		BigNum(25)
		"""

		if (x != -1) and not(isinstance(x, BigNum)):
			try:
				x = BigNum(x)
			except:
				raise RuntimeError(x)
		if y and not(isinstance(y, BigNum)):
			y = BigNum(y)

		res = BigNum()

		if y:
			if x == -1:
				libssl.BN_mod_inverse(res, self, y, ctx())
			else:
				libssl.BN_mod_exp(res, self, x, y, ctx())
		else:
			libssl.BN_exp(res, self, x, ctx())

		return res

	for m in ('add', 'and', 'divmod', 'floordiv', 'lshift', 'mod', 'mul', 'or',
	          'pow', 'rshift', 'shift', 'sub', 'truediv', 'xor'):
		locals()['r'+m] = _ensure_arg_type(lambda self, x: getattr(x, m)(self))
	del m

	def __repr__(self):
		"""
		>>> BigNum(142978)
		BigNum(142978)
		"""

		return "%s(%d)" % (type(self).__name__, int(self))

	def __sizeof__(self):
		raise NotImplementedError

	@_ensure_arg_type
	def __sub__(self, x):
		"""
		>>> BigNum(1429) - 78
		BigNum(1351)
		>>> BigNum(142) - 978
		Traceback (most recent call last):
		...
		ValueError: BigNum supports only positive integers.
		"""

		if self < x:
			raise ValueError("BigNum supports only positive integers.")

		res = BigNum()
		libssl.BN_sub(res, self, x)
		return res

	def __truediv__(self, x):
		"""
		>>> BigNum(142) / 978
		Traceback (most recent call last):
		...
		NotImplementedError: BigNum supports only integers.
		"""

		raise NotImplementedError("BigNum supports only integers.")

	def is_prime(self):
		"""Check if we're prime.

		>>> BigNum(142).is_prime()
		False
		>>> BigNum(1429).is_prime()
		True
		>>> BigNum(14297).is_prime()
		False
		>>> BigNum().is_prime()
		False
		>>> BigNum(1).is_prime()
		False
		"""

		return bool( libssl.BN_is_prime(self, 0, None, ctx(), None) )

def generate_prime(bits):
	"""Generate a prime of bits bits.

	>>> all(generate_prime(128).is_prime() for x in range(14))
	True
	"""

	bn = BigNum()
	libssl.BN_generate_prime(bn, bits, 0, None, None, None, None)
	return bn

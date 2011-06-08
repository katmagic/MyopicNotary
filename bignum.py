#!/usr/bin/env python3
from ctypes import *
from ctypes.util import find_library
import math

__libssl_name = find_library('ssl')
if not __libssl_name:
	raise ImportError("OpenSSL must be installed to use this module.")
libssl = CDLL(__libssl_name)

for funcname, argtypes, restype in (
	('new', (), c_void_p),
	('init', (c_void_p,), None),
	('bin2bn', (c_char_p, c_int, c_void_p), c_void_p),
	('bn2bin', (c_void_p, c_char_p), c_int),
	('num_bits', (c_void_p,), c_int),
	('clear_free', (c_void_p,), None)
):
	func = getattr(libssl, 'BN_' + funcname)
	func.argtypes = argtypes
	func.restype = restype

class BigNum:
	"""Use an OpenSSL BIGNUM."""

	@classmethod
	def _ensure_arg_type(ensured_type, meth):
		"""Ensure that all the arguments of meth are ensured_type instances."""

		def new_meth(*a, **kw):
			nonlocal ensured_type
			nonlocal meth

			args = list()
			kwargs = dict()

			for arg in a:
				if isinstance(ensured_type, arg):
					args.append(arg)
				else:
					args.append( ensured_type(arg) )

			for key, val in kw:
				if isinstance(ensured_type, val):
					kwargs[key] = val
				else:
					kwargs[key] = ensured_type(val)

			return meth(*args, **kwargs)

		return new_meth

	def __init__(self, i=0):
		if not isinstance(i, int):
			raise TypeError(
				"%s() argument must an int, not '%s'" % (type(self), type(i))
			)

		i_repr = i.to_bytes(math.ceil(i.bit_length()/8), 'big')
		self._as_parameter_ = libssl.BN_bin2bn(
			create_string_buffer(i_repr),
			len(i_repr),
			c_void_p()
		)

	def __del__(self):
		libssl.BN_clear_free(self._as_parameter_)

	def __int__(self):
		i_repr_size = math.ceil(libssl.BN_num_bits(self._as_parameter_)/8)
		i_repr = create_string_buffer(i_repr_size)
		libssl.BN_bn2bin(self._as_parameter_, i_repr)
		return int.from_bytes(string_at(i_repr, i_repr_size), 'big')

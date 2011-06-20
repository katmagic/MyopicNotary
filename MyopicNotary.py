#!/usr/bin/env python3
"""Create and verify blind signatures.

>>> m = MyopicNotary( ('127.0.0.1', 0), 3, '127.0.0.1',
...                   Blinder.generate(256).serialize() )
>>> threading.Thread(target=m.serve_once).start()
>>> c = NotaryClient.from_public_id( m.public_id )
>>> c.verify(b"token", c.request_sig(b"token"))
True
"""
from blind_signatures import Blinder
import threading
import logging
import socket
import select
import base64
import time

class MyopicError(Exception): pass

class MyopicNotary:
	"""MyopicNotary is a server that gives clients a tokens that shows (that we
	claimed) that that client waited for a designated amount of time."""

	def __init__( self, listen, wait_time, public_name, privkey,
	              logger=logging.getLogger("myopic_notary") ):
		"""listen is the (host, port) tuple we should listen on; wait_time is the
		amount of time (in seconds) that we make a client wait before giving them a
		token; public_name is the	domain or IP at which clients can access us;
		privkey is a serialized Blinder instance."""

		self.wait_time = wait_time
		self.public_name = public_name

		self._server = socket.socket()
		self._server.bind(listen)
		self._server.listen(8)

		self._logger = logger

		self.privkey = Blinder.deserialize(privkey)

		self.clients = set()

	@property
	def public_id(self):
		"""This is the identifier that is given to NotaryClients to use our
		services. It consists of our IP or DNS name, the port we listen on, the time
		(in seconds) that we require a client to wait before giving them a token,
		and our public key, seperated by colons."""

		port = self._server.getsockname()[1]
		pubkey = base64.b64encode( self.privkey.public.serialize() ).decode()

		return \
			"{self.public_name}:{port}:{self.wait_time}:{pubkey}".format(**locals())

	def serve_forever(self):
		while True:
			self.serve_once()

	def serve_once(self):
		"""Accept and process one connection in a new thread."""

		con = self._server.accept()[0]
		t = threading.Thread(target=self.__serve_once, args=(con,))
		t.start()

	def __serve_once(self, con):
		# We only allow a client to wait for one token at a time.
		client_addr = con.getpeername()[0]
		if client_addr in self.clients:
			con.send(b"ERROR: You're already waiting for a token.")
			con.shutdown()
			con.close()
			return
		else:
			self.clients.add(client_addr)

		try:
			data = con.recv(512)

			# The signing is rather computationally intensive, so let's make the
			# client wait for half the required time before attempting it.
			time.sleep(self.wait_time/2)

			# We need to process the signature asynchronously so as to not be
			# vulnerable to a timing attack.
			signature = None
			def sign_data():
				nonlocal signature, data, self
				signature = self.privkey.sign(data)
			sig_thread = threading.Thread(target=sign_data)
			sig_thread.run()

			time.sleep(self.wait_time/2)

			if signature:
				con.send(signature)
				con.close()

			# If we haven't got a chance to sign the data yet, we're too vulnerable to
			# a timing attack to wait for it. We'll send the client a string of zeros
			# to signal an error and warn about it.
			else:
				logger.fatal("We weren't able to produce a signature in our alloted "
					           "time. Consider increasing wait_time.")

				con.send(b"ERROR: Signing timed out. Sorry to make you wait for "
				         b"nothing. :-(")
				con.close()

		except socket.error:
			pass

		finally:
			self.clients.remove(client_addr)

class NotaryClient:
	@classmethod
	def from_public_id(class_, public_id):
		"""Create a NotaryClient object from a string of the form returned by
		MyopicNotary.public_id()."""

		server, port, wait_time, pubkey = public_id.split(":")
		pubkey = pubkey.encode()
		port = int(port)
		wait_time = int(wait_time)

		return class_( (server, port), pubkey, wait_time )

	def __init__(self, notary_addr, notary_key, wait_time):
		self.notary_addr = notary_addr
		self.notary_key = Blinder.deserialize( base64.b64decode(notary_key) )
		self.wait_time = wait_time

	def request_sig(self, token):
		"""Request that the notary notarize token. This will block wait_time (or
		possibly a little more."""

		blinding_factor, blinded_token = self.notary_key.blind(token)

		con = socket.socket()
		con.connect(self.notary_addr)
		con.send(blinded_token)

		# Don't let the notary make us wait forever to obtain a token.
		con.settimeout(self.wait_time+15)

		data = con.recv(512)
		con.close()

		if not data:
			raise MyopicError("The notary disconnected prior to sending a signature.")

		# The chance of a valid signature beginning with "ERROR: " is so miniscule
		# that we can ignore the possibility.
		elif data.startswith(b"ERROR: "):
			raise MyopicError( "Notary erred: " + data[7:].decode() )

		sig = self.notary_key.unblind(data, blinding_factor)
		if not self.verify(token, sig):
			raise MyopicError("The notary sent us invalid data! Mofo.")
		else:
			return sig

	def verify(self, token, sig):
		"""Verify that a signature received from the notary is valid."""

		return self.notary_key.verify(token, sig)

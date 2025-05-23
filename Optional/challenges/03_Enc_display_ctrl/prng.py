#!/usr/bin/env python3
#prng.py

from Crypto.Hash import MD5

class PRNG:
	prng_glen = None
	prng_state = None
	prng_buffer = None

	def __init__(self):
		self.prng_glen = 16
		self.prng_state = b''
		self.prng_buffer = b''

	def rot_byte(self, b):
		f = b%2
		r = b//2
		if f: r = r|0b10000000
		return r

	def rot_block(self, B):
		R = B[-1:]+B[:-1] 
		return R

	def shuffle_block(self, B):
		R = b''
		for i in range(len(B)):
			r = B[i]
			for j in range(i): r = self.rot_byte(r)
			R += r.to_bytes(1, 'big')
		R = self.rot_block(R)
		return R

	def update_state_and_generate(self):
		self.prng_state = self.shuffle_block(self.prng_state)
		h = MD5.new()
		h.update(self.prng_state)
		return(h.digest())

	def seed(self, s):
		h = MD5.new()
		h.update(s)
		self.prng_state = h.digest()[4:12]

	def get_random_bytes(self, n):

		if n < 0: return(b'')

		l = len(self.prng_buffer)
		if n > l:  # not enough bytes in buffer, we need to generate more
			for i in range(1+(n-l)//self.prng_glen):
				self.prng_buffer += self.update_state_and_generate()
		
		# enough bytes in buffer 
		r = self.prng_buffer[:n]  # will return first n bytes from buffer
		self.prng_buffer = self.prng_buffer[n:]  # remove first n bytes from buffer
		return r


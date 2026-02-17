module secretbox

import rand

#flag -lsodium
#include <sodium.h>

fn C.crypto_secretbox_easy(byteptr, byteptr, u64, byteptr, byteptr) int
fn C.crypto_secretbox_open_easy(byteptr, byteptr, u64, byteptr, byteptr) int

pub const key_size = 32 // crypto_secretbox_KEYBYTES

pub const nonce_size = 24 // crypto_secretbox_NONCEBYTES

pub const overhead = 16 // crypto_secretbox_MACBYTES

pub fn generate_key() ![]u8 {
	key := rand.bytes(key_size)!
	return key
}

pub fn generate_nonce() ![]u8 {
	nonce := rand.bytes(nonce_size)!
	return nonce
}

// Encrypt message
pub fn seal(message []u8, nonce []u8, key []u8) ![]u8 {
	if nonce.len != nonce_size {
		return error('Nonce size must be ${nonce_size}, got ${nonce.len}')
	}

	if key.len != key_size {
		return error('Key size must be ${key_size}, got ${key.len}')
	}

	mut ciphertext := []u8{len: message.len + overhead}

	result := C.crypto_secretbox_easy(ciphertext.data, message.data, u64(message.len),
		nonce.data, key.data)

	if result != 0 {
		return error('encrypt error')
	}

	return ciphertext
}

// Decrypt message
pub fn open(ciphertext []u8, nonce []u8, key []u8) ![]u8 {
	if ciphertext.len < overhead {
		return error('ciphertext too short')
	}

	if nonce.len != nonce_size {
		return error('Nonce size must be ${nonce_size}, got ${nonce.len}')
	}

	if key.len != key_size {
		return error('Key size must be ${key_size}, got ${key.len}')
	}

	mut message := []u8{len: ciphertext.len - overhead}

	result := C.crypto_secretbox_open_easy(message.data, ciphertext.data, u64(ciphertext.len),
		nonce.data, key.data)

	if result != 0 {
		return error('Auth or decrypt error')
	}

	return message
}

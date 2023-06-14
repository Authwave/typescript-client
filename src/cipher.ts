import nacl from 'tweetnacl';
import { randomBytes } from 'node:crypto';
import { DecryptionFailureException, EncryptionFailureException } from './errors.js';

export class InitVector {
	private bytes: Buffer;
	constructor(byteLength = 24) {
		if (byteLength < 1) throw new RangeError('IV byte length must be greater than 1');
		this.bytes = randomBytes(byteLength);
	}
	getBytes(): Buffer {
		return Buffer.from(this.bytes);
	}
	withBytes(bytes: Uint8Array): InitVector {
		const clone = new InitVector();
		clone.bytes = Buffer.from(bytes);
		return clone;
	}
	toString(): string {
		return this.bytes.toString('base64');
	}
}
export class CipherText {
	private readonly bytes: Buffer;
	constructor(
		data: string,
		private readonly iv: InitVector,
		key: string,
	) {
		try {
			this.bytes = Buffer.from(nacl.secretbox(Buffer.from(data), iv.getBytes(), Buffer.from(key)));
		} catch (cause) {
			throw new EncryptionFailureException('Error encrypting cipher message', { cause });
		}
	}
	getBytes(): Buffer {
		return Buffer.from(this.bytes);
	}
	toString(): string {
		return this.bytes.toString('base64');
	}
}
export function decrypt(data: string, iv: InitVector, secret: string): string {
	try {
		const plain = nacl.secretbox.open(
			Buffer.from(data, 'base64'),
			iv.getBytes(),
			Buffer.from(secret),
		);
		if (!plain) throw new Error('Authentication failed');
		return Buffer.from(plain).toString('utf8');
	} catch (cause) {
		throw new DecryptionFailureException('Error decrypting cipher message', { cause });
	}
}

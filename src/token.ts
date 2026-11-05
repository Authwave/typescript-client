import { CipherText, decrypt, InitVector } from './cipher.js';
import { InvalidUserDataSerializationException, TokenReuseException } from './errors.js';
import { UserResponseData } from './user.js';
export class Token {
	private requestPlaintext: string | null = null;
	constructor(
		private readonly secret: string,
		private readonly sessionIv = new InitVector(),
		private readonly iv = new InitVector(),
	) {}
	getIv(): InitVector {
		return this.iv;
	}
	getSecretIv(): InitVector {
		return this.sessionIv;
	}
	generateRequestCipher(message = ''): CipherText {
		const plaintext = `${message}&secretIv=${this.sessionIv}`;
		if (this.requestPlaintext !== null && this.requestPlaintext !== plaintext) {
			throw new TokenReuseException('Create a new token for a different request.');
		}
		const cipher = new CipherText(plaintext, this.iv, this.secret);
		this.requestPlaintext = plaintext;
		return cipher;
	}
	decode(base64cipher: string): UserResponseData {
		const plain = decrypt(base64cipher, this.iv, this.secret);
		try {
			const data = JSON.parse(plain);
			const id = data?.uuid ?? data?.id;
			if (
				!data ||
				typeof data !== 'object' ||
				typeof data.email !== 'string' ||
				typeof id !== 'string'
			)
				throw new Error();
			return new UserResponseData(id, data.email);
		} catch (cause) {
			throw new InvalidUserDataSerializationException('', { cause });
		}
	}
	/** Server-side session serialization only; contains the client secret. */
	toJSON() {
		return {
			secret: this.secret,
			sessionIv: String(this.sessionIv),
			iv: String(this.iv),
			requestPlaintext: this.requestPlaintext,
		};
	}
	static fromJSON(
		data: Omit<ReturnType<Token['toJSON']>, 'requestPlaintext'> & {
			requestPlaintext?: string | null;
		},
	): Token {
		const token = new Token(
			data.secret,
			new InitVector().withBytes(Buffer.from(data.sessionIv, 'base64')),
			new InitVector().withBytes(Buffer.from(data.iv, 'base64')),
		);
		// Legacy records have no safe request-plaintext binding; decryption remains available.
		token.requestPlaintext = Object.hasOwn(data, 'requestPlaintext') ? data.requestPlaintext! : '';
		return token;
	}
}

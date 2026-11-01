import { CipherText, decrypt, InitVector } from './cipher.js';
import { InvalidUserDataSerializationException } from './errors.js';
import { UserResponseData } from './user.js';
export class Token {
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
		return new CipherText(`${message}&secretIv=${this.sessionIv}`, this.iv, this.secret);
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
		return { secret: this.secret, sessionIv: String(this.sessionIv), iv: String(this.iv) };
	}
	static fromJSON(data: ReturnType<Token['toJSON']>): Token {
		return new Token(
			data.secret,
			new InitVector().withBytes(Buffer.from(data.sessionIv, 'base64')),
			new InitVector().withBytes(Buffer.from(data.iv, 'base64')),
		);
	}
}

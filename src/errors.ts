export class AuthwaveException extends Error {
	constructor(message = '', options?: ErrorOptions) {
		super(message, options);
		this.name = new.target.name;
	}
}
export class SessionNotStartedException extends AuthwaveException {}
export class NotLoggedInException extends AuthwaveException {}
export class InsecureProtocolException extends AuthwaveException {}
export class InvalidUserDataSerializationException extends AuthwaveException {}
// Retained for PHP API parity; cipher failures use DecryptionFailureException.
export class ResponseCipherDecryptionException extends AuthwaveException {}
export class DecryptionFailureException extends AuthwaveException {}
export class EncryptionFailureException extends AuthwaveException {}

export class TokenReuseException extends AuthwaveException {}

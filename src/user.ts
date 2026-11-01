export class AuthUser {
	constructor(
		public readonly id: string,
		public readonly email: string,
	) {
		Object.defineProperties(this, { id: { writable: false }, email: { writable: false } });
	}
}
/** @deprecated Use AuthUser. */
export class User extends AuthUser {}
export abstract class BaseResponseData {
	constructor(protected readonly message: string | null = null) {}
	getMessage(): string | null {
		return this.message;
	}
}
export class UserResponseData extends BaseResponseData {
	constructor(
		private readonly uuid: string,
		private readonly email: string,
		message: string | null = null,
	) {
		super(message);
	}
	getId(): string {
		return this.uuid;
	}
	getEmail(): string {
		return this.email;
	}
}

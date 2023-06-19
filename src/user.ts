export type Fields = Readonly<Record<string, string>>;
export class AuthUser {
	private readonly kvp: Fields;
	constructor(
		public readonly id: string,
		public readonly email: string,
		kvp: Fields = {},
	) {
		this.kvp = Object.freeze({ ...kvp });
		Object.defineProperties(this, { id: { writable: false }, email: { writable: false } });
	}
	getData(key: string): string | null {
		return Object.hasOwn(this.kvp, key) ? this.kvp[key]! : null;
	}
	getKvp(): Fields {
		return { ...this.kvp };
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
	private readonly kvp: Fields;
	constructor(
		private readonly uuid: string,
		private readonly email: string,
		kvp: Fields = {},
		message: string | null = null,
	) {
		super(message);
		this.kvp = Object.freeze({ ...kvp });
	}
	getId(): string {
		return this.uuid;
	}
	getEmail(): string {
		return this.email;
	}
	getField(name: string): string | null {
		return Object.hasOwn(this.kvp, name) ? this.kvp[name]! : null;
	}
	getAllFields(): Fields {
		return { ...this.kvp };
	}
}

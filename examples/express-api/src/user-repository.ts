export type UserRole = "user" | "admin";

export interface User {
  id: string;
  email: string;
  passwordHash: string;
  role: UserRole;
}

/** Demonstration repository. Replace this class with application-owned DB queries. */
export class InMemoryUserRepository {
  readonly #usersById = new Map<string, User>();
  readonly #userIdByEmail = new Map<string, string>();
  #nextId = 1;

  async findByEmail(email: string): Promise<User | undefined> {
    const id = this.#userIdByEmail.get(email.toLowerCase());
    return id === undefined ? undefined : this.#usersById.get(id);
  }

  async findById(id: string): Promise<User | undefined> {
    return this.#usersById.get(id);
  }

  async create(email: string, passwordHash: string, role: UserRole = "user") {
    const normalizedEmail = email.toLowerCase();
    if (this.#userIdByEmail.has(normalizedEmail)) {
      return undefined;
    }
    const user: User = {
      id: `user-${this.#nextId++}`,
      email: normalizedEmail,
      passwordHash,
      role,
    };
    this.#usersById.set(user.id, user);
    this.#userIdByEmail.set(user.email, user.id);
    return user;
  }

  get size(): number {
    return this.#usersById.size;
  }
}

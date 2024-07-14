import type { Mongoose } from "mongoose";
import sha3 from "crypto-js/sha3.js";
import { validate as isemail } from "email-validator";
import random from "@cch137/random";
import EmailAddressVerifier from "./email-verifier.js";
import Mailer, { type MailerOptions } from "./mailer.js";
import { parseToken, serializeToken, type AuthClientSession } from "./token.js";

export type RawUser = {
  id: string;
  un: string;
  ea: string;
  pw: string;
  ct: Date;
};

export type UserSummary = {
  id: string;
  username: string;
};
export type UserProfile = {
  id: string;
  username: string;
  createdTime: Date;
};
export type IUser = {
  _id: string;
  id: string;
  username: string;
  createdTime: Date;
  emailAddress: string;
  roles: string[];
};

export type ISession = {
  /** Session ID */
  id: string;
  /** User ID */
  uid?: string;
  /** User ID list */
  uidList: string[];
  /** A JSON string containing client information and configuration. */
  preference: string;
  /** User's ip list. */
  ipList: string[];
  /** User's user agent list. */
  userAgents: string[];
  /** Created time */
  createdTime: Date;
  /** Accessed time */
  accessedTime: Date;
};

const ERR_EAV = new Error("The verification code is incorrect or has expired.");
const ERR_INVALID_EMAIL_FORMAT = new Error("Invalid email address format.");
const ERR_INVALID_FORM = new Error("Invalid form.");
const ERR_NO_UID = new Error("User ID generation failed.");
const ERR_NO_USER = new Error("User does not exist.");
const ERR_USER_EXISTS = new Error("User already exists.");
const ERR_USERNAME_EXISTS = new Error("Username already in used.");

const hashPassword = (password: string) =>
  sha3(password, { outputLength: 256 }).toString();

const type = <T>(type: T, required = true) => ({ type, required });

const successResult: {
  <T = undefined>(value: T): { success: true; value: T };
  (): { success: true };
} = <T = undefined>(value?: T) => ({
  success: true as true,
  value,
});

const errorResult = (e: any) => ({
  success: false as false,
  message:
    e instanceof Error
      ? e.message || e.name
      : typeof e === "string"
      ? e
      : "Unknown error",
});

class MongooseBase {
  readonly mongoose: Mongoose;
  constructor(mongoose: Mongoose) {
    this.mongoose = mongoose;
  }
}

type Result<T = undefined> =
  | { success: true; value: T }
  | { success: false; message: string };
type PResult<T = undefined> = Promise<Result<T>>;

export type { AuthClientSession };

export { parseToken, serializeToken };

export default class Auth extends MongooseBase {
  static readonly Mailer = Mailer;
  static readonly EmailAddressVerifier = EmailAddressVerifier;
  static readonly parseToken = parseToken;
  static readonly serializeToken = serializeToken;

  static USERNAME_MIN_LENGTH = 6;
  static USERNAME_MAX_LENGTH = 32;

  static safeUsername(username: string) {
    return username
      .padEnd(Auth.USERNAME_MIN_LENGTH, "_")
      .replace(/[^\w]+/g, "")
      .substring(0, this.USERNAME_MAX_LENGTH);
  }

  static safeEmailAddress(email: string) {
    if (!isemail(email)) throw ERR_INVALID_EMAIL_FORMAT;
    return email;
  }

  constructor({
    appName,
    mongoose,
    mailer,
  }: {
    appName: string;
    mongoose: Mongoose;
    mailer:
      | Mailer
      | { user: string; pass: string; options?: Partial<MailerOptions> };
  }) {
    super(mongoose);
    this.eav = new EmailAddressVerifier(
      appName,
      mailer instanceof Mailer
        ? mailer
        : new Mailer(mailer.user, mailer.pass, mailer.options)
    );
  }

  readonly eav: EmailAddressVerifier;

  readonly User = this.mongoose.model(
    "User",
    new this.mongoose.Schema(
      {
        id: type(String),
        un: type(String),
        ea: type(String),
        pw: type(String),
        rl: type([String]),
        ct: type(Date),
      },
      { versionKey: false }
    ),
    "users",
    { overwriteModels: true }
  );

  readonly Session = this.mongoose.model(
    "Session",
    new this.mongoose.Schema(
      {
        us: type(String, false),
        ul: type([String]),
        pf: type(String, false),
        ip: type([String]),
        ua: type([String]),
        ct: type(Date),
        at: type(Date),
      },
      { versionKey: false }
    ),
    "sessions",
    { overwriteModels: true }
  );

  readonly Track = this.mongoose.connection.collection("tracks");

  private async generateUserId() {
    let i = 3;
    while (i--) {
      try {
        const id = random.base64(16);
        if (await this.hasUser({ id })) continue;
        return id;
      } catch {}
    }
    throw ERR_NO_UID;
  }

  async createUser({
    username,
    emailAddress,
    password,
    code,
  }: {
    username: string;
    emailAddress: string;
    password: string;
    code: string;
  }) {
    try {
      if (!this.eav.verify(emailAddress, code)) throw ERR_EAV;
      const un = Auth.safeUsername(username);
      const ea = Auth.safeEmailAddress(emailAddress);
      if (await this.hasUser({ un, ea })) throw ERR_USER_EXISTS;
      const id = await this.generateUserId();
      this.User.create({
        id,
        un,
        ea,
        pw: hashPassword(password),
        rl: [],
        ct: new Date(),
      });
      return successResult({ id, username: un });
    } catch (e) {
      return errorResult(e);
    }
  }

  async changePassword(form: {
    id: string;
    password: string;
    email: string;
    code: string;
  }): Promise<Result>;
  async changePassword(form: {
    id: string;
    password: string;
    oldPassword: string;
  }): Promise<Result>;
  async changePassword({
    id,
    emailAddress,
    password,
    code,
    oldPassword,
  }: {
    id: string;
    password: string;
    emailAddress?: string;
    code?: string;
    oldPassword?: string;
  }) {
    try {
      if (!id) throw ERR_NO_USER;
      if (typeof oldPassword === "string") {
        // change password by old password
        await this.User.updateOne(
          { id, pw: oldPassword },
          { $set: { pw: hashPassword(password) } }
        );
        return successResult();
      } else if (typeof code === "string" && typeof emailAddress === "string") {
        // change password by verification code
        if (!this.eav.verify(emailAddress, code)) throw ERR_EAV;
        await this.User.updateOne(
          { id, ea: emailAddress },
          { $set: { pw: hashPassword(password) } }
        );
        return successResult();
      }
      throw ERR_INVALID_FORM;
    } catch (e) {
      return errorResult(e);
    }
  }

  async changeUsername(userId: string, username: string) {
    try {
      if (!userId) throw ERR_NO_USER;
      const un = Auth.safeUsername(username);
      if (await this.hasUser({ un })) throw ERR_USERNAME_EXISTS;
      await this.User.updateOne({ id: userId }, { $set: { un } });
      return successResult({ un });
    } catch (e) {
      return errorResult(e);
    }
  }

  async changeEmailAddress(userId: string, emailAddress: string, code: string) {
    try {
      if (!userId) throw ERR_NO_USER;
      if (!this.eav.verify(emailAddress, code)) throw ERR_EAV;
      await this.User.updateOne({ id: userId }, { $set: { ea: emailAddress } });
    } catch (e) {
      return errorResult(e);
    }
  }

  addRole(userId: string, roles: string[]): PResult;
  addRole(userId: string, ...roles: string[]): PResult;
  async addRole(userId: string, ...roles: (string | string[])[]) {
    try {
      if (!userId) throw ERR_NO_USER;
      await this.User.updateOne(
        { id: userId },
        { $addToSet: { rl: { $each: roles.flat() } } }
      );
      return successResult();
    } catch (e) {
      return errorResult(e);
    }
  }

  removeRole(userId: string, roles: string[]): PResult;
  removeRole(userId: string, ...roles: string[]): PResult;
  async removeRole(userId: string, ...roles: (string | string[])[]) {
    try {
      if (!userId) throw ERR_NO_USER;
      await this.User.updateOne(
        { id: userId },
        { $pull: { rl: { $in: roles.flat() } } }
      );
      return successResult();
    } catch (e) {
      return errorResult(e);
    }
  }

  async validUser(
    usernameOrEmailAddress: string,
    password: string
  ): Promise<
    | ({ valid: true; exists: true } & UserSummary)
    | { valid: false; exists: boolean }
  > {
    if (!usernameOrEmailAddress || !password)
      return { valid: false, exists: false };
    const hashedPassword = hashPassword(password);
    const user = await this.User.findOne(
      { $or: [{ ea: usernameOrEmailAddress }, { un: usernameOrEmailAddress }] },
      { _id: 0, id: 1, un: 1, pw: 1 }
    );
    if (!user) return { valid: false, exists: false };
    if (user.pw !== hashedPassword) return { valid: false, exists: true };
    return { valid: true, exists: true, id: user.id, username: user.un };
  }

  async hasUser(user: Partial<RawUser>) {
    return Boolean(await this.User.exists(user));
  }

  async getUser(userId: string): Promise<IUser | null> {
    if (!userId) return null;
    const user = await this.User.findOne({ id: userId }, { pw: 0 });
    if (!user) return null;
    return {
      _id: user._id.toHexString(),
      id: user.id,
      username: user.un,
      emailAddress: user.ea,
      createdTime: user.ct,
      roles: user.rl,
    };
  }

  async getUserSummary(userId: string): Promise<UserSummary | null> {
    if (!userId) return null;
    const user = await this.User.findOne(
      { id: userId },
      { _id: 0, pw: 0, id: 1, un: 1 }
    );
    if (!user) return null;
    return { id: user.id, username: user.un };
  }

  async getUserProfile(userId: string): Promise<UserProfile | null> {
    if (!userId) return null;
    const user = await this.User.findOne(
      { id: userId },
      { _id: 0, pw: 0, id: 1, un: 1 }
    );
    if (!user) return null;
    return { id: user.id, username: user.un, createdTime: user.ct };
  }

  async createSession(userId?: string, preference = "") {
    const { _id } = await this.Session.create({
      us: userId,
      ul: userId ? [userId] : [],
      pf: preference,
      ip: [],
      ua: [],
      ct: new Date(),
      at: new Date(),
    });
    return { _id };
  }

  async getSession(sessionId: string) {
    if (!sessionId) return null;
    const session = await this.Session.findOne({ _id: sessionId });
    if (!session) return null;
    const { _id, us, ul, pf, ip, ua, ct, at } = session;
    return {
      id: _id.toHexString(),
      uid: us,
      uidList: ul,
      preference: pf,
      ipList: ip,
      userAgents: ua,
      createdTime: ct,
      accessedTime: at,
    };
  }

  async signInSession(sessionId: string, userId: string) {
    if (!sessionId) return;
    await this.Session.updateOne(
      { _id: sessionId },
      { $set: { us: userId, at: new Date() }, $addToSet: { ul: userId } }
    );
  }

  async signOutSession(sessionId: string) {
    if (!sessionId) return;
    await this.Session.updateOne(
      { _id: sessionId },
      { $unset: { us: "" }, $set: { at: new Date() } }
    );
  }

  async setPreference(sessionId: string, preference = "") {
    if (!sessionId) return;
    await this.Session.updateOne(
      { _id: sessionId },
      { $set: { pf: preference, at: new Date() } }
    );
  }

  async accessSession(sessionId: string) {
    if (!sessionId) return;
    await this.Session.updateOne(
      { _id: sessionId },
      { $set: { at: new Date() } }
    );
  }

  async trackUserDevice(sessionId?: string, ip?: string, ua?: string) {
    if (!sessionId) return;
    await this.Session.updateOne(
      { _id: sessionId },
      { $addToSet: { ip, ua, at: new Date() } }
    );
  }

  async trackUserActivity(
    sessionId?: string,
    activityName?: string,
    userId?: string,
    details?: { [key: string]: any }
  ) {
    if (!sessionId) return;
    await this.Track.insertOne({
      s: new this.mongoose.mongo.ObjectId(sessionId),
      t: activityName,
      u: userId,
      d: details,
    });
  }
}

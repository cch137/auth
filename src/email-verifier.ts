import random from "@cch137/random";
import type { Mailer } from "./mailer.js";

class Verification {
  private static readonly codes: Verification[] = [];

  static MAX_TRIES = 3;
  static MAX_SENT_TIMES = 3;

  static readonly get = (uuid: string) =>
    this.codes.find((i) => i.uuid === uuid);

  static readonly getByEmail = (email: string) =>
    this.codes.filter((i) => i.email === email);

  static readonly hasEmail = (email: string) =>
    Boolean(this.codes.find((i) => i.email === email));

  // default timeout 15 minutes
  constructor(email: string, timeoutMs = 900000) {
    this.email = email;
    this.timeout = setTimeout(() => this.kill(), timeoutMs);
    Verification.codes.push(this);
  }

  readonly uuid = crypto.randomUUID();
  readonly email: string;
  readonly code = random.base16(8).toUpperCase();

  private readonly timeout: NodeJS.Timeout;
  sentTimes = 0;
  verifyTryTimes = 0;

  private kill() {
    clearTimeout(this.timeout);
    const index = Verification.codes.indexOf(this);
    if (index !== -1) Verification.codes.splice(index, 1);
  }

  verify(code: string) {
    if (++this.verifyTryTimes >= Verification.MAX_TRIES) {
      this.kill();
      return false;
    }
    return code === this.code;
  }
}

export default class EmailAddressVerifier {
  static Verification = Verification;

  constructor(appName: string, mailer: Mailer) {
    this.appName = appName;
    this.mailer = mailer;
  }

  appName: string;
  mailer: Mailer;

  sendCode(verification: Verification) {
    if (verification.sentTimes >= Verification.MAX_SENT_TIMES)
      throw new Error("The verification code resend limit has been reached.");
    verification.sentTimes++;
    return this.mailer.sendText(
      verification.email,
      `Verification code - ${this.appName}`,
      `Here is your ${this.appName} verification code:\n\n${verification.code}\n\n` +
        "Do not share this information with anyone.\n" +
        "The verification code is valid for 10 minutes.\n" +
        "If you are unsure of the intended purpose of this code, kindly disregard this email.\n" +
        "This is an automated email. Please do not reply."
    );
  }

  resendCode(verificationUUID: string) {
    const v = Verification.get(verificationUUID);
    if (!v) throw new Error("Verification code not exists.");
    return this.sendCode(v);
  }

  async createVerification(email: string) {
    const v = new EmailAddressVerifier.Verification(email);
    await this.sendCode(v);
    return v;
  }

  verify(email: string, code: string) {
    const verifications = Verification.getByEmail(email);
    for (const v of verifications) if (v.verify(code)) return true;
    return false;
  }

  hasEmail(email: string) {
    return Verification.hasEmail(email);
  }
}

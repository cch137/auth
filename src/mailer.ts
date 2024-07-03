import type { Transporter } from "nodemailer";
import nodemailer from "nodemailer";

export type MailerOptions = {
  service: string;
  log: (message: string) => void;
  emailValidate: (email: string) => boolean | Promise<boolean>;
};

export default class Mailer {
  readonly user: string;
  readonly transporter: Transporter;
  log?: (message: string) => void;
  emailValidate?: (email: string) => boolean | Promise<boolean>;

  constructor(user: string, pass: string, options?: Partial<MailerOptions>);
  constructor(
    user: string,
    pass: string,
    { service = "gmail", log, emailValidate }: Partial<MailerOptions> = {}
  ) {
    this.user = user;
    this.transporter = nodemailer.createTransport({
      service,
      secure: true,
      auth: { user, pass },
    });
    this.log = log;
    this.emailValidate = emailValidate;
  }

  async sendMail(
    toEmailAddress: string,
    subject: string,
    message: string,
    type: "text" | "html" = "text"
  ) {
    if (this.emailValidate && !(await this.emailValidate(toEmailAddress)))
      throw new Error("Email address validation failed");
    return await new Promise<void>(async (resolve, reject) => {
      this.transporter.sendMail(
        {
          from: this.user,
          to: toEmailAddress,
          subject,
          [type]: message,
        },
        (err, info) => {
          if (err) return reject(err);
          if (this.log) this.log(`Email sent: (${subject}) ${info.response}`);
          resolve(info);
        }
      );
    });
  }

  sendText(toEmailAddress: string, subject: string, content: string) {
    return this.sendMail(toEmailAddress, subject, content, "text");
  }

  sendHTML(toEmailAddress: string, subject: string, content: string) {
    return this.sendMail(toEmailAddress, subject, content, "html");
  }
}

export { Mailer };

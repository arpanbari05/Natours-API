const nodemailer = require("nodemailer");

module.exports = class Email {
  constructor(user, url) {
    this.to = user.email;
    this.firstName = user.name.split(" ")[0];
    this.url = url;
    this.from = `Arpan Bari <${process.env.EMAIL_FROM}>`;
  }

  newTransport() {
    // if (process.env.NODE_ENV === "production") {
    if (true) {
      //sending email via sendGrid
      return nodemailer.createTransport({
        service: "SendGrid",
        auth: {
          user: process.env.SENDGRID_USERNAME,
          pass: process.env.SENDGRID_PASSWORD
        }
      });
    }

    return nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT,
      auth: {
        user: process.env.EMAIL_USERNAME,
        pass: process.env.EMAIL_PASSWORD,
      },
    });
  }

  async sendEmail(subject, message) {
    const htmlMessage = `<p>${message}</p>`
    return await this.newTransport().sendMail({
      from: this.from,
      to: this.to,
      subject,
      // text: message,
      html: htmlMessage
    });
  }

  async sendWelcome() {
    const message = `Hello ${this.firstName}, hope you enjoy surfing on our website.`
    await this.sendEmail("Welcome to the Natours family :-)", message);
  }

  async sendResetEmail() {
    const message = `Forgot your password?<br/> Click <a href="${this.url}">here</a> to reset your password. If you didn't requested this email ignore this mail.`;
    await this.sendEmail("Reset your password for Natours", message);
  }
};

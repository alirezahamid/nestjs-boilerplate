import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import * as SendGridTransport from '@sendgrid/mail';

@Injectable()
export class NotificationService {
  private transporter: nodemailer.Transporter;

  constructor() {
    // Configure SendGrid transport
    SendGridTransport.setApiKey(process.env.SENDGRID_API_KEY);
    this.transporter = nodemailer.createTransport({
      service: 'SendGrid',
      auth: {
        user: 'apikey',
        pass: process.env.SENDGRID_API_KEY,
      },
    });
  }

  async sendEmail(to: string, subject: string, content: string): Promise<void> {
    const mailOptions = {
      from: process.env.EMAIL_FROM, // Sender address
      to: to, // List of receivers
      subject: subject, // Subject line
      html: content, // HTML body content
    };

    await this.transporter.sendMail(mailOptions);
  }
}

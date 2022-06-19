import { MailerService } from '@nestjs-modules/mailer'
import { Injectable } from '@nestjs/common'
import { InjectTwilio, TwilioClient } from 'nestjs-twilio'

@Injectable()
export class NotifierService {
  constructor(
    private readonly mailService: MailerService,
    @InjectTwilio() private readonly smsService: TwilioClient,
  ) {}

  async sendEmail(to: string, subject: string, body?: string): Promise<void> {
    await this.mailService.sendMail({
      to,
      subject,
      text: body,
    })
  }

  async sendEmailWithTemplate(
    to: string,
    subject: string,
    template: string,
    context: any,
  ): Promise<void> {
    await this.mailService.sendMail({
      to,
      subject,
      template,
      context,
    })
  }

  async sendSms(to: string, body: string) {
    try {
      return await this.smsService.messages.create({
        from: process.env.TWILIO_PHONE_NUMBER,
        to,
        body,
      })
    } catch (err) {
      throw new Error(err)
    }
  }

  async notifyAll(
    toEmail: string,
    toPhone: string,
    subject: string,
    body: string,
  ) {
    await this.sendEmail(toEmail, subject, body)
    await this.sendSms(toPhone, body)
  }
}

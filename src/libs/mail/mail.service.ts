import { MailerService } from '@nestjs-modules/mailer';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as path from 'path';
import logger from 'src/utils/logger';

@Injectable()
export class MailService {
  constructor(private readonly mailerService: MailerService,
    private readonly configService: ConfigService,
    ) {}

  async sendMail(to: string , formData: any, subject: string, template: string,   attachments: any[] = [], userEmail?: string) {
    try {
      await this.mailerService.sendMail({
        to,
        from: this.configService.get<string>('MAIL_FROM'),
        replyTo: userEmail,
        subject: subject,
        template: template,
        context: formData,
        attachments: [
          ...attachments,
          {
            filename: 'logo.png',
            path: path.join(process.cwd(), 'public', 'logo.png'),
            cid: 'logo@yourapp' 
          }
        ] 
      });
      return { message: 'Email sent successfully' };
    } catch (error) {
        logger.error('Failed to send email', {
        error: error.message,
        stack: error.stack });
      return { error: 'Failed to send email', details: error.message };
    }
  }

  public async sendPasswordResetEmail(email: string, token: string) {
    const domain = this.configService.getOrThrow<string>('APP_ORIGIN');
  
    const formData = {
      domain,
      token,
    };
  
    return this.sendMail(
      email,
      formData,
      'Відновлення пароля',
      'password-reset' 
    );
  }

  public async sendTwoFactorTokenEmail(email: string, token: string) {
    const formData = {
      twoFactorCode: token
    };
     return this.sendMail(
      email,
      formData,
      'Підтвердження вашої особистості',
      'two-factor-token' 
    );
  }

  public async sendPasswordNewEmail(email: string) {
   
    return this.sendMail(
      email,
      {},
      'Пароль успішно змінено',
      'password-new'
    );
  }
  
  public async sendConfirmationEmail(email: string, token: string) {
    const domain = this.configService.getOrThrow<string>('APP_ORIGIN');
    const assetsBase = this.configService.getOrThrow<string>('APPLICATION_URL');
  
    const formData = {
      domain,       
      token,      
      assetsBase,  
    };
  
    return this.sendMail(
      email,
      formData,
      'Підтвердження електронної пошти',
      'email-confirmation'
    );
  }
  
  
}

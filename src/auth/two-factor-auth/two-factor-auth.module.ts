import { MailerModule } from '@nestjs-modules/mailer';
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Token } from 'src/entities/token.entity';


import { MailService } from 'src/libs/mail/mail.service';
import { TwoFactorAuthService } from './two-factor-auth.service';

@Module({
  imports: [TypeOrmModule.forFeature([Token]), MailerModule],
  providers: [TwoFactorAuthService, MailService],
  exports: [TwoFactorAuthService],
})
export class TwoFactorAuthModule {}

import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Token } from 'src/entities/token.entity';
import { User } from 'src/entities/user.entity';

import { AuthModule } from 'src/auth/auth.module';

import { MailService } from 'src/libs/mail/mail.service';
import { UserService } from 'src/user/user.service';
import { PasswordRecoveryController } from './password-recovery.controller';
import { PasswordRecoveryService } from './password-recovery.service';

@Module({
  imports: [
    TypeOrmModule.forFeature([Token, User]), 
    AuthModule] ,
  controllers: [PasswordRecoveryController],
  providers: [PasswordRecoveryService, UserService, MailService],
})
export class PasswordRecoveryModule {}

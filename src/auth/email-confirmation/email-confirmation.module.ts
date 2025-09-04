import { forwardRef, Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Token } from 'src/entities/token.entity';
import { User } from 'src/entities/user.entity';

import { MailService } from 'src/libs/mail/mail.service';
import { UserModule } from 'src/user/user.module';
import { AuthModule } from '../auth.module';
import { EmailConfirmationController } from './email-confirmation.controller';
import { EmailConfirmationService } from './email-confirmation.service';

@Module({
  imports: [
    TypeOrmModule.forFeature([Token, User]), 
    forwardRef(() => UserModule),          
    forwardRef(() => AuthModule),          
  ],
  controllers: [EmailConfirmationController],
  providers: [EmailConfirmationService, MailService],
  exports: [EmailConfirmationService],
})
export class EmailConfirmationModule {}

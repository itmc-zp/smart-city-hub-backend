import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from './auth/auth.module';
import { EmailConfirmationModule } from './auth/email-confirmation/email-confirmation.module';
import { ProviderModule } from './auth/provider/provider.module';
import { TwoFactorAuthModule } from './auth/two-factor-auth/two-factor-auth.module';
import { DatabaseModule } from './database/database.module';
import { MailController } from './libs/mail/mail.controller';
import { MailModule } from './libs/mail/mail.module';
import { MailService } from './libs/mail/mail.service';
import { PasswordRecoveryModule } from './password-recovery/password-recovery.module';
import { UserModule } from './user/user.module';
import { NormalizeSlashesMiddleware } from './utils/normalize-slashes.middleware';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    MailModule,
    DatabaseModule,
    AuthModule,
    UserModule,
    EmailConfirmationModule,
    PasswordRecoveryModule,
    TwoFactorAuthModule,
    ProviderModule,
  ],
  controllers: [MailController],
  providers: [MailService],
  exports: [MailService],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(NormalizeSlashesMiddleware).forRoutes('*');
  }
}

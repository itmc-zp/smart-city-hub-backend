import { forwardRef, Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { EmailConfirmationModule } from './email-confirmation/email-confirmation.module';

import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Account } from 'src/entities/account.entity';
import { getProvidersConfig } from 'src/providers/providers.config';
import { UserModule } from 'src/user/user.module';
import { ProviderModule } from './provider/provider.module';
import { TwoFactorAuthModule } from './two-factor-auth/two-factor-auth.module';


@Module({
  imports: [
    TypeOrmModule.forFeature([Account]),
    forwardRef(() => EmailConfirmationModule),
    forwardRef(() => UserModule), 
    forwardRef(() => TwoFactorAuthModule),
    ProviderModule.registerAsync({
      imports: [ConfigModule], 
      useFactory: (config: ConfigService) =>
        getProvidersConfig(config),   
      inject: [ConfigService],
    }),
    forwardRef(() => EmailConfirmationModule),
    JwtModule.register({
      secret: process.env.JWT_SECRET || 'smart-city',
      signOptions: { expiresIn: '1h' },
    })
  ],
  controllers: [AuthController],
  providers: [AuthService],
  exports: [AuthService],
})
export class AuthModule {}
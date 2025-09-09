import { forwardRef, Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from 'src/auth/auth.module';
import { User } from 'src/entities/user.entity';
import { MailModule } from 'src/libs/mail/mail.module';
import { UserController } from './user.controller';
import { UserService } from './user.service';

@Module({
  imports: [
    JwtModule.register({
      secret: process.env.JWT_SECRET || 'smart-city', 
      signOptions: { expiresIn: '15m' },
    }),
    TypeOrmModule.forFeature([User]),
    forwardRef(() => AuthModule),
    MailModule
  ],
  controllers: [UserController],
  providers: [UserService],
  exports: [UserService],
})
export class UserModule {}

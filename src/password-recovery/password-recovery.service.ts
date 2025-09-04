import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { hash } from 'argon2';
import { Token, TokenType } from 'src/entities/token.entity';
import { User } from 'src/entities/user.entity';

import { Response } from 'express';
import { AuthService } from 'src/auth/auth.service';

import { MailService } from 'src/libs/mail/mail.service';
import { UserService } from 'src/user/user.service';
import { Repository } from 'typeorm';
import { v4 as uuidv4 } from 'uuid';
import { NewPasswordDto } from './dto/new-password.dto';
import { ResetPasswordDto } from './dto/reset.password.dto';

@Injectable()
export class PasswordRecoveryService {
  constructor(
    @InjectRepository(Token)
    private readonly tokenRepository: Repository<Token>,

    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly mailService: MailService,
    private readonly authService: AuthService,
    private readonly userService: UserService
  ) {}

  public async resetPassword(dto: ResetPasswordDto) {
    const existingUser = await this.userRepository.findOne({ where: { email: dto.email } });

    if (!existingUser) {
      throw new NotFoundException('Користувача не знайдено.');
    }

    const passwordResetToken = await this.generatePasswordResetToken(existingUser.email);

    await this.mailService.sendPasswordResetEmail(passwordResetToken.email, passwordResetToken.token);

    return true;
  }

  public async newPassword(dto: NewPasswordDto, token: string, res: Response) {
    const existingToken = await this.tokenRepository.findOne({
      where: {
        token,
        type: TokenType.PASSWORD_RESET,
      },
    });
  
    if (!existingToken) {
      throw new NotFoundException('Token not found.');
    }
  
    const hasExpired = existingToken.expiresIn < new Date();
    if (hasExpired) {
      throw new BadRequestException('Термін дії токена закінчився. Будь ласка, запитайте новий токен.');
    }
  
    const existingUser = await this.userRepository.findOne({ where: { email: existingToken.email } });
  
    if (!existingUser) {
      throw new NotFoundException('Користувача не знайдено.');
    }
  
    existingUser.password = await hash(dto.password);

    await this.userRepository.save(existingUser);
    await this.mailService.sendPasswordNewEmail(existingUser.email);
    await this.tokenRepository.delete({ id: existingToken.id });
  
    const freshUser = await this.userService.findByEmail(existingUser.email);
  
    const session = await this.authService.saveSession(freshUser); 
    res.cookie('refresh_token', session.refresh_token, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
  
    return {
      access_token: session.access_token,
      user: session.user,
    };
  }
  

  private async generatePasswordResetToken(email: string) {
    const token = uuidv4();
    const expiresIn = new Date(Date.now() + 3600 * 1000);

    const existingToken = await this.tokenRepository.findOne({
      where: { email, type: TokenType.PASSWORD_RESET },
    });

    if (existingToken) {
      await this.tokenRepository.delete({ id: existingToken.id });
    }

    const passwordResetToken = this.tokenRepository.create({
      email,
      token,
      expiresIn,
      type: TokenType.PASSWORD_RESET,
    });

    await this.tokenRepository.save(passwordResetToken);

    return passwordResetToken;
  }
}

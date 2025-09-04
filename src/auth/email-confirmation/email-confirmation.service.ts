import {
  BadRequestException,
  forwardRef,
  Inject,
  Injectable,
  NotFoundException
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Request, Response } from 'express';
import { Token, TokenType } from 'src/entities/token.entity';
import { User } from 'src/entities/user.entity';

import { MailService } from 'src/libs/mail/mail.service';
import { UserService } from 'src/user/user.service';
import { Repository } from 'typeorm';
import { v4 as uuidv4 } from 'uuid';
import { AuthService } from '../auth.service';
import { ConfirmationDto } from './dto/confirmation.dto';
  
@Injectable()
  export class EmailConfirmationService {
    constructor(
      @InjectRepository(Token)
      private readonly tokenRepository: Repository<Token>,
  
      @InjectRepository(User)
      private readonly userRepository: Repository<User>,
  
      private readonly mailService: MailService,
      private readonly userService: UserService,
      @Inject(forwardRef(() => AuthService))
      private readonly authService: AuthService
    ) {}
    
    public async newVerification(req: Request, res: Response, dto: ConfirmationDto) {
      const existingToken = await this.tokenRepository.findOne({
        where: {
          token: dto.token,
          type: TokenType.VERIFICATION
        }
      });
 
      if (!existingToken) {
        throw new NotFoundException(
          'Токен підтвердження не знайдено. Будь ласка, переконайтесь, що ваш токен правильний.'
        );
      }
  
      const hasExpired = new Date(existingToken.expiresIn) < new Date();
      if (hasExpired) {
        throw new BadRequestException(
          'Термін дії токена підтвердження минув. Будь ласка, запросіть новий.'
        );
      }
  
      const existingUser = await this.userService.findByEmail(existingToken.email);
      if (!existingUser) {
        throw new NotFoundException('Користувача не знайдено.');
      }
  
      existingUser.isVerified = true;
      await this.userRepository.save(existingUser);
  
      await this.tokenRepository.delete({
        id: existingToken.id
      });

    const session = await this.authService.saveSession(existingUser);
    
    res.cookie('refresh_token', session.refresh_token, {
      httpOnly: true,
      secure: true, // или false, если dev
      sameSite: 'strict', // как в refreshTokens
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    

    return {
      access_token: session.access_token,
      user: session.user,
    };
    } 
  
    public async sendVerificationToken(user: User) {
      const verificationToken = await this.generateVerificationToken(user.email);

      await this.mailService.sendConfirmationEmail(
        verificationToken.email,
        verificationToken.token
      );
  
      return true;
    }
  
    private async generateVerificationToken(email: string) {
      const token = uuidv4();
      const expiresIn = new Date(Date.now() + 3600 * 1000); // 1 hour
  
      const existingToken = await this.tokenRepository.findOne({
        where: {
          email,
          type: TokenType.VERIFICATION
        }
      });
  
      if (existingToken) {
        await this.tokenRepository.remove(existingToken);
      }
  
      const newToken = this.tokenRepository.create({
        email,
        token,
        expiresIn,
        type: TokenType.VERIFICATION
      });
      return this.tokenRepository.save(newToken);
    }
  }
  

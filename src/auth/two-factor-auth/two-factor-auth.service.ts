import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Token, TokenType } from 'src/entities/token.entity';
import { MailService } from 'src/libs/mail/mail.service';

import { Repository } from 'typeorm';

@Injectable()
export class TwoFactorAuthService {
  constructor(
    @InjectRepository(Token)
    private readonly tokenRepository: Repository<Token>,
    private readonly mailService: MailService
  ) {}

  public async validateTwoFactorToken(email: string, code: string) {
    const existingToken = await this.tokenRepository.findOne({
      where: { email, type: TokenType.TWO_FACTOR }
    });

    if (!existingToken) {
      throw new NotFoundException('Токен двофакторної автентифікації не знайдено.');
    }

    if (existingToken.token !== code) {
      throw new BadRequestException('Невірний код двофакторної автентифікації.');
    }

    const hasExpired = new Date(existingToken.expiresIn) < new Date();

    if (hasExpired) {
      throw new BadRequestException('Строк дії токена двофакторної автентифікації минув.');
    }

    await this.tokenRepository.delete(existingToken.id);

    return true;
  }

  public async sendTwoFactorToken(email: string) {
    const twoFactorToken = await this.generateTwoFactorToken(email);
 
    await this.mailService.sendTwoFactorTokenEmail(
      twoFactorToken.email,
      twoFactorToken.token
    );

    return true;
  }

  private async generateTwoFactorToken(email: string): Promise<Token> {
    const token = Math.floor(Math.random() * (999999 - 100000) + 100000).toString();
    const expiresIn = new Date(Date.now() + 5 * 60 * 1000); // 5 минут

    const existingToken = await this.tokenRepository.findOne({
      where: { email, type: TokenType.TWO_FACTOR }
    });

    if (existingToken) {
      await this.tokenRepository.delete(existingToken.id);
    }

    const newToken = this.tokenRepository.create({
      email,
      token,
      expiresIn,
      type: TokenType.TWO_FACTOR
    });

    return this.tokenRepository.save(newToken);
  }
}

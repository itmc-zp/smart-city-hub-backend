import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { hash } from 'argon2';
import { AuthMethod, TwoFactorType, User } from 'src/entities/user.entity';
import { MailService } from 'src/libs/mail/mail.service';
import { Repository } from 'typeorm';
import { UpdateUserDto } from './dto/update.user.dto';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
     private readonly mailService: MailService,
  ) {}

  async findById(id: string): Promise<User> {
    const user = await this.userRepository.findOne({
      where: { id },
      relations: ['accounts'], 
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  async findByEmail(email: string): Promise<User | null> {
    const user = await this.userRepository.findOne({
      where: { email },
      relations: ['accounts'],
    });
    return user;
  }

  async create(
    email: string,
    password: string,
    displayName: string,
    picture: string,
    method: AuthMethod,
    isVerified: boolean,
    gender: string
  ): Promise<User> {
    const hashedPassword = password ? await hash(password) : '';

    const user = this.userRepository.create({
      email,
      password: hashedPassword,
      displayName,
      picture,
      method,
      isVerified,
      gender
    });

    return this.userRepository.save(user);
  }

  async update(userId: string, dto: UpdateUserDto): Promise<User> {
    const user = await this.findById(userId);

    user.email = dto.email;
    user.displayName = dto.name;
    user.isTwoFactorEnabled = dto.isTwoFactorEnabled;
    user.refreshToken = dto.refreshToken;
    user.gender = dto.gender;
    
    return this.userRepository.save(user);
  }

  async delete(userId: string): Promise<void> {
    await this.userRepository.delete(userId);
  }
  
  async updatePassword(userId: string, hashedPassword: string): Promise<void> {
    await this.userRepository.update(userId, { password: hashedPassword })
  }

  async setTwoFASecret(userId: string, secret: string): Promise<void> {
    await this.userRepository.update(userId, { twoFASecret: secret });
  }
  
  async enableTwoFA(userId: string): Promise<void> {
    await this.userRepository.update(userId, { isTwoFactorEnabled: true });
  }

  async setTwoFactorType(userId: string, type: TwoFactorType): Promise<void> {
    const user = await this.findById(userId);

    const wasEmail = user.twoFactorType === TwoFactorType.EMAIL;
    await this.userRepository.update(userId, { twoFactorType: type });

    if (type === TwoFactorType.EMAIL && !wasEmail) {
      this.mailService.sendTwoFactorEnabledEmail(user.email)
    }
  }
  
}



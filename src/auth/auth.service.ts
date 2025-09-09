import {
  BadRequestException,
  ConflictException,
  forwardRef,
  Inject,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import * as argon2 from 'argon2';
import { verify } from 'argon2';
import { randomBytes } from 'crypto';
import { Response } from 'express';
import * as qrcode from 'qrcode';
import * as speakeasy from 'speakeasy';
import { Account } from 'src/entities/account.entity';
import { AuthMethod, TwoFactorType, User } from 'src/entities/user.entity';
import { MailService } from 'src/libs/mail/mail.service';
import { getGoogleGender } from 'src/providers/providers.config';
import { UserService } from 'src/user/user.service';
import { hashStableId, mapProviderToAuthMethod, maskStableId, normalizeExpires } from 'src/utils/diia.helpers';
import { Repository } from 'typeorm';
import { ChangePasswordDto } from './dto/change-password.dto';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { EmailConfirmationService } from './email-confirmation/email-confirmation.service';
import { ProviderService } from './provider/provider.service';
import { TwoFactorAuthService } from './two-factor-auth/two-factor-auth.service';

@Injectable()
export class AuthService {
  public constructor(
    @Inject(forwardRef(() => UserService))
    private readonly userService: UserService,
    @InjectRepository(Account)
    private readonly accountRepository: Repository<Account>,
    private readonly emailConfirmationService: EmailConfirmationService,
    private readonly twoFactorAuthService: TwoFactorAuthService,
    private readonly providerService: ProviderService,
    private readonly jwtService: JwtService,
    private readonly mailService: MailService,
  ) {}

  public async register(dto: RegisterDto) {
    const isExists = await this.userService.findByEmail(dto.email);

    if (isExists) {
      throw new ConflictException(
        'Реєстрація не вдалася. Користувач з таким email вже існує.',
      );
    }

    const newUser = await this.userService.create(
      dto.email,
      dto.password,
      `${dto.firstName} ${dto.lastName}`,
      '',
      AuthMethod.CREDENTIALS,
      false,
      dto.gender,
    );

    await this.emailConfirmationService.sendVerificationToken(newUser);
    return {
      message:
        'Ви успішно зареєструвались. Будь ласка, підтвердіть ваш email. Повідомлення було надіслано на вашу пошту.',
    };
  }

  public async login(dto: LoginDto, res: Response) {
    const user = await this.userService.findByEmail(dto.email);

    if (!user || !user.password) {
      throw new NotFoundException('Користувача не знайдено.');
    }

    const isValidPassword = await verify(user.password, dto.password);
    if (!isValidPassword) {
      throw new UnauthorizedException('Невірний пароль.');
    }

    if (!user.isVerified) {
      await this.emailConfirmationService.sendVerificationToken(user);
      throw new UnauthorizedException('Ваш email не підтверджено.');
    }

    if (user.twoFactorType !== TwoFactorType.NONE) {
      if (!dto.code) {
        if (user.twoFactorType === TwoFactorType.EMAIL) {
          await this.twoFactorAuthService.sendTwoFactorToken(user.email);
          return {
            twoFactorType: user.twoFactorType,
          };
        }

        if (user.twoFactorType === TwoFactorType.APP) {
          return {
            twoFactorType: user.twoFactorType,
          };
        }
        throw new UnauthorizedException(
          'Потрібен код двофакторної аутентифікації.',
        );
      }

      if (user.twoFactorType === TwoFactorType.EMAIL) {
        try {
          await this.twoFactorAuthService.validateTwoFactorToken(
            user.email,
            dto.code,
          );
        } catch {
          throw new UnauthorizedException(
            'Невірний код двофакторної аутентифікації.',
          );
        }
      }

      if (user.twoFactorType === TwoFactorType.APP) {
        const is2faValid = this.verify2FACode(user, dto.code);
        if (!is2faValid) {
          throw new UnauthorizedException('Невірний код 2FA з додатку.');
        }
      }
    }

    const session = await this.saveSession(user);

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

  public async deleteAccount(userId: string): Promise<void> {
    const user = await this.userService.findById(userId);
    if (!user) {
      throw new NotFoundException('Користувача не знайдено.');
    }

    const email = user.email;

    await this.accountRepository
      .createQueryBuilder()
      .delete()
      .where('USER_ID = :userId', { userId })
      .execute();

    await this.userService.delete(userId);

    this.mailService.sendAccountDeletedEmail(email).catch((err) => {
      console.error('Failed to send account deletion email', err);
    });
  }

  public async extractProfileFromCode(
    res: Response,
    provider: string,
    code: string,
    ctx?: { linkUserId?: string }, 
  ) {
    const providerInstance = this.providerService.findByService(provider);
    if (!providerInstance)
      throw new Error(`OAuth provider '${provider}' not supported.`);

    const profile = await providerInstance.findUserByCode(code);
    if (!profile)
      throw new UnauthorizedException('Не вдалося отримати дані користувача');

    const isDiia = profile.provider?.toLowerCase() === 'diia';

    let stableId: string | null = null;
    if (isDiia) {
      const raw =
        typeof profile.raw === 'string' ? JSON.parse(profile.raw) : profile.raw;
      stableId = raw?.drfocode || raw?.serial || profile.id || null;
    } else {
      stableId = profile.id || null;
    }
    if (!stableId)
      throw new UnauthorizedException(
        'Не вдалося визначити ідентифікатор користувача',
      );

    // Проверяем существующий Account по (provider, providerAccountId)
    let account = await this.accountRepository.findOne({
      where: { provider: profile.provider, providerAccountId: stableId },
      relations: ['user'],
    });
    let user = account?.user || null;

    // === ВЕТКА ДІЇ: только из кабинета под текущим юзером ===
    if (isDiia) {
      const currentUserId = ctx?.linkUserId; // просто id текущего залогиненного
      if (!currentUserId) {
        throw new UnauthorizedException('Спочатку увійдіть у кабінет.');
      }
      const currentUser = await this.userService.findById(currentUserId);
      if (!currentUser) throw new UnauthorizedException('Сесія недійсна.');

      if (account && user && user.id !== currentUser.id) {
        throw new ConflictException(
          'Цей акаунт Дії вже прив’язаний до іншого користувача.',
        );
      }

      user = currentUser; 
    }
  
    if (!isDiia && !user) {
      const gender = await getGoogleGender(profile.access_token);
      const existingUser = profile.email
        ? await this.userService.findByEmail(profile.email)
        : null;
      user =
        existingUser ??
        (await this.userService.create(
          profile.email ?? `${profile.provider}:${stableId}@example.invalid`,
          randomBytes(16).toString('hex'),
          profile.name || 'Користувач',
          profile.picture ?? null,
          mapProviderToAuthMethod(profile.provider),
          true,
          gender,
        ));
    }

    if (!user)
      throw new UnauthorizedException('Неможливо визначити користувача');

    const normalizedExpiresAt = normalizeExpires(
      (profile as any).expires_at ?? null,
      (profile as any).expires_in ?? null,
    );


    if (!account) {
      account = this.accountRepository.create({
        user,
        type: 'oauth',
        provider: profile.provider, // 'google' | 'diia'
        providerAccountId: stableId,
        accessToken: profile.access_token ?? '',
        refreshToken: profile.refresh_token ?? null,
        expiresAt: normalizedExpiresAt ?? null,
      });
    } else {
      account.accessToken = profile.access_token ?? account.accessToken;
      if (profile.refresh_token) account.refreshToken = profile.refresh_token;
      if (normalizedExpiresAt != null) account.expiresAt = normalizedExpiresAt;
    }
    await this.accountRepository.save(account);


    if (isDiia) {
      await this.userService.update(user.id, {
        diiaVerified: true,
        diiaVerifiedAt: new Date().toISOString(),
        diiaStableIdHash: await hashStableId(stableId),
        diiaLastDocMask: maskStableId(stableId),
      
      });
    }

    const session = await this.saveSession(user);

    // 2FA
    if (user.twoFactorType !== TwoFactorType.NONE) {
      if (user.twoFactorType === TwoFactorType.EMAIL) {
        await this.twoFactorAuthService.sendTwoFactorToken(user.email);
      }
      const tempToken = this.jwtService.sign(
        { sub: user.id, type: '2fa' },
        { expiresIn: '5m' },
      );
      return {
        requires2FA: true,
        twoFactorType: user.twoFactorType,
        tempToken,
      };
    }

    res.cookie('refresh_token', session.refresh_token, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: '/',
    });

    return { access_token: session.access_token, user: session.user };
  }

  async changePassword(userId: string, dto: ChangePasswordDto) {
    const user = await this.userService.findById(userId);

    if (!user) {
      throw new NotFoundException('Користувача не знайдено.');
    }

    if (!user.password) {
      throw new BadRequestException(
        'У цього користувача немає локального пароля (вхід через OAuth).',
      );
    }

    const isOldPasswordValid = await argon2.verify(
      user.password,
      dto.oldPassword,
    );
    if (!isOldPasswordValid) {
      throw new BadRequestException('Старий пароль невірний.');
    }

    const isSamePassword = await argon2.verify(user.password, dto.newPassword);
    if (isSamePassword) {
      throw new BadRequestException(
        'Новий пароль не повинен збігатися зі старим.',
      );
    }

    const hashedNewPassword = await argon2.hash(dto.newPassword);

    await this.userService.updatePassword(user.id, hashedNewPassword);

    return {
      message: 'Пароль успішно змінено.',
    };
  }

  public async refreshAccessToken(refreshToken: string, res: Response) {
    if (!refreshToken)
      throw new UnauthorizedException('Refresh token не передан');

    let payload: any;
    try {
      payload = await this.jwtService.verifyAsync(refreshToken);
    } catch {
      throw new UnauthorizedException('Некоректний refresh token');
    }

    const user = await this.userService.findById(payload.sub);
    if (!user) throw new NotFoundException('Користувача не знайдено.');

    const account = await this.accountRepository.findOne({
      where: { user: { id: user.id }, provider: user.method.toLowerCase() },
    });

    const shouldAttemptProviderRefresh =
      !!account &&
      account.provider !== 'diia' && 
      !!account.refreshToken &&
      !!account.expiresAt &&
      account.expiresAt * 1000 - Date.now() < 5 * 60 * 1000; 

    if (shouldAttemptProviderRefresh) {
      const provider = this.providerService.findByService(account.provider);
      if (provider?.refreshAccessToken) {
        try {
          const refreshed = await provider.refreshAccessToken(
            account.refreshToken!,
          );
          account.accessToken = refreshed.access_token;
          if (refreshed.refresh_token)
            account.refreshToken = refreshed.refresh_token;

          await this.accountRepository.save(account);
        } catch (e: any) {
          // ВАЖНО: не ломаем /auth/refresh — логируем и идем дальше
          console.warn(
            'Provider refresh failed:',
            e?.response?.data ?? e?.message ?? e,
          );
        }
      }
    }

    const newAccess = await this.jwtService.signAsync(
      { sub: user.id },
      { expiresIn: '15m' },
    );
    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: '/',
    });

    return {
      access_token: newAccess,
      user: { id: user.id, email: user.email, name: user.displayName },
    };
  }

  public async saveSession(user: User) {
    const payload = {
      sub: user.id,
      email: user.email,
    };

    const accessToken = await this.jwtService.signAsync(payload, {
      expiresIn: '15m',
    });

    const refreshToken = await this.jwtService.signAsync(payload, {
      expiresIn: '7d',
    });

    user.refreshToken = refreshToken;
    await this.userService.update(user.id, { refreshToken });

    const result: any = {
      access_token: accessToken,
      refresh_token: refreshToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.displayName,
      },
    };
    return result;
  }
  // refactor
  async generate2FASecret(
    user: User,
  ): Promise<{ otpauthUrl: string; qrCodeDataURL: string }> {
    const secret = speakeasy.generateSecret({
      name: `Цифрове Запоріжжя (${user.email})`,
    });

    await this.userService.setTwoFASecret(user.id, secret.base32);

    const qrCodeDataURL = await qrcode.toDataURL(secret.otpauth_url);

    return {
      otpauthUrl: secret.otpauth_url,
      qrCodeDataURL,
    };
  }

  async verifyAndEnable2FA(userId: string, code: string): Promise<void> {
    const user = await this.userService.findById(userId);

    const isValid = this.verify2FACode(user, code);
    if (!isValid) {
      throw new BadRequestException('Неправильний код аутентифікації');
    }

    await this.userService.enableTwoFA(user.id);
  }

  private verify2FACode(user: User, code: string): boolean {
    return speakeasy.totp.verify({
      secret: user.twoFASecret,
      encoding: 'base32',
      token: code,
      window: 1,
    });
  }

  async verifyTwoFactorCode(code: string, tempToken: string) {
    let payload: any;
    try {
      payload = this.jwtService.verify(tempToken);
    } catch {
      throw new UnauthorizedException(
        'Невірний або прострочений тимчасовий токен',
      );
    }

    if (payload.type !== '2fa') {
      throw new UnauthorizedException('Невірений тип токена');
    }

    const user = await this.userService.findById(payload.sub);
    if (!user) {
      throw new UnauthorizedException('Користувача не знайдено');
    }

    let isValid = false;

    if (user.twoFactorType === TwoFactorType.EMAIL) {
      isValid = await this.twoFactorAuthService.validateTwoFactorToken(
        user.email,
        code,
      );
    } else if (user.twoFactorType === TwoFactorType.APP) {
      isValid = this.verify2FACode(user, code);
    }

    if (!isValid) {
      throw new UnauthorizedException('Невірний 2FA код');
    }

    const session = await this.saveSession(user);
    return session;
  }

  public async logout(userId: string, res: Response) {
    const user = await this.userService.findById(userId);
    if (!user) throw new NotFoundException('Користувача не знайдено.');

    if (user.method === AuthMethod.CREDENTIALS) {
      await this.userService.update(user.id, { refreshToken: null });
    } else {
      await this.accountRepository
        .createQueryBuilder()
        .update()
        .set({ refreshToken: null })
        .where('USER_ID = :userId', { userId: user.id })
        .execute();
    }

    res.clearCookie('refresh_token', {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
    });
  }
}

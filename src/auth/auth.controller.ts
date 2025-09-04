import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Post,
  Query,
  Req,
  Res,
  Session,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import {
  ApiBearerAuth,
  ApiBody,
  ApiExcludeEndpoint,
  ApiOperation,
  ApiParam,
  ApiQuery,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { randomUUID } from 'crypto';
import { Request, Response } from 'express';
import { Authorization } from 'src/decorators/auth.decorator';
import { TwoFactorType, User } from 'src/entities/user.entity';
import { AuthGuard } from 'src/guards/auth.guards';
import { AuthProviderGuard } from 'src/guards/provider.guards';
import { UserService } from 'src/user/user.service';
import {
  base64urlDecode,
  base64urlEncode,
  providerDefaultNext,
  sanitizeNext,
  saveSession,
} from 'src/utils/diia.helpers';
import { AuthService } from './auth.service';
import { ChangePasswordDto } from './dto/change-password.dto';
import { LoginDto, LoginResponseDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { ProviderService } from './provider/provider.service';

type StatePayload = {
  csrf: string;
  next?: string | null;
  mode?: 'login' | 'link';
  linkUserId?: string;
};

interface RequestWithUser extends Request {
  user: User;
}

@ApiTags('Авторизація')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
    private readonly providerService: ProviderService,
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
  ) {}

  @Post('register')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Реєстрація нового користувача' })
  @ApiResponse({ status: 200, description: 'Успішна реєстрація' })
  @ApiResponse({
    status: 409,
    description: 'Користувач з таким email вже існує',
  })
  @ApiBody({ type: RegisterDto })
  public async register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Вхід користувача' })
  @ApiBody({ type: LoginDto })
  @ApiResponse({
    status: 200,
    description:
      'Успішний вхід. Повертає access_token, refresh_token (в HttpOnly cookie) та дані користувача.',
    type: LoginResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Невірний email, пароль, код 2FA або email не підтверджено.',
  })
  @ApiResponse({
    status: 404,
    description: 'Користувача не знайдено.',
  })
  public async login(
    @Body() dto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.authService.login(dto, res);
  }

  @Post('delete-account')
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Видалення облікового запису' })
  @ApiBearerAuth()
  @ApiResponse({
    status: 200,
    description:
      'Обліковий запис успішно видалено. Очищено refresh_token cookie.',
    schema: {
      example: true,
    },
  })
  @ApiResponse({
    status: 404,
    description: 'Користувача не знайдено.',
  })
  @ApiResponse({
    status: 401,
    description: 'Неавторизований запит.',
  })
  public async deleteAccount(
    @Req() req: RequestWithUser,
    @Res({ passthrough: true }) res: Response,
  ) {
    const userId = req.user.id;
    await this.authService.deleteAccount(userId);
    res.clearCookie('refresh_token', {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
    });
    return true;
  }

  @UseGuards(AuthProviderGuard)
  @Get('/oauth/connect/:provider')
  public async connect(
    @Param('provider') provider: string,
    @Query('next') next: string | undefined,
    @Req() req: Request,
    @Res() res: Response,
    @Session() session: Record<string, any>,
  ) {
    const csrf = randomUUID();
    const safeNext = sanitizeNext(next, provider);
    const isDiia = provider.toLowerCase() === 'diia';

    let linkUserId: string | undefined;
    const token = (req as any)?.cookies?.['refresh_token'];
    if (token) {
      try {
        const payload = await this.jwtService.verifyAsync(token);
        linkUserId = payload?.sub;
      } catch {}
    }

    const statePayload: StatePayload = {
      csrf,
      next: safeNext,
      mode: isDiia ? 'link' : 'login',
      linkUserId: isDiia ? linkUserId : undefined,
    };

    const state = base64urlEncode(JSON.stringify(statePayload));
    session.oauth_state = state;

    const providerInstance = this.providerService.findByService(provider);
    if (!providerInstance) throw new BadRequestException('Unknown provider');

    const url = providerInstance.getAuthUrl(session, state);
    await saveSession(session);

    return res.redirect(url);
  }

  @UseGuards(AuthProviderGuard)
  @Get('/oauth/callback/:provider')
  @ApiOperation({ summary: 'OAuth callback від провайдера' })
  @ApiParam({ name: 'provider', description: 'Назва OAuth провайдера' })
  @ApiQuery({
    name: 'code',
    required: true,
    description: 'Код авторизації від OAuth провайдера',
  })
  @ApiQuery({
    name: 'state',
    required: true,
    description: 'Значення state для перевірки CSRF',
  })
  public async callback(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Query('code') code: string,
    @Query('state') state: string,
    @Param('provider') provider: string,
    @Session() session: Record<string, any>,
  ) {
    if (!code) {
      throw new BadRequestException('Код авторизації не був наданий');
    }

    if (!state || state !== session.oauth_state) {
      throw new UnauthorizedException('Invalid state parameter');
    }

    let nextPath = providerDefaultNext(provider);
    let linkUserIdFromState: string | undefined;
    try {
      const parsed = JSON.parse(base64urlDecode(state));
      nextPath = sanitizeNext(parsed?.next, provider);
      linkUserIdFromState = parsed?.linkUserId;
    } catch {}

    delete session.oauth_state;

    const result = await this.authService.extractProfileFromCode(
      res,
      provider,
      code,
      { linkUserId: linkUserIdFromState },
    );

    if (result.requires2FA) {
      return res.redirect(
        `${this.configService.getOrThrow<string>('APP_ORIGIN')}/auth/verify-2fa?tempToken=${encodeURIComponent(result.tempToken)}&twoFactorType=${result.twoFactorType}`,
      );
    }
    return res.redirect(
      `${this.configService.getOrThrow<string>('APP_ORIGIN')}${nextPath}`,
    );
  }

  @ApiExcludeEndpoint()
  @Authorization()
  @Post('2fa/verify-setup')
  async verify2FASetup(@Req() req, @Body('code') code: string) {
    await this.authService.verifyAndEnable2FA(req.user.id, code);
    return { success: true };
  }

  @ApiExcludeEndpoint()
  @Authorization()
  @Get('2fa/generate')
  async generate2FAQr(@Req() req) {
    const user = await this.userService.findById(req.user.id);
    return this.authService.generate2FASecret(user);
  }

  @ApiExcludeEndpoint()
  @Authorization()
  @Patch('2fa/type')
  async change2FAType(@Req() req, @Body('type') type: TwoFactorType) {
    if (!Object.values(TwoFactorType).includes(type)) {
      throw new BadRequestException('Невірний тип 2FA');
    }

    await this.userService.setTwoFactorType(req.user.id, type);
    if (type === TwoFactorType.NONE) {
      await this.userService.setTwoFASecret(req.user.id, null);
    }

    return { success: true };
  }

  // між гугл та кабінетом
  @Post('verify-2fa')
  @ApiOperation({ summary: 'Підтвердження 2FA коду' })
  @ApiResponse({
    status: 200,
    description:
      'Успішне підтвердження 2FA. Повертає access_token та користувача.',
    type: LoginResponseDto,
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        code: { type: 'string', example: '123456' },
        tempToken: { type: 'string', example: 'eyJhbGciOi...' },
      },
    },
  })
  async verify2FA(
    @Body() dto: { code: string; tempToken: string },
    @Res({ passthrough: true }) res: Response,
  ) {
    const session = await this.authService.verifyTwoFactorCode(
      dto.code,
      dto.tempToken,
    );

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

  @UseGuards(AuthGuard)
  @Patch('change-password')
  @ApiOperation({ summary: 'Зміна паролю' })
  @ApiBearerAuth()
  @ApiBody({ type: ChangePasswordDto })
  @ApiResponse({
    status: 200,
    description: 'Пароль успішно змінено',
    schema: {
      example: { message: 'Пароль успішно змінено.' },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Некоректні дані або помилка валідації',
  })
  @ApiResponse({ status: 401, description: 'Неавторизований користувач' })
  @ApiResponse({ status: 404, description: 'Користувача не знайдено' })
  async changePassword(
    @Req() req: RequestWithUser,
    @Body() dto: ChangePasswordDto,
  ) {
    const user = req.user;
    return this.authService.changePassword(user.id, dto);
  }

  @Post('refresh')
  @ApiOperation({
    summary: 'Оновлення access токену через refresh токен (у cookie)',
  })
  @ApiResponse({
    status: 200,
    description: 'Повертає новий access_token та користувача',
    type: LoginResponseDto,
  })
  async refreshTokens(@Req() req: Request, @Res() res: Response) {
    const refreshToken = req.cookies['refresh_token'];
    if (!refreshToken) {
      throw new UnauthorizedException('Потрібен refresh token.');
    }

    const session = await this.authService.refreshAccessToken(
      refreshToken,
      res,
    );

    return res.json(session);
  }

  @Post('logout')
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Вихід користувача' })
  @ApiResponse({
    status: 200,
    description: 'Вихід успішний',
    schema: {
      example: { message: 'Ви успішно вийшли з системи.' },
    },
  })
  @ApiBearerAuth()
  public async logout(
    @Req() req: RequestWithUser,
    @Res({ passthrough: true }) res: Response,
  ) {
    const user = req.user;
    await this.authService.logout(user.id, res);
    return { message: 'Ви успішно вийшли з системи.' };
  }
}

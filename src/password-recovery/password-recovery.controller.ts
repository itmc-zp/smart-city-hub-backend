import { Body, Controller, HttpCode, HttpStatus, Param, Post, Res } from '@nestjs/common';
import { ApiBody, ApiOperation, ApiParam, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Response } from 'express';
import { LoginResponseDto } from 'src/auth/dto/login.dto';
import { NewPasswordDto } from './dto/new-password.dto';
import { ResetPasswordDto } from './dto/reset.password.dto';
import { PasswordRecoveryService } from './password-recovery.service';

@ApiTags('Відновлення паролю')
@Controller('auth/password-recovery')
export class PasswordRecoveryController {
  constructor(private readonly passwordRecoveryService: PasswordRecoveryService) {}

  @Post('reset')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Запит на відновлення паролю' })
  @ApiBody({ type: ResetPasswordDto })
  @ApiResponse({
    status: 200,
    description: 'Лист для відновлення паролю надіслано.',
    schema: { example: true },
  })
  @ApiResponse({ status: 404, description: 'Користувача не знайдено' })
  public async resetPassword(@Body() dto: ResetPasswordDto) {
    return this.passwordRecoveryService.resetPassword(dto)
  }

  @Post('new/:token')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Встановлення нового паролю' })
  @ApiParam({ name: 'token', description: 'Токен відновлення паролю з email' })
  @ApiBody({ type: NewPasswordDto })
  @ApiResponse({
    status: 200,
    description: 'Пароль було успішно змінено. Повертає access_token та користувача.',
    type: LoginResponseDto
  })
  @ApiResponse({ status: 400, description: 'Термін дії токена закінчився або некоректні дані' })
  @ApiResponse({ status: 404, description: 'Токен або користувача не знайдено' })
  public async newPassword(
    @Body() dto: NewPasswordDto, 
    @Param('token') token: string,
    @Res({ passthrough: true }) res: Response
  ) {
    return  this.passwordRecoveryService.newPassword(dto, token, res)
  }

 
}
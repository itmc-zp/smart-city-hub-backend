import { Body, Controller, HttpCode, HttpStatus, Post, Req, Res } from '@nestjs/common';
import { ApiBody, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Request, Response } from 'express';
import { LoginResponseDto } from '../dto/login.dto';
import { ConfirmationDto } from './dto/confirmation.dto';
import { EmailConfirmationService } from './email-confirmation.service';

@ApiTags('Підтвердження пошти')
@Controller('auth/email-confirmation')
export class EmailConfirmationController {
  constructor(private readonly emailConfirmationService: EmailConfirmationService) {}

  @Post()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Підтвердження електронної пошти після реєстрації' })
  @ApiResponse({ status: 200, description: 'Пошта підтверджена успішно', type: LoginResponseDto})
  @ApiBody({ type: ConfirmationDto })
  @ApiResponse({
    status: 400,
    description: 'Токен підтвердження прострочений',
  })
  @ApiResponse({
    status: 404,
    description: 'Токен або користувач не знайдені',
  })
  public async newVerification(
    @Req() req: Request, 
    @Res({ passthrough: true }) res: Response,
    @Body() dto: ConfirmationDto
  ) {
    return this.emailConfirmationService.newVerification(req, res, dto)
  }
}
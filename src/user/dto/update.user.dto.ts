import { ApiPropertyOptional } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import { IsBoolean, IsDateString, IsEmail, IsEnum, IsOptional, IsString } from 'class-validator';

export enum Gender {
  MALE = 'male',
  FEMALE = 'female',
  UNKNOWN = 'unknown',
}

export class UpdateUserDto {
  @ApiPropertyOptional({ example: 'Іван Петренко', description: "Ім'я користувача" })
  @IsOptional()
  @IsString({ message: 'Name must be a string.' })
  name?: string; 

  @ApiPropertyOptional({ example: 'ivan@example.com', description: 'Нова email адреса користувача' })
  @IsOptional()
  @IsEmail({}, { message: 'Invalid email format.' })
  @IsString({ message: 'Email must be a string.' })
  email?: string;

  @ApiPropertyOptional({
    enum: Gender,
    example: Gender.UNKNOWN,
    description: "Стать користувача (значення: 'male' | 'female' | 'unknown')",
  })
  @IsOptional()
  @Transform(({ value }) => (typeof value === 'string' ? value.toLowerCase() : value))
  @IsEnum(Gender, { message: "Gender must be one of: 'male', 'female', 'unknown'." })
  gender?: Gender;

  @ApiPropertyOptional({ example: true, description: 'Чи увімкнено 2FA' })
  @IsOptional()
  @IsBoolean({ message: 'isTwoFactorEnabled must be a boolean.' })
  isTwoFactorEnabled?: boolean;

  @ApiPropertyOptional({ example: 'some-refresh-token', description: 'Оновлений refresh токен' })
  @IsOptional()
  @IsString({ message: 'Refresh token must be a string.' })
  refreshToken?: string;
  
  @ApiPropertyOptional({ example: true, description: 'Статус верифікації через Дію', readOnly: true })
  @IsOptional()
  @IsBoolean()
  diiaVerified?: boolean;

  @ApiPropertyOptional({
    example: '2025-08-27T13:12:51.000Z',
    description: 'Час верифікації через Дію (ISO 8601)',
    readOnly: true,
  })
  @IsOptional()
  @IsDateString()
  diiaVerifiedAt?: string; // можна Date, але для валідації зручніше ISO-рядок

  @ApiPropertyOptional({
    example: '****08544',
    description: 'Маска стабільного ідентифікатора (для UI)',
    readOnly: true,
  })
  @IsOptional()
  @IsString()
  diiaLastDocMask?: string;

  @ApiPropertyOptional({
    example: '2b9f1b3b9e... (sha256)',
    description: 'Хеш DRFO/serial з Дії (server-only)',
    readOnly: true,
  })
  @IsOptional()
  @IsString()
  diiaStableIdHash?: string;
}

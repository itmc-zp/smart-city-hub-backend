import { ApiProperty } from '@nestjs/swagger';
import { AuthMethod, TwoFactorType } from 'src/entities/user.entity';


export class UserDto {
  @ApiProperty({ example: 'faef-3124-abc...', description: 'Унікальний ID користувача' })
  id: string;

  @ApiProperty({ example: 'ivan@example.com', description: 'Email користувача' })
  email: string;

  @ApiProperty({ example: 'Іван Петренко', description: 'Ім’я користувача' })
  displayName: string;

  @ApiProperty({ example: 'https://example.com/avatar.png', description: 'Фото профілю якщо вхід через Google', required: false })
  picture?: string;

  @ApiProperty({ example: true, description: 'Чи підтверджено email' })
  isVerified: boolean;

  @ApiProperty({ example: false, description: 'Чи включено двофакторну автентифікацію' })
  isTwoFactorEnabled: boolean;

  @ApiProperty({ example: 'CREDENTIALS', description: 'Метод реєстрації', enum: AuthMethod})
  method: AuthMethod;

  @ApiProperty({ example: 'APP', description: 'Тип 2FA', enum: TwoFactorType })
  twoFactorType: TwoFactorType;

  @ApiProperty({ example: '2024-05-21T10:20:30.000Z', description: 'Дата створення облікового запису' })
  createdAt: Date;

  @ApiProperty({ example: '2024-06-10T15:11:12.000Z', description: 'Дата останнього оновлення' })
  updatedAt: Date;

 /* @ApiProperty({ type: [AccountDto], description: 'Список акаунтів користувача', required: false })
    accounts?: AccountDto[];
  */
}

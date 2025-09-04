import { ApiProperty } from '@nestjs/swagger';
import {
  IsNotEmpty,
  IsString,
  Matches,
  MinLength,
} from 'class-validator';

export class ChangePasswordDto {
  @ApiProperty({
    example: 'OldPass123!',
    description: 'Старий пароль користувача',
  })
  @IsNotEmpty({ message: 'Поле паролю не може бути порожнім.' })
  @IsString({ message: 'Пароль повинен бути рядком.' })
  oldPassword: string;

  @ApiProperty({
    example: 'Qwerty1!',
    description: 'Новий складний пароль. Повинен містити великі і малі літери, цифру та спеціальний символ.',
  })
  @IsString({ message: 'Пароль повинен бути рядком.' })
  @IsNotEmpty({ message: 'Поле паролю не може бути порожнім.' })
  @MinLength(6, { message: 'Пароль має містити щонайменше 6 символів.' })
  @Matches(/[A-Z]/, { message: 'Пароль повинен містити хоча б одну велику літеру' })
  @Matches(/[a-z]/, { message: 'Пароль повинен містити хоча б одну маленьку літеру' })
  @Matches(/\d/, { message: 'Пароль повинен містити хоча б одну цифру' })
  @Matches(/[^A-Za-z0-9]/, { message: 'Пароль повинен містити хоча б один спеціальний символ' })
  newPassword: string;
}


import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsEnum, IsNotEmpty, IsString, Matches, MinLength, Validate } from 'class-validator';
import { DeviceType } from 'src/entities/user.entity';
import { IsPasswordsMatchingConstraint } from 'src/libs/common/decorators/is-passwords-matching-constraint.decorator';

export enum Gender {
  MALE = 'male',
  FEMALE = 'female',
  UNKNOWN = 'unknown',
}

export class RegisterDto {
  @IsString()
  @IsNotEmpty({ message: "Ім'я є обов'язковим" })
  @ApiProperty({ example: 'Іван', description: "Ім'я користувача" })
  firstName: string;

  @IsString()
  @IsNotEmpty({ message: 'Прізвище є обов’язковим' })
  @ApiProperty({ example: 'Петренко', description: 'Прізвище користувача' })
  lastName: string;

  @IsEmail({}, { message: 'Невірний формат електронної пошти.' })
  @ApiProperty({ example: 'ivan@example.com', description: 'Email адреса користувача' })
  email: string;

  @IsString()
  @MinLength(6, { message: 'Пароль має містити щонайменше 6 символів.' })
  @Matches(/[A-Z]/, { message: 'Пароль повинен містити хоча б одну велику літеру' })
  @Matches(/[a-z]/, { message: 'Пароль повинен містити хоча б одну маленьку літеру' })
  @Matches(/\d/, { message: 'Пароль повинен містити хоча б одну цифру' })
  @Matches(/[^A-Za-z0-9]/, { message: 'Пароль повинен містити хоча б один спеціальний символ' })
  @ApiProperty({ example: 'Qwerty1!', description: 'Складний пароль' })
  password: string;

  @IsString()
  @IsNotEmpty({ message: 'Підтвердження паролю є обов’язковим' })
  @MinLength(6, { message: 'Підтвердження паролю має містити щонайменше 6 символів.' })
  @Validate(IsPasswordsMatchingConstraint, { message: 'Паролі не збігаються.' })
  @ApiProperty({ example: 'Qwerty1!', description: 'Підтвердження паролю' })
  passwordRepeat: string;

  @ApiProperty({
		enum: DeviceType,
		example: DeviceType.DESKTOP,
		description: 'Тип пристрою користувача (DESKTOP або MOBILE)',
	  })
  @IsEnum(DeviceType)
  deviceType: DeviceType;

  @ApiProperty({
    enum: Gender,
    example: Gender.UNKNOWN,
    description: 'Стать користувача (male, female, unknown)',
  })
  @IsEnum(Gender)
  gender: Gender;
}
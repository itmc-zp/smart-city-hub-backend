import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
	IsEmail,
	IsEnum,
	IsNotEmpty,
	IsOptional,
	IsString,
	Matches,
	MinLength
} from 'class-validator';
import { DeviceType } from 'src/entities/user.entity';
import { UserDto } from 'src/user/dto/user.dto';

export class LoginDto {
	@ApiProperty({
	  example: 'user@example.com',
	  description: 'Email користувача',
	})
	@IsString()
	@IsEmail({}, { message: 'Невірний формат електронної пошти.' })
	@IsNotEmpty({ message: 'Поле email є обов’язковим' })
	email: string;
  
	@ApiProperty({
	  example: 'Qwerty1!',
	  description: 'Складний пароль',
	})
	@IsString()
	@IsNotEmpty({ message: 'Поле паролю не може бути порожнім.' })
	@MinLength(6, { message: 'Пароль має містити щонайменше 6 символів.' })
	@Matches(/[A-Z]/, { message: 'Пароль повинен містити хоча б одну велику літеру' })
	@Matches(/[a-z]/, { message: 'Пароль повинен містити хоча б одну маленьку літеру' })
	@Matches(/\d/, { message: 'Пароль повинен містити хоча б одну цифру' })
	@Matches(/[^A-Za-z0-9]/, { message: 'Пароль повинен містити хоча б один спеціальний символ' })
	password: string;
  
	@ApiPropertyOptional({
	  example: '123456',
	  description: '2FA код, якщо включена двофакторна автентифікація',
	})
	@IsOptional()
	@IsString()
	code: string;

	@ApiProperty({
		enum: DeviceType,
		example: DeviceType.DESKTOP,
		description: 'Тип пристрою користувача (DESKTOP або MOBILE)',
	  })
	 @IsEnum(DeviceType)
	  deviceType: DeviceType;
  }

  export class LoginResponseDto {
	@ApiProperty({
	  description: 'JWT access token для авторизації',
	  example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
	})
	access_token: string;
  
	@ApiProperty({
	  description: 'Дані користувача',
	  type: () => UserDto,
	})
	user: UserDto;
  }
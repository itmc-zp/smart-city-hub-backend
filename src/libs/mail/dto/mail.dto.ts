import { ApiProperty } from '@nestjs/swagger';
import { IsDateString, IsEmail, IsPhoneNumber, IsString } from 'class-validator';

export class IndividualFormDto {
  @ApiProperty({ description: "ПІБ заявника" })
  @IsString()
  fullName: string;

  @ApiProperty({ description: "Email заявника" })
  @IsEmail()
  email: string;

  @ApiProperty({ description: "Номер телефону (UA)" })
  @IsPhoneNumber('UA')
  phoneNumber: string;

  @ApiProperty({ description: "Місце проживання" })
  @IsString()
  location: string;

  @ApiProperty({ description: "Місце проведення події" })
  @IsString()
  eventLocation: string;

  @ApiProperty({ description: "Дата події" })
  @IsDateString()
  eventDate: string;

  @ApiProperty({ description: "Час події" })
  @IsString()
  eventTime: string;

  @ApiProperty({ description: "Токен Captcha" })
  @IsString()
  captchaToken: string;
}


export class LegalEntityFormDto {
  @ApiProperty({ description: "Назва компанії" })
  @IsString()
  companyName: string;

  @ApiProperty({ description: "Місцезнаходження компанії" })
  @IsString()
  location: string;

  @ApiProperty({ description: "ЄДРПОУ" })
  @IsString()
  edrpouCode: string;

  @ApiProperty({ description: "ПІБ представника" })
  @IsString()
  fullName: string;

  @ApiProperty({ description: "Посада представника" })
  @IsString()
  position: string;

  @ApiProperty({ description: "Номер телефону (UA)" })
  @IsPhoneNumber('UA')  
  phoneNumber: string;

  @ApiProperty({ description: "Email компанії або представника" })
  @IsEmail()
  email: string;

  @ApiProperty({ description: "Місце події" })
  @IsString()
  eventLocation: string;

  @ApiProperty({ description: "Дата події" })
  @IsDateString()
  eventDate: string;
  
  @ApiProperty({ description: "Час події" })
  @IsString()
  eventTime: string;

  @ApiProperty({ description: "Токен Captcha" })
  @IsString()
  captchaToken: string;
}


export class FeedbackFormDto {
  @ApiProperty({ description: "Імʼя користувача" })
  @IsString()
  name: string;

  @ApiProperty({
    description: "Телефон або email",
    example: "example@gmail.com або +380971234567",
  })
  @IsString()
  phoneOrEmail: string; 

  @ApiProperty({ description: "Текст звернення" })
  @IsString()
  feedback: string;

  @ApiProperty({ description: "Токен Captcha" })
  @IsString()
  captchaToken: string; 
}

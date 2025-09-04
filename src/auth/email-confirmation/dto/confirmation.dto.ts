import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty, IsString } from "class-validator";

export class ConfirmationDto {
  @ApiProperty({
    example: 'abc123token',
    description: 'Токен підтвердження, надісланий на електронну пошту',
  })
  @IsString({ message: 'Token must be a string.' })
  @IsNotEmpty({ message: 'Token field cannot be empty.' })
  token: string;
}
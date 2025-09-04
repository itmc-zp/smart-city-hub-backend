import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsNotEmpty } from "class-validator";

export class ResetPasswordDto {
    @ApiProperty({
        example: 'user@example.com',
        description: 'Email користувача для відновлення паролю',
      })
    @IsEmail({}, { message: 'Please enter a valid email address.' })
    @IsNotEmpty({ message: 'Email field cannot be empty.' })
    email: string;
}

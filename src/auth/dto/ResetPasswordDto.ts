import { ApiProperty } from '@nestjs/swagger'
import { IsNotEmpty, IsEmail, IsNumberString, Length } from 'class-validator'

export class RequestPasswordResetDto {
  @ApiProperty()
  @IsEmail()
  email: string
}

export class PasswordResetDto {
  @ApiProperty()
  @IsNumberString()
  @Length(6, 6)
  code: string

  @ApiProperty()
  @IsNotEmpty()
  password: string
}

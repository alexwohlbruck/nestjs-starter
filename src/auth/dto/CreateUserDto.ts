import { ApiProperty } from '@nestjs/swagger'
import { IsEmail, IsNotEmpty } from 'class-validator'

// TODO: Add complete validation rules and make sure the request cannot crash the server

class Name {
  @ApiProperty()
  @IsNotEmpty()
  first: string

  @ApiProperty()
  @IsNotEmpty()
  last: string
}

export class CreateUserDto {
  // Name
  @ApiProperty()
  @IsNotEmpty()
  name: Name

  @ApiProperty()
  @IsEmail()
  email: string

  // TODO: Enforce password length and complexity
  @ApiProperty()
  @IsNotEmpty()
  password: string
}

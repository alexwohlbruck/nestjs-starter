import { ApiProperty } from '@nestjs/swagger'
import { Role } from '@prisma/client'
import { IsEmail, IsNotEmpty } from 'class-validator'

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

  @ApiProperty()
  @IsNotEmpty()
  password: string

  @ApiProperty({ enum: Role, default: [], isArray: true })
  roles: Role[]
}

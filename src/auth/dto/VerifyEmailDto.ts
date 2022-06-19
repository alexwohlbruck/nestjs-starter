import { ApiProperty } from '@nestjs/swagger'
import { Length, IsNumberString } from 'class-validator'

export class VerifyEmailDto {
  @ApiProperty()
  @IsNumberString()
  @Length(6, 6)
  code: string
}

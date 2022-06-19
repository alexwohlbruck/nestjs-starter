import {
  Body,
  Controller,
  Get,
  Post,
  Query,
  Request,
  UseGuards,
} from '@nestjs/common'
import { JwtAuthGuard } from '../auth/jwt-auth.guard'
import { Prisma, User as UserModel } from '@prisma/client'
import { UsersService } from './users.service'
import { ApiProperty } from '@nestjs/swagger'

class Test {
  @ApiProperty()
  name: string
}

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  /**
   * Return the user profile
   */
  @UseGuards(JwtAuthGuard)
  @Get('me')
  getProfile(@Request() req) {
    return req.user
  }

  // Search user
  @Get('search')
  async searchUser(
    @Query()
    query: {
      skip?: number
      take?: number
      cursor?: Prisma.UserWhereUniqueInput
      where?: Prisma.UserWhereInput
      orderBy?: Prisma.UserOrderByWithRelationInput
    },
  ): Promise<UserModel[]> {
    return this.usersService.find(query)
  }

  @Post('test')
  async test(
    @Body()
    data: Test,
  ) {
    return data
  }
}

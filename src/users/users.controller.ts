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
import { ApiProperty, ApiQuery, ApiTags } from '@nestjs/swagger'
import { CreateUserDto } from '../generated/nestjs-dto/create-user.dto'

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
  @Get('profile')
  getProfile(@Request() req) {
    return req.user
  }

  // TODO: Move to auth module
  @Post('user')
  async signupUser(
    @Body()
    userData: CreateUserDto,
  ): Promise<UserModel> {
    return this.usersService.createUser(userData)
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

import {
  Body,
  Controller,
  Get,
  InternalServerErrorException,
  Post,
  Query,
  Request,
  UseGuards,
} from '@nestjs/common'
import { JwtAuthGuard } from '../auth/jwt-auth.guard'
import { Prisma, User as UserModel } from '@prisma/client'
import { UsersService } from './users.service'
import { ApiProperty, ApiTags } from '@nestjs/swagger'
import { NotifierService } from '../notifier/notifier.service'

class Test {
  @ApiProperty()
  name: string
}
@ApiTags('Users')
@Controller('users')
export class UsersController {
  constructor(
    private readonly usersService: UsersService,
    private readonly notifierService: NotifierService,
  ) {}

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
    data: {
      message: string
    },
  ) {
    try {
      return await this.notifierService.sendSms('+17045599636', data.message)
    } catch (e) {
      throw new InternalServerErrorException(e.message)
    }
  }
}

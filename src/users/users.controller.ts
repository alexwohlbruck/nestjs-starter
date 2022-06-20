import { Controller, Get, Query, Request, UseGuards } from '@nestjs/common'
import { JwtAuthGuard } from '../auth/jwt-auth.guard'
import { Prisma, Role, User as UserModel } from '@prisma/client'
import { UsersService } from './users.service'
import { ApiTags } from '@nestjs/swagger'
import { Roles } from '../auth/auth-decorators'
import { RolesGuard } from '../auth/roles.guard'
import { JwtPayload } from '../auth/jwt.strategy'

@ApiTags('Users')
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  /**
   * Return the user profile
   */
  @Get('me')
  @Roles(Role.ADMIN, Role.SUPERVISOR)
  getProfile(@Request() { user }: { user: JwtPayload }) {
    console.log({ groups: user.groupIds })
    return user
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
}

import {
  ConflictException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common'
import { PrismaService } from '../prisma/prisma.service'
import {
  Prisma,
  User,
  VerificationCode,
  VerificationCodeType,
} from '@prisma/client'
import { hash } from 'bcrypt'
import { CreateUserDto } from '../auth/dto/CreateUserDto'

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  async findOne(
    userWhereUniqueInput: Prisma.UserWhereUniqueInput,
  ): Promise<User | undefined> {
    return this.prisma.user.findUnique({
      where: userWhereUniqueInput,
    })
  }

  async find(params: {
    skip?: number
    take?: number
    cursor?: Prisma.UserWhereUniqueInput
    where?: Prisma.UserWhereInput
    orderBy?: Prisma.UserOrderByWithRelationInput
  }): Promise<User[]> {
    const { skip, take, cursor, where, orderBy } = params
    return this.prisma.user.findMany({
      skip,
      take,
      cursor,
      where,
      orderBy,
    })
  }

  async createUser(data: CreateUserDto): Promise<User> {
    // Check user exists
    const user = await this.findOne({ email: data.email })
    if (user) {
      throw new ConflictException('User already exists')
    }

    const newUser = await this.prisma.user.create({
      data: {
        ...data,
        password: await hash(data.password, 12), // TODO: Salt?? Apparently bcrypt might handle this automatically
      },
    })

    this.createVerificationCode(newUser.id)
    // TODO: Email code to user with notification service

    return newUser
  }

  /**
   * Generate a verification code
   * @returns A 6-digit numeric code
   */
  async createVerificationCode(userId: string): Promise<VerificationCode> {
    const code = (Math.floor(Math.random() * 900000) + 100000).toString()
    try {
      return await this.prisma.verificationCode.create({
        data: {
          userId: userId,
          code,
          type: VerificationCodeType.EMAIL,
        },
      })
    } catch (e) {
      if (e?.code === 'P2002') {
        // If the code already exists, try again
        return this.createVerificationCode(userId)
      }
      throw new InternalServerErrorException(e)
    }
  }

  /**
   * Accept an email verification code and mark the user's email as verified
   */
  async verifyEmail(code: string): Promise<User> {
    const foundCode = await this.prisma.verificationCode.findFirst({
      where: {
        code,
        type: VerificationCodeType.EMAIL,
      },
    })
    if (!foundCode) {
      throw new UnauthorizedException('Invalid verification code')
    }
    const promises = [
      this.prisma.user.update({
        where: {
          id: foundCode.userId,
        },
        data: {
          emailVerified: true,
        },
      }),
      this.prisma.verificationCode.delete({
        where: {
          id: foundCode.id,
        },
      }),
    ]
    // Get user from promise results
    const [user] = await Promise.all(promises)
    return user as User
  }

  async updateUser(params: {
    where: Prisma.UserWhereUniqueInput
    data: Prisma.UserUpdateInput
  }): Promise<User> {
    const { where, data } = params
    return this.prisma.user.update({
      data,
      where,
    })
  }

  async deleteUser(where: Prisma.UserWhereUniqueInput): Promise<User> {
    return this.prisma.user.delete({ where })
  }
}

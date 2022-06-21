import {
  ForbiddenException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
  InternalServerErrorException,
  ConflictException,
} from '@nestjs/common'
import {
  User,
  VerificationCode,
  VerificationCodeType,
  UserRole,
} from '@prisma/client'
import { JwtService } from '@nestjs/jwt'
import { PrismaService } from '../prisma/prisma.service'
import { CreateUserDto } from '../auth/dto/CreateUserDto'
import { hash, compare } from 'bcrypt'
import { NotifierService } from '../notifier/notifier.service'

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly notifierService: NotifierService,
  ) {}

  /**
   * Generate a password hash
   */
  async hashPassword(password: string): Promise<string> {
    return await hash(password, 12)
  }

  /**
   * Compare two passwords
   */
  async comparePasswords(password: string, hash: string): Promise<boolean> {
    return compare(password, hash)
  }

  /**
   * Generate a verification code
   * @returns A 6-digit numeric code
   */
  async createVerificationCode(
    userId: string,
    type: VerificationCodeType,
  ): Promise<VerificationCode> {
    const code = (Math.floor(Math.random() * 900000) + 100000).toString()
    try {
      return await this.prisma.verificationCode.create({
        data: {
          userId: userId,
          code,
          type,
        },
      })
    } catch (e) {
      if (e?.code === 'P2002') {
        // If the code already exists, try again
        return this.createVerificationCode(userId, type)
      }
      throw new InternalServerErrorException(e)
    }
  }

  /**
   * Check if a verification code is valid. If so, delete it.
   * @returns VerificationCode if the code is valid, UnauthorizedException otherwise
   */
  async checkVerificationCode(
    code: string,
    type: VerificationCodeType,
  ): Promise<VerificationCode> {
    const foundCode = await this.prisma.verificationCode.findFirst({
      where: { code, type },
    })
    if (!foundCode) {
      throw new UnauthorizedException('Invalid verification code.')
    }
    await this.prisma.verificationCode.delete({
      where: { id: foundCode.id },
    })
    return foundCode
  }

  // TODO: Cache this db call with Redis
  /**
   * Get a user's roles
   */
  async getUserRoles(userId: string): Promise<UserRole[]> {
    return this.prisma.userRole.findMany({
      where: {
        userId,
      },
    })
  }

  /**
   * Used by Passport to validate a user who is logging in
   */
  async validateUser(email: string, password: string) {
    const user = await this.prisma.user.findUnique({
      where: { email },
      select: {
        emailVerified: true,
        password: true,
      },
    })
    if (!user) {
      throw new NotFoundException("User doesn't exist.")
    }
    if (!user.emailVerified) {
      throw new ForbiddenException('Email not verified.')
    }
    const isPasswordMatched = await this.comparePasswords(
      password,
      user.password,
    )
    if (!isPasswordMatched) {
      throw new UnauthorizedException('Invalid password.')
    }
    return user
  }

  /**
   * Sign a new JWT token for a user
   */
  async signToken(user: User) {
    const payload = {
      email: user.email,
      sub: user.id,
      name: user.name,
    }
    return {
      access_token: this.jwtService.sign(payload),
    }
  }

  /**
   * Create a new user
   */
  async register(data: CreateUserDto): Promise<User> {
    // Check user exists
    const user = await this.prisma.user.findUnique({
      where: { email: data.email },
    })
    if (user) {
      throw new ConflictException('User already exists.')
    }

    const newUser = await this.prisma.user.create({
      data: {
        ...data,
        password: await this.hashPassword(data.password),
      },
    })

    const verifcationCode = await this.createVerificationCode(
      newUser.id,
      VerificationCodeType.EMAIL,
    )
    try {
      await this.notifierService.sendEmailWithTemplate(
        newUser.email,
        'email-verification',
        'verifyEmail',
        {
          firstName: newUser.name.first,
          // TODO: Build proper url
          // url: `${process.env.FRONTEND_URL}/verify-email/${code.code}`,
          url: `http://localhost:3000/verify-email?code=${verifcationCode.code}`,
        },
      )
    } catch (e) {
      throw new InternalServerErrorException(e.message)
    }

    return newUser
  }

  /**
   * Accept an email verification code and mark the user's email as verified
   */
  async verifyEmail(code: string): Promise<User> {
    const foundCode = await this.checkVerificationCode(
      code,
      VerificationCodeType.EMAIL,
    )

    return this.prisma.user.update({
      where: {
        id: foundCode.userId,
      },
      data: {
        emailVerified: true,
      },
    })
  }

  /**
   * Request a password reset code
   */
  async requestPasswordReset(email: string) {
    const user = await this.prisma.user.findUnique({
      where: { email },
    })
    if (!user) {
      throw new UnauthorizedException('Invalid email.')
    }
    const verifcationCode = await this.createVerificationCode(
      user.id,
      VerificationCodeType.PASSWORD_RESET,
    )
    try {
      await this.notifierService.sendEmailWithTemplate(
        user.email,
        'Verify your email',
        'requestPasswordReset',
        {
          firstName: user.name.first,
          // TODO: Build proper url
          // url: `${process.env.FRONTEND_URL}/verify-email/${code.code}`,
          url: `http://localhost:3000/reset-password?code=${verifcationCode.code}`,
        },
      )
    } catch (e) {
      throw new InternalServerErrorException(e.message)
    }
    return { message: `Password reset link sent to ${email}.` }
  }

  /**
   * Reset a user's password using a password reset code
   */
  async resetPassword(code: string, password: string) {
    const foundCode = await this.checkVerificationCode(
      code,
      VerificationCodeType.PASSWORD_RESET,
    )

    await this.prisma.user.update({
      where: {
        id: foundCode.userId,
      },
      data: {
        password: await this.hashPassword(password),
      },
    })

    return { message: 'Password reset successful.' }
  }
}

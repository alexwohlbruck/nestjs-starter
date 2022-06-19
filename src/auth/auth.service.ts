import {
  ForbiddenException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { PrismaService } from '../prisma/prisma.service'
import { compare, hash } from 'bcrypt'

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}

  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.prisma.user.findUnique({
      where: { email },
    })
    if (!user) {
      throw new NotFoundException("User doesn't exist")
    }
    if (!user.emailVerified) {
      throw new ForbiddenException('Email not verified')
    }
    const isPasswordMatched = await compare(password, user.password)
    if (!isPasswordMatched) {
      throw new UnauthorizedException('Invalid password')
    }
    return user
  }

  async login(user: any) {
    const payload = { username: user.username, sub: user.userId }
    return {
      access_token: this.jwtService.sign(payload),
    }
  }
}

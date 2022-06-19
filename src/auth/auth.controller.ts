import {
  Controller,
  Request,
  Post,
  UseGuards,
  Get,
  Res,
  Body,
} from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { User } from '@prisma/client'
import { AuthService } from '../auth/auth.service'
import { JwtAuthGuard } from '../auth/jwt-auth.guard'
import { LocalAuthGuard } from '../auth/local-auth.guard'
import { UsersService } from '../users/users.service'
import { CreateUserDto } from './dto/CreateUserDto'
import { VerifyEmailDto } from './dto/VerifyEmailDto'

@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private configService: ConfigService,
    private usersService: UsersService,
  ) {}

  /**
   * Log in
   */
  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login(@Request() req, @Res({ passthrough: true }) res) {
    const response = await this.authService.login(req.user)

    res.cookie('access_token', response.access_token, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      maxAge: this.configService.get('JWT_LIFETIME'),
    })

    return response
  }

  /**
   * Register new account
   */
  @Post('register')
  async signupUser(
    @Body()
    userData: CreateUserDto,
  ): Promise<User> {
    return this.usersService.createUser(userData)
  }

  /**
   * Log out the user. This is only needed for cookie-based auth
   */
  @UseGuards(JwtAuthGuard)
  @Get('logout')
  logout(@Res() res) {
    res.clearCookie('access_token')
    return { message: 'Logged out' }
  }

  /**
   * Verify the user's email address
   */
  @Post('verify-email')
  async verifyEmail(@Body() { code }: VerifyEmailDto) {
    return await this.usersService.verifyEmail(code)
  }
}

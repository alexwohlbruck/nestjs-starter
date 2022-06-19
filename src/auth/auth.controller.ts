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
import { ApiTags } from '@nestjs/swagger'
import { User } from '@prisma/client'
import { AuthService } from '../auth/auth.service'
import { JwtAuthGuard } from '../auth/jwt-auth.guard'
import { LocalAuthGuard } from '../auth/local-auth.guard'
import { CreateUserDto } from './dto/CreateUserDto'
import { LoginDto } from './dto/LoginDto'
import {
  PasswordResetDto,
  RequestPasswordResetDto,
} from './dto/ResetPasswordDto'
import { VerifyEmailDto } from './dto/VerifyEmailDto'

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private configService: ConfigService,
  ) {}

  /**
   * Log in
   */
  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login(
    @Request()
    req: {
      user: User
    },
    @Body() _credentials: LoginDto,
    @Res({ passthrough: true }) res,
  ) {
    const response = await this.authService.signToken(req.user)

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
    return this.authService.register(userData)
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
    return await this.authService.verifyEmail(code)
  }

  /**
   * Request a password reset code
   */
  @Post('request-password-reset')
  async requestPasswordReset(@Body() { email }: RequestPasswordResetDto) {
    return await this.authService.requestPasswordReset(email)
  }

  /**
   * Reset the user's password
   */
  @Post('reset-password')
  async resetPassword(@Body() { code, password }: PasswordResetDto) {
    return await this.authService.resetPassword(code, password)
  }
}

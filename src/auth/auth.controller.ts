import {
  Controller,
  Request,
  Post,
  UseGuards,
  Res,
  Body,
  UnauthorizedException,
} from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { ApiTags } from '@nestjs/swagger'
import { User } from '@prisma/client'
import { AuthService } from '../auth/auth.service'
import { LocalAuthGuard } from '../auth/local-auth.guard'
import { Public } from './auth-decorators'
import { CreateUserDto } from './dto/CreateUserDto'
import { LoginDto } from './dto/LoginDto'
import {
  PasswordResetDto,
  RequestPasswordResetDto,
} from './dto/ResetPasswordDto'
import { VerifyEmailDto } from './dto/VerifyEmailDto'

@ApiTags('Authentication')
@Controller('auth')
@Public()
export class AuthController {
  constructor(
    private authService: AuthService,
    private configService: ConfigService,
  ) {}

  setJwtCookie(res, token) {
    res.cookie('access_token', token, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      maxAge: this.configService.get('JWT_LIFETIME'),
    })
  }

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
    const twoFactorEnabled = req.user.twoFactorEnabled

    const token = await this.authService.signToken(
      req.user,
      !twoFactorEnabled, // If 2fa is enabled, authentication flow hasn't completed yet
    )

    this.setJwtCookie(res, token.access_token)

    return token
  }

  /**
   * Validate 2 factor TOTP code
   */
  @Post('totp')
  async validateTotp(
    @Request()
    req: {
      user: User
    },
    @Body() { code }: { code: string },
    @Res({ passthrough: true }) res,
  ) {
    const isValid = this.authService.validateTotp(req.user.id, code)
    if (!isValid) {
      throw new UnauthorizedException('Invalid TOTP code.')
    }
    const token = await this.authService.signToken(req.user, true)
    this.setJwtCookie(res, token.access_token)
    return token
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
  @Post('logout')
  logout(@Res({ passthrough: true }) res) {
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

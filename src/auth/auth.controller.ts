import {
  Controller,
  Request,
  Post,
  UseGuards,
  Res,
  Body,
  UnauthorizedException,
  Patch,
  Get,
  Redirect,
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
import * as qrcode from 'qrcode'
import { JwtAuthGuard } from './jwt-auth.guard'

@ApiTags('Authentication')
@Controller('auth')
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
  @Public()
  async login(
    @Request()
    req: {
      user: User
    },
    @Body() _credentials: LoginDto,
    @Res({ passthrough: true }) res,
  ) {
    const twoFactorEnabled = req.user.twoFactorEnabled

    const { access_token } = await this.authService.signToken(
      req.user,
      !twoFactorEnabled, // If 2fa is enabled, authentication flow hasn't completed yet
    )

    this.setJwtCookie(res, access_token)

    return {
      access_token,
      twoFactorEnabled,
    }
  }

  /**
   * Validate 2 factor TOTP token
   */
  @Post('2fa/totp')
  @UseGuards(JwtAuthGuard)
  async validateTotpToken(
    @Request()
    req: {
      user: User
    },
    @Body() { code }: { code: string },
    @Res({ passthrough: true }) res,
  ) {
    const isValid = await this.authService.validateTotpToken(req.user.id, code)
    if (!isValid) {
      throw new UnauthorizedException('Invalid TOTP token.')
    }
    const token = await this.authService.signToken(req.user, true)
    this.setJwtCookie(res, token.access_token)
    return token
  }

  /**
   * Toggle 2FA for a user
   */
  @Patch('2fa')
  @UseGuards(JwtAuthGuard)
  async toggle2fa(
    @Request()
    req: {
      user: User
    },
  ) {
    return await this.authService.toggleTwoFactor(req.user.id)
  }

  /**
   * Get TOTP secret for a user
   */
  @Get('2fa/totp')
  @UseGuards(JwtAuthGuard)
  async getTotpSecret(
    @Request()
    req: {
      user: User
    },
  ) {
    const secret = await this.authService.getTotpSecret(req.user.id)
    const appName = this.configService.get('APP_NAME')
    const url = `otpauth://totp/${appName}:${req.user.email}?secret=${secret}&issuer=${appName}`
    const qr = await qrcode.toDataURL(url)
    return { secret, url, qrCode: qr }
  }

  // Return the current totp
  @Get('2fa/totp/current')
  @UseGuards(JwtAuthGuard)
  async getUser(@Request() req: { user: User }) {
    return this.authService.currentTotp(req.user.id)
  }

  /**
   * Register new account
   */
  @Post('register')
  @Public()
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
  @Public()
  logout(@Res({ passthrough: true }) res) {
    res.clearCookie('access_token')
    return { message: 'Logged out' }
  }

  /**
   * Verify the user's email address
   */
  @Post('verify-email')
  @Public()
  async verifyEmail(@Body() { code }: VerifyEmailDto) {
    return await this.authService.verifyEmail(code)
  }

  /**
   * Request a password reset code
   */
  @Post('request-password-reset')
  @Public()
  async requestPasswordReset(@Body() { email }: RequestPasswordResetDto) {
    return await this.authService.requestPasswordReset(email)
  }

  /**
   * Reset the user's password
   */
  @Post('reset-password')
  @Public()
  async resetPassword(@Body() { code, password }: PasswordResetDto) {
    return await this.authService.resetPassword(code, password)
  }
}

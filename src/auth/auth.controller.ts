import { Controller, Request, Post, UseGuards, Get, Res } from '@nestjs/common'
import { AuthService } from '../auth/auth.service'
import { jwtConstants } from '../auth/constants'
import { JwtAuthGuard } from '../auth/jwt-auth.guard'
import { LocalAuthGuard } from '../auth/local-auth.guard'

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login(@Request() req, @Res({ passthrough: true }) res) {
    const response = await this.authService.login(req.user)

    res.cookie('access_token', response.access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: jwtConstants.lifetime,
    })

    return response
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
}

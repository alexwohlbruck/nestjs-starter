import { Controller, Request, Post, UseGuards, Get, Res } from '@nestjs/common'
import { AuthService } from './auth/auth.service'
import { jwtConstants } from './auth/constants'
import { JwtAuthGuard } from './auth/jwt-auth.guard'
import { LocalAuthGuard } from './auth/local-auth.guard'

@Controller()
export class AppController {
  constructor(private authService: AuthService) {}

  @UseGuards(LocalAuthGuard)
  @Post('auth/login')
  async login(@Request() req, @Res({ passthrough: true }) res) {
    const response = await this.authService.login(req.user)

    res.cookie('access_token', response.access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: jwtConstants.lifetime,
    })

    return response
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@Request() req) {
    return req.user
  }
}

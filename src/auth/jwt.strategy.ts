import { Strategy, ExtractJwt } from 'passport-jwt'
import { PassportStrategy } from '@nestjs/passport'
import { Injectable } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'

export class JwtPayload {
  id: string
  sub: string
  email: string
  authenticated: boolean
  groupIds?: string[];
  [key: string]: any
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        JwtStrategy.fromCookie,
        ExtractJwt.fromAuthHeaderAsBearerToken(),
      ]),
      ignoreExpiration: false,
      secretOrKey: configService.get('JWT_SECRET'),
    })
  }

  validate(payload: any): JwtPayload {
    return {
      id: payload.sub,
      ...payload,
      sub: undefined,
    }
  }

  // Extract JWT token from fastify request
  private static fromCookie(req: any): string | null {
    const cookie = req.cookies.access_token
    if (cookie) {
      return cookie
    }
    return null
  }
}

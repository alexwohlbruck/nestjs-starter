import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { Role } from '@prisma/client'
import { ROLE_KEY } from './auth-decorators'
import { AuthService } from './auth.service'
import { JwtPayload } from './jwt.strategy'

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector, private authService: AuthService) {}

  async canActivate(context: ExecutionContext) {
    const requiredRoles = this.reflector.get<Role[]>(
      ROLE_KEY,
      context.getHandler(),
    )
    if (!requiredRoles) {
      return true
    }
    const request = context.switchToHttp().getRequest()
    const user = request.user as JwtPayload

    if (!user.authenticated) {
      return false
    }

    const userRoles = await this.authService.getUserRoles(user.id)

    // Extract group ids the user belongs to and add it to context
    // Routes can use req.groupIds in their logic to scope group-specific resources
    const groupIds = userRoles
      .map(role => role.groupId)
      .filter(role => {
        return role !== null
      })
    request.user.groupIds = groupIds

    return matchRoles(
      requiredRoles,
      userRoles.map(role => role.type),
    )
  }
}

function matchRoles(requiredRoles: string[], roles: any) {
  // If the user has at least of the required roles, return true
  return requiredRoles.some(role => roles.includes(role))
}

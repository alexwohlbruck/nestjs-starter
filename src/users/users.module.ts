import { Module } from '@nestjs/common'
import { UsersService } from './users.service'
import { UsersController } from './users.controller'
import { PrismaService } from '../prisma/prisma.service'
import { NotifierService } from '../notifier/notifier.service'

@Module({
  providers: [UsersService, PrismaService, NotifierService],
  exports: [UsersService],
  controllers: [UsersController],
})
export class UsersModule {}

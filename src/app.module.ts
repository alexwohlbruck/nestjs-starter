import * as Joi from 'joi'
import { Module } from '@nestjs/common'
import { ConfigModule } from '@nestjs/config'
import { AppController } from './app.controller'
import { AppService } from './app.service'
import { AuthModule } from './auth/auth.module'
import { UsersModule } from './users/users.module'
import { PrismaService } from './prisma/prisma.service';
import { PostsService } from './posts/posts.service';
import { PostsController } from './posts/posts.controller';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validationSchema: Joi.object({
        NODE_ENV: Joi.string()
          .valid('development', 'production', 'test', 'prod')
          .default('development'),
        PORT: Joi.number().default(3000),
        JWT_SECRET: Joi.string().default('secret'),
        JWT_LIFETIME: Joi.number().default(1000 * 60 * 60 * 24 * 7),
        COOKIE_SECRET: Joi.string().default('secret'),
      }),
    }),
    AuthModule,
    UsersModule,
  ],
  controllers: [AppController, PostsController],
  providers: [AppService, PrismaService, PostsService],
})
export class AppModule {}

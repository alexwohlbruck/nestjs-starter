import * as Joi from 'joi'
import { Module } from '@nestjs/common'
import { ConfigModule } from '@nestjs/config'
import { AppController } from './app.controller'
import { AppService } from './app.service'
import { AuthModule } from './auth/auth.module'
import { UsersModule } from './users/users.module'
import { PrismaService } from './prisma/prisma.service'
import { NotifierService } from './notifier/notifier.service'
import { NotifierModule } from './notifier/notifier.module'

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validationSchema: Joi.object({
        NODE_ENV: Joi.string()
          .valid('development', 'production', 'test', 'prod')
          .default('development'),
        PORT: Joi.number().default(3000),
        DATABSE_URL: Joi.string(),
        JWT_SECRET: Joi.string().default('secret'),
        JWT_LIFETIME: Joi.number().default(1000 * 60 * 60 * 24 * 7),
        COOKIE_SECRET: Joi.string().default('secret'),

        MAIL_HOST: Joi.string().required(),
        MAIL_PORT: Joi.number().default(465),
        MAIL_SECURE: Joi.boolean().default(true),
        MAIL_USERNAME: Joi.string().required(),
        MAIL_PASSWORD: Joi.string().required(),
        MAIL_FROM: Joi.string().required(),

        TWILIO_ACCOUNT_SID: Joi.string().required(),
        TWILIO_AUTH_TOKEN: Joi.string().required(),
        TWILIO_PHONE_NUMBER: Joi.string().required(),
      }),
    }),
    AuthModule,
    UsersModule,
    NotifierModule,
  ],
  controllers: [AppController],
  providers: [AppService, PrismaService, NotifierService],
})
export class AppModule {}

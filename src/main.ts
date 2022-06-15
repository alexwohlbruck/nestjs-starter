import { NestFactory } from '@nestjs/core'
import { ConfigService } from '@nestjs/config'
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify'
import fastifyCookie from 'fastify-cookie'
import { AppModule } from './app.module'
import { PrismaService } from './prisma/prisma.service'
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger'

async function bootstrap() {
  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter(),
  )

  const prismaService = app.get(PrismaService)
  const configService = app.get(ConfigService)

  const PORT = configService.get<number>('PORT')
  const cookieSecret = configService.get<string>('COOKIE_SECRET')

  await prismaService.enableShutdownHooks(app)
  await bootstrapSwagger(app)
  await app.register(fastifyCookie, {
    secret: cookieSecret,
  })
  await app.listen(PORT)
}
bootstrap()

async function bootstrapSwagger(app: NestFastifyApplication) {
  const swaggerConfig = new DocumentBuilder()
    .setTitle('API docs')
    .setDescription('Automatically generated documentation for the API')
    .setVersion('1.0')
    .build()
  const document = SwaggerModule.createDocument(app, swaggerConfig)
  SwaggerModule.setup('api', app, document)
}

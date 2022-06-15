import { NestFactory } from '@nestjs/core'
import { ConfigService } from '@nestjs/config'
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify'
import fastifyCookie from 'fastify-cookie'
import { AppModule } from './app.module'
import { PrismaService } from './prisma/prisma.service'

async function bootstrap() {
  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter(),
  )
  const configService = app.get(ConfigService)
  console.log(configService.get('DATABASE_URL'))
  const prismaService = app.get(PrismaService)

  await prismaService.enableShutdownHooks(app)

  const PORT = configService.get<number>('PORT')

  await app.register(fastifyCookie, {
    secret: configService.get<string>('COOKIE_SECRET'),
  })

  await app.listen(PORT)
}
bootstrap()

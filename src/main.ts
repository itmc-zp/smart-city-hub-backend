import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import * as cookieParser from 'cookie-parser';
import * as session from 'express-session';
import * as path from 'path';
import { AppModule } from './app.module';
import logger from './utils/logger';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  const configService = app.get(ConfigService);
  
  const appPort = configService.get<number>('APP_PORT', 4200); 
  const corsOrigin = configService.get<string>('APP_ORIGIN', 'http://localhost:3000');
  app.use(cookieParser());
  app.set('trust proxy', 1);
  app.use(session({
    secret: process.env.SESSION_SECRET || 'nastya',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: true,
      sameSite: 'lax',
      httpOnly: true, 
    },
  }));
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true
    })
  )
  app.enableCors({
    origin: [corsOrigin],
    credentials: true,
    exposedHeaders: 'set-cookie',
  });
  app.setGlobalPrefix('api');
  app.useLogger(logger);

  const config = new DocumentBuilder()
  .setTitle('API авторизації')
  .setDescription('Документація до ендпоінтів аутентифікації та авторизації')
  .setVersion('1.0')
  .addBearerAuth(
    {
      type: 'http',
      scheme: 'bearer',
      bearerFormat: 'JWT',
      name: 'JWT',
      description: 'Введіть access token',
      in: 'header',
    },
    'JWT-auth', 
  )
  .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('docs', app, document);

  const clientBuildPath = path.join(__dirname, '..', 'client');

  app.useStaticAssets(clientBuildPath, { index: false });
   app.useStaticAssets(path.join(clientBuildPath, 'static'), { prefix: '/static' });

  app.setBaseViewsDir(clientBuildPath);
  app.setViewEngine('html');

  app.use('/env.js', (req, res) => {
    res.setHeader('Content-Type', 'application/javascript');
    res.send(`
      window.__ENV__ = {
        REACT_APP_GA_ID: "${process.env.REACT_APP_GA_ID}",
        REACT_APP_TURNSTILE_SITEKEY: "${process.env.REACT_APP_TURNSTILE_SITEKEY}"
      };
    `);
  });
  
   
    app.use((req, res, next) => {
      if (req.path.startsWith('/api') || req.path === '/env.js') {
        return next();
      }
      res.sendFile(path.join(clientBuildPath, 'index.html'));
    });
  
    await app.listen(appPort);
}
  
bootstrap();

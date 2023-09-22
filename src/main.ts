import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { readFileSync } from 'fs';

async function bootstrap() {
  const httpsOptions = {
    key: readFileSync('./certs/localhost-key.pem'),
    cert: readFileSync('./certs/localhost.pem'),
  };
  const app = await NestFactory.create(AppModule, { httpsOptions });
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
    }),
  );
  await app.listen(8000);
}
bootstrap();

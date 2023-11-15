import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { readFileSync } from 'fs';
import helmet from 'helmet';

async function bootstrap() {
  const httpsOptions = {
    key: readFileSync('./certs/server.key'),
    cert: readFileSync('./certs/server.cert'),
  };
  const app = await NestFactory.create(AppModule, { httpsOptions });
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
    }),
  );
  app.use(helmet());
  await app.listen(8000);
}
bootstrap();

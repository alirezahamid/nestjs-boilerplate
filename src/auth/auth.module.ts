import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './strategy';
import { NotificationService } from 'src/notification/notification.service';

/**
 * Represents the authentication module of the application.
 * @module AuthModule
 * @requires JwtModule
 * @controllers AuthController
 * @providers AuthService, JwtStrategy, NotificationService
 */
@Module({
  imports: [JwtModule.register({})],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy, NotificationService],
})
export class AuthModule {}

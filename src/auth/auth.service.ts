import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { v4 as uuidv4 } from 'uuid'; // UUID for generating a unique token

import { AuthDto, ChangePasswordDto, ResetPasswordDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { RedisService } from 'src/redis/redis.service';
import { JwtPayload, Tokens } from './types';
import { NotificationService } from 'src/notification/notification.service';

@Injectable({})
export class AuthService {
  constructor(
    private config: ConfigService,
    private prisma: PrismaService,
    private jwtService: JwtService,
    private redisService: RedisService,
    private notificationService: NotificationService,
  ) {}

  /*****
   * Registers a new user with the provided authentication data and returns the generated tokens.
   * @param {AuthDto} dto - The authentication data for the new user.
   * @returns {Promise<Tokens>} - A promise that resolves to the generated tokens.
   * @throws {ForbiddenException} - If the provided credentials are incorrect.
   *****/
  async register(dto: AuthDto): Promise<{ message: string }> {
    const password = await argon.hash(dto.password);

    await this.prisma.user
      .create({
        data: {
          email: dto.email,
          password,
        },
      })
      .catch((error) => {
        if (error instanceof PrismaClientKnownRequestError) {
          if (error.code === 'P2002') {
            throw new ForbiddenException('Credentials incorrect');
          }
        }
        throw error;
      });

    // Send verification email
    await this.sendVerificationEmail(dto.email);

    // Return a response (could be tokens, confirmation message, etc.)
    return {
      message:
        'Registration successful. Please check your email to verify your account.',
    };
  }

  /*****
   * Logs in a user with the provided authentication data and returns the generated tokens.
   * @param {AuthDto} dto - The authentication data object containing the user's email and password.
   * @returns {Promise<Tokens>} - A promise that resolves to the generated tokens.
   * @throws {ForbiddenException} - If the user does not exist or the password does not match.
   *****/
  async login(dto: AuthDto): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    if (!user.verified) {
      throw new ForbiddenException('Please verify your email first');
    }
    if (!user) throw new ForbiddenException('Access Denied');

    const passwordMatches = await argon.verify(user.password, dto.password);
    if (!passwordMatches) throw new ForbiddenException('Access Denied');

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRefreshTokenHash(user.id, tokens.refresh_token);

    return tokens;
  }

  /*****
   * Updates the hash of the refresh token for a specific user in Redis.
   * @param {number} userId - The ID of the user.
   * @param {string} refreshToken - The refresh token to update.
   * @returns {Promise<void>} - A promise that resolves when the update is complete.
   *****/
  async updateRefreshTokenHash(
    userId: number,
    refreshToken: string,
  ): Promise<void> {
    const client = this.redisService.getClient();
    const refreshTokenHash = await argon.hash(refreshToken);
    await client.set(
      `refresh_token_${userId}`,
      refreshTokenHash,
      'EX',
      7 * 24 * 60 * 60,
    ); // Expires in 7 days
  }

  /**
   * Retrieves the access token and refresh token for the given user.
   * @param {number} userId - The ID of the user.
   * @param {string} email - The email of the user.
   * @returns {Promise<Tokens>} - A promise that resolves to an object containing the access token and refresh token.
   */
  async getTokens(userId: number, email: string): Promise<Tokens> {
    const jwtPayload: JwtPayload = {
      sub: userId,
      email: email,
    };

    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(jwtPayload, {
        secret: this.config.get<string>('JWT_SECRET_ACCESS_KEY'),
        expiresIn: '15m',
      }),
      this.jwtService.signAsync(jwtPayload, {
        secret: this.config.get<string>('JWT_SECRET_REFRESH_KEY'),
        expiresIn: '7d',
      }),
    ]);

    return {
      id: userId,
      access_token: at,
      refresh_token: rt,
    };
  }

  /**
   * Refreshes the access token for a user using their refresh token.
   * @param {number} userId - The ID of the user.
   * @param {string} refreshToken - The refresh token of the user.
   * @returns {Promise<Object>} - An object containing the new access token and refresh token.
   * @throws {ForbiddenException} - If the stored refresh token does not match the provided refresh token.
   */
  async refresh(userId: string, refreshToken: string) {
    const client = this.redisService.getClient();
    const storedToken = await client.get(`refresh_token_${userId}`);
    const user = await this.prisma.user.findUnique({
      where: {
        id: parseInt(userId),
      },
    });
    if (!storedToken) throw new ForbiddenException('Access Denied');

    const refreshTokenMatches = await argon.verify(storedToken, refreshToken);
    if (!refreshTokenMatches) throw new ForbiddenException('Access Denied');

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRefreshTokenHash(user.id, tokens.refresh_token);

    return tokens;
  }

  /**
   * Sends a password reset email to the user with the provided email address.
   * @param {string} email - The email address of the user requesting the password reset.
   * @returns {Promise<void>} - A promise that resolves when the email has been sent.
   * @throws {NotFoundException} - If the user with the provided email address is not found.
   */
  async forgotPassword(email: string): Promise<void> {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const resetToken = uuidv4();
    const client = this.redisService.getClient();

    await client.set(`reset_token_${user.id}`, resetToken, 'EX', 60 * 60);

    const resetUrl = `https://yourapp.com/reset-password?token=${resetToken}`;
    const emailContent = `Please click on the following link to reset your password: ${resetUrl}`;

    await this.notificationService.sendEmail(
      user.email,
      'Password Reset',
      emailContent,
    );
  }

  /**
   * Resets the password for a user using the provided reset password DTO.
   * @param {ResetPasswordDto} dto - The DTO containing the necessary information for password reset.
   * @returns {Promise<void>} - A promise that resolves when the password has been successfully reset.
   * @throws {BadRequestException} - If the reset token is invalid or expired.
   */
  async resetPassword(dto: ResetPasswordDto): Promise<void> {
    const client = this.redisService.getClient();
    const resetToken = await client.get(`reset_token_${dto.userId}`);

    if (!resetToken || resetToken !== dto.token) {
      throw new BadRequestException('Invalid or expired reset token');
    }

    const hashedPassword = await argon.hash(dto.newPassword);

    await this.prisma.user.update({
      where: { id: dto.userId },
      data: {
        password: hashedPassword,
      },
    });

    await client.del(`reset_token_${dto.userId}`);
  }

  /**
   * Changes the password for a user.
   * @param {number} userId - The ID of the user.
   * @param {ChangePasswordDto} changePasswordDto - The DTO containing the current and new passwords.
   * @returns {Promise<{ message: string }>} - A promise that resolves to an object with a message indicating the success of the password change.
   * @throws {NotFoundException} - If the user with the given ID is not found.
   * @throws {ForbiddenException} - If the current password provided is incorrect.
   */
  async changePassword(
    userId: number,
    changePasswordDto: ChangePasswordDto,
  ): Promise<{ message: string }> {
    const { currentPassword, newPassword } = changePasswordDto;

    const user = await this.prisma.user.findUnique({ where: { id: userId } });

    if (!user) throw new NotFoundException('User not found');

    const passwordValid = await argon.verify(user.password, currentPassword);

    if (!passwordValid)
      throw new ForbiddenException('Current password is incorrect');

    const hashedNewPassword = await argon.hash(newPassword);

    await this.prisma.user.update({
      where: { id: userId },
      data: { password: hashedNewPassword },
    });

    return { message: 'Password successfully changed' };
  }

  private async sendVerificationEmail(email: string): Promise<void> {
    const verificationToken = uuidv4();
    const client = this.redisService.getClient();

    // Store the verification token in Redis with a 24-hour expiry
    await client.set(
      `email_verification_token_${verificationToken}`,
      email,
      'EX',
      24 * 60 * 60,
    );

    const verificationUrl = `https://yourapp.com/verify-email?token=${verificationToken}`;
    await this.notificationService.sendEmail(
      email,
      'Email Verification',
      `Please click on this link to verify your email: ${verificationUrl}`,
    );
  }

  async verifyEmail(token: string): Promise<{ message: string }> {
    const client = this.redisService.getClient();
    const email = await client.get(`email_verification_token_${token}`);

    if (!email) {
      throw new BadRequestException('Invalid or expired verification token');
    }

    // Find the user by email and update the emailVerified status
    await this.prisma.user.update({
      where: { email },
      data: {
        verified: true,
      },
    });

    // Clear the verification token from Redis
    await client.del(`email_verification_token_${token}`);

    // Return a success message or redirect the user
    return {
      message: 'Email verified successfully.',
    };
  }

  async resendVerificationEmail(email: string): Promise<any> {
    // Check if the user exists and email is not verified
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      throw new NotFoundException('User not found');
    }
    if (user.verified) {
      throw new BadRequestException('Email is already verified');
    }

    // Send verification email
    await this.sendVerificationEmail(email);

    return { message: 'Verification email resent. Please check your inbox.' };
  }

  twoFactorAuthEnable() {
    return '2 Factor Auth enable';
  }

  twoFactorAuthDisable() {
    return '2 Factor Auth disable';
  }

  twoFactorLogin() {
    return '2 Factor Login';
  }

  /**
   * Logs out a user by deleting their refresh token from the Redis cache.
   * @param {number} userId - The ID of the user to log out.
   * @returns {Promise<{ message: string }>} - A promise that resolves to an object with a success message.
   * @throws {NotFoundException} - If the refresh token is not found for the provided user ID.
   * @throws {InternalServerErrorException} - If an error occurs while logging out.
   */
  async logout(userId: number) {
    try {
      const tokenKey = `refresh_token_${userId}`;
      const refreshToken = await this.redisService.getClient().get(tokenKey);

      if (!refreshToken) {
        throw new NotFoundException(
          'Refresh token not found for the provided user ID',
        );
      }

      await this.redisService.getClient().del(tokenKey);

      return { message: 'Logged out successfully' };
    } catch (error) {
      if (error instanceof URIError) {
        throw new InternalServerErrorException(
          'An error occurred while logging out. Please try again.',
        );
      }
      throw error;
    }
  }
}

import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { RedisService } from 'src/redis/redis.service';
import { JwtPayload, Tokens } from './types';

@Injectable({})
export class AuthService {
  constructor(
    private config: ConfigService,
    private prisma: PrismaService,
    private jwtService: JwtService,
    private redisService: RedisService,
  ) {}

  async register(dto: AuthDto): Promise<Tokens> {
    const password = await argon.hash(dto.password);

    const user = await this.prisma.user
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

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRefreshTokenHash(user.id, tokens.refresh_token);

    return tokens;
  }

  async login(dto: AuthDto): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    if (!user) throw new ForbiddenException('Access Denied');

    const passwordMatches = await argon.verify(user.password, dto.password);
    if (!passwordMatches) throw new ForbiddenException('Access Denied');

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRefreshTokenHash(user.id, tokens.refresh_token);

    return tokens;
  }

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
      access_token: at,
      refresh_token: rt,
    };
  }
  async refresh(userId: number, refreshToken: string) {
    console.log('refresh: ', userId);
    const client = this.redisService.getClient();
    const storedToken = await client.get(`refresh_token_${userId}`);
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    });
    if (!storedToken) throw new ForbiddenException('Access Denied');

    const refreshTokenMatches = await argon.verify(storedToken, refreshToken);
    if (!refreshTokenMatches) throw new ForbiddenException('Access Denied');

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRefreshTokenHash(user.id, tokens.refresh_token);

    return tokens;
  }

  forgotPassword() {
    return 'Forgot Password';
  }

  changePassword() {
    return 'Change Password';
  }

  verifyEmail() {
    return 'Verify Email';
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

  async logout(userId: number) {
    await this.redisService.getClient().del(`refresh_token_${userId}`);
    return { message: 'Logged out' };
  }
}

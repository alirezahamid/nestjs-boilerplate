import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { GetUser, Public } from './decorator';
import { JwtGuard } from './guard';
import { Tokens } from './types';
import { AuthGuard } from '@nestjs/passport';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  register(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.register(dto);
  }

  @HttpCode(HttpStatus.OK)
  @Post('login')
  login(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.login(dto);
  }

  @Public()
  @UseGuards(JwtGuard)
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(
    @GetUser('id') userId: number,
    @Body('refreshToken') refreshToken: string,
  ) {
    return this.authService.refresh(userId, refreshToken);
  }

  @Post('forgot-password')
  forgotPassword() {
    return this.authService.forgotPassword();
  }

  @Post('change-password')
  changePassword() {
    return this.authService.changePassword();
  }

  @Post('verify-email')
  verifyEmail() {
    return this.authService.verifyEmail();
  }

  @Post('2fa/enable')
  twoFactorAuthEnable() {
    return this.authService.twoFactorAuthEnable();
  }

  @Post('2fa/disable')
  twoFactorAuthDisable() {
    return this.authService.twoFactorAuthDisable();
  }

  @Post('2fa/login')
  twoFactorLogin() {
    return this.authService.twoFactorLogin();
  }

  @UseGuards(JwtGuard)
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  logout(@GetUser('id') userId: number) {
    return this.authService.logout(userId);
  }

  @Get('slack')
  @UseGuards(AuthGuard('slack'))
  async slackAuth() {}

  @Get('slack/callback')
  @UseGuards(AuthGuard('slack'))
  async slackAuthRedirect(@Req() req) {
    const slackUser = req.user;
    const user = await this.authService.findOrCreateUserFromSlack(slackUser);
    const tokens = await this.authService.getTokens(user.id, user.email);
    return tokens;
  }
}

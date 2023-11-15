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
import { AuthDto, ChangePasswordDto } from './dto';
import { GetUser, Public } from './decorator';
import { JwtGuard } from './guard';
import { Tokens } from './types';
import { AuthGuard } from '@nestjs/passport';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  /**
   * Registers a new user by creating an account with the provided authentication data.
   * @param {AuthDto} dto - The authentication data for the new user.
   * @returns {Promise<Tokens>} - A promise that resolves to the generated tokens for the new user.
   */
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  register(@Body() dto: AuthDto): Promise<{ message: string }> {
    return this.authService.register(dto);
  }

  /**
   * Handles the login request and returns the tokens for the authenticated user.
   * @param {AuthDto} dto - The authentication data transfer object containing the user credentials.
   * @returns {Promise<Tokens>} - A promise that resolves to the tokens for the authenticated user.
   */
  @HttpCode(HttpStatus.OK)
  @Post('login')
  login(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.login(dto);
  }

  /**
   * Refreshes the authentication token for the user.
   * @param {number} userId - The ID of the user.
   * @param {string} refreshToken - The refresh token provided by the user.
   * @returns The refreshed authentication token.
   */
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

  /**
   * Handles the 'forgot-password' POST request and initiates the password reset process for the given email.
   * @param {string} email - The email address of the user requesting password reset.
   * @returns The result of the password reset process.
   */
  @Post('forgot-password')
  forgotPassword(@Body('email') email: string) {
    return this.authService.forgotPassword(email);
  }

  /**
   * Endpoint for changing the password of a user.
   * @param {number} userId - The ID of the user whose password is being changed.
   * @param {ChangePasswordDto} passwords - The new and old passwords provided by the user.
   * @returns The result of the password change operation.
   */
  @UseGuards(JwtGuard)
  @Post('change-password')
  changePassword(
    @GetUser('id') userId: number,
    @Body() passwords: ChangePasswordDto,
  ) {
    return this.authService.changePassword(userId, passwords);
  }

  /**
   * Endpoint for verifying user email.
   * @param {string} token - The verification token sent to the user's email.
   * @returns The result of the email verification process.
   */
  @Post('verify-email')
  async verifyEmail(@Body('token') token: string) {
    return this.authService.verifyEmail(token);
  }

  /**
   * Resends a verification email to the specified email address.
   * @param {string} email - The email address to send the verification email to.
   * @returns A Promise that resolves to the result of the resend operation.
   */
  @Post('resend-verification-email')
  async resendVerificationEmail(@Body('email') email: string) {
    return this.authService.resendVerificationEmail(email);
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

  /**
   * Logout endpoint that requires JWT authentication.
   * @param {number} userId - The ID of the user to logout.
   * @returns The result of the logout operation.
   */
  @UseGuards(JwtGuard)
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  logout(@GetUser('id') userId: number) {
    return this.authService.logout(userId);
  }

  @Get('slack')
  @UseGuards(AuthGuard('slack'))
  async slackAuth() {}

  /**
   * Handles the callback route for Slack authentication.
   * @param {Object} req - The request object.
   * @returns {Promise<Object>} - The tokens for the authenticated user.
   */
  @Get('slack/callback')
  @UseGuards(AuthGuard('slack'))
  async slackAuthRedirect(@Req() req) {
    const slackUser = req.user;
    const user = await this.authService.findOrCreateUserFromSlack(slackUser);
    const tokens = await this.authService.getTokens(user.id, user.email);
    return tokens;
  }
}

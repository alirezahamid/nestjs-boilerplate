import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-slack-oauth2';

@Injectable()
export class SlackStrategy extends PassportStrategy(Strategy, 'slack') {
  constructor(configService: ConfigService) {
    super({
      clientID: configService.get<string>('SLACK_CLEINT_ID'),
      clientSecret: configService.get<string>('SLACK_SECRET_KEY'),
      callbackURL: configService.get<string>('SLACK_CALLBACK_URL'),
      scope: ['identity.basic', 'identity.email'], // Adjust based on what you need.
    });
  }

  async validate(accessToken: string, refreshToken: string, profile: any) {
    // Here you can align the Slack user information with your application's user record.
    // You can save or update the user in your DB and return the user info.
    const { id, displayName, user } = profile;
    console.log(profile);
    console.log('access_token', accessToken);
    console.log('refresh_token', refreshToken);
    return {
      slackId: id,
      username: displayName,
      email: user.email,
    };
  }
}

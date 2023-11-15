import { JwtPayload } from './jwtPayload.type';

export type JwtPayloadWithRefresh = JwtPayload & { refreshToken: string };

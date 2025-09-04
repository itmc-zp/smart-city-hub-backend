import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import axios from 'axios';
import * as fs from 'node:fs';
import * as path from 'path';
import { getUtilsPath, loadCertBase64 } from 'src/utils/diia.helpers';
import { TypeBaseProviderOptions } from './types/base-provider.options.types';
import { TypeUserInfo } from './types/user-info.types';


@Injectable()
export class BaseOAuthService {
  private BASE_URL: string;

  private readonly eusign: any = ((): any => {
    const mod = require(
      path.join(__dirname, '..', '..', '..', 'eusign', 'eusign.js'),
    );
    return mod?.default ?? mod;
  })();

  public constructor(private readonly options: TypeBaseProviderOptions) {}

  protected async extractUserInfo(data: any): Promise<TypeUserInfo> {
    return {
      ...data,
      provider: this.options.name,
    };
  }

  public getAuthUrl(session: Record<string, any> | null, state?: string) {
    if (session && state) {
      session.oauth_state = state;
      const redirectUri = this.getRedirecUrl();
      session.oauth_redirect_uri = redirectUri;
    }

    const redirectUri = this.getRedirecUrl();

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.options.client_id,
      redirect_uri: redirectUri,
    });

    if (state) params.set('state', state);

    switch ((this.options.name || '').toLowerCase()) {
      case 'google': {
        const scope = this.options.scopes?.length
          ? this.options.scopes.join(' ')
          : 'openid email profile';
        params.set('scope', scope);
        params.set('prompt', 'consent');
        params.set('access_type', 'offline');
        params.set('include_granted_scopes', 'true'); 
        break;
      }

      default:
        if (this.options.scopes?.length) {
          params.set('scope', this.options.scopes.join(' '));
        }
    }

    return `${this.options.authorize_url}?${params.toString()}`;
  }

  public async findUserByCode(code: string): Promise<TypeUserInfo> {
    switch ((this.options.name || '').toLowerCase()) {
      case 'diia':
        return this.findDiiaUserByCode(code);
      case 'google':
        return this.findGoogleUserByCode(code);
      default:
        throw new BadRequestException(
          `Provider '${this.options.name}' is not supported.`,
        );
    }
  }

  public async findDiiaUserByCode(code: string) {
    const tokenUrl = 'https://test.id.gov.ua/get-access-token';
    const profileUrl = 'https://test.id.gov.ua/get-user-info';
    const redirect_uri =
      'https://digital-test.zp.gov.ua/api/auth/oauth/callback/diia';

    // 1. Получаем токен
    const tokenResp = await axios.get(tokenUrl, {
      params: {
        grant_type: 'authorization_code',
        client_id: '7d5879ee3ddb5a3aa619bbc80d01ab71',
        client_secret: '3133737033a24c44f6c3810b7b35ef6a251911bd',
        code,
        redirect_uri: redirect_uri.trim(),
      },
      headers: {
        'User-Agent': 'curl/8.5.0',
        'Accept-Encoding': 'identity',
      },
      timeout: 15000,
      validateStatus: () => true,
    });

    if (tokenResp.status !== 200 || !tokenResp.data?.access_token) {
      throw new UnauthorizedException(
        `Не вдалося отримати токен з ${tokenUrl}. Відповідь: ${tokenResp.status} ${JSON.stringify(tokenResp.data)}`,
      );
    }

    const access_token = tokenResp.data.access_token;
    // 2. Читаем сертификат Дії (.cer) и переводим в Base64

    const certPath = getUtilsPath('test-2108.cer');
    const certBase64 = loadCertBase64(certPath);

    fs.accessSync(certPath, fs.constants.R_OK);

    const params = new URLSearchParams({
      access_token: access_token, // з кроку обміну коду на токен
      user_id: String(tokenResp.data.user_id ?? ''), // якщо потрібно
      fields:
        'issuer,issuercn,serial,subject,subjectcn,locality,state,o,ou,title,surname,givenname,email,address,phone,dns,edrpoucode,drfocode,documents',
      cert: certBase64, // DER→Base64
    });

    const userResp = await axios.post(profileUrl, params, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
        Authorization: `Bearer ${access_token}`,
      },
      timeout: 15000,
      validateStatus: () => true,
    });

    if (userResp.status !== 200 || !userResp.data?.encryptedUserInfo) {
      throw new UnauthorizedException(
        `Не вдалося отримати користувача з ${profileUrl}. Відповідь: ${userResp.status} ${JSON.stringify(userResp.data)}`,
      );
    }

    const decryptedInfo = await this.eusign.developData(
      Buffer.from(userResp.data.encryptedUserInfo, 'base64'),
    );

    const id =
      tokenResp.data.user_id ??
      (decryptedInfo.drfocode && String(decryptedInfo.drfocode).trim()) ??
      (decryptedInfo.serial && String(decryptedInfo.serial).trim()) ??
      null;

    const email =
      decryptedInfo.email && decryptedInfo.email.toLowerCase() !== 'n/a'
        ? decryptedInfo.email
        : null;

    const name = (decryptedInfo.subjectcn ?? '').trim();

    const now = Date.now();
    const expiresIn = tokenResp.data.expires_in ?? null; // сек
    const expiresAt = expiresIn
      ? Math.floor((now + expiresIn * 1000) / 1000) // UNIX seconds
      : (tokenResp.data.expires_at ?? null);

    const profile = {
      id,
      email,
      name,
      picture: null,
      provider: 'diia',
      raw: decryptedInfo, 
      access_token,
      refresh_token: tokenResp.data.refresh_token ?? null,
      expires_at: expiresAt,
    };

    return {
      id,
      email,
      name,
      picture: null,
      provider: 'diia',
      raw: decryptedInfo, 
      access_token,
      refresh_token: tokenResp.data.refresh_token ?? null,
      expires_at: tokenResp.data.expires_at ?? null,
    };
  }

  public async findGoogleUserByCode(code: string): Promise<TypeUserInfo> {
    const client_id = this.options.client_id;
    const client_secret = this.options.client_secret;

    const tokenQuery = new URLSearchParams({
      client_id,
      client_secret,
      code,
      redirect_uri: this.getRedirecUrl(),
      grant_type: 'authorization_code',
    });

    const tokenRequest = await fetch(this.options.access_url, {
      method: 'POST',
      body: tokenQuery,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
    });

    if (!tokenRequest.ok) {
      throw new BadRequestException(
        `Не вдалося отримати користувача з ${this.options.profile_url}.`,
      );
    }

    const tokens = await tokenRequest.json();
    if (!tokens.access_token) {
      throw new BadRequestException(
        `Відповідь з ${this.options.access_url} не містить access_token.`,
      );
    }

    const userRequest = await fetch(this.options.profile_url, {
      headers: {
        Authorization: `Bearer ${tokens.access_token}`,
      },
    });

    if (!userRequest.ok) {
      throw new UnauthorizedException(
        `Не вдалося отримати користувача з ${this.options.profile_url}. Перевірте правильність access_token.`,
      );
    }

    const user = await userRequest.json();
    const userData = await this.extractUserInfo(user);

    return {
      ...userData,
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      expires_at: tokens.expires_at ?? null,
      provider: this.options.name,
    };
  }

  public getRedirecUrl() {
    return `${this.BASE_URL}/api/auth/oauth/callback/${this.options.name}`;
  }

  public async refreshAccessToken(
    refreshToken: string,
  ): Promise<{ access_token: string; refresh_token?: string }> {
    const tokenQuery = new URLSearchParams({
      client_id: this.options.client_id,
      client_secret: this.options.client_secret,
      refresh_token: refreshToken,
      grant_type: 'refresh_token',
    });

    const tokenRequest = await fetch(this.options.access_url, {
      method: 'POST',
      body: tokenQuery,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
    });

    if (!tokenRequest.ok) {
      throw new BadRequestException('Не вдалося оновити access token');
    }

    const tokens = await tokenRequest.json();

    if (!tokens.access_token) {
      throw new BadRequestException('Відповідь не містить access_token');
    }

    return {
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
    };
  }

  set baseUrl(value: string) {
    this.BASE_URL = value;
  }

  get name() {
    return this.options.name;
  }

  get access_url() {
    return this.options.access_url;
  }

  get profile_url() {
    return this.options.profile_url;
  }

  get scopes() {
    return this.options.scopes;
  }
}

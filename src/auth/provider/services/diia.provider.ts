import { Injectable } from '@nestjs/common';

import { BaseOAuthService } from './base-oauth.service';
import { TypeProviderOptions } from './types/provider-options.types';
import { TypeUserInfo } from './types/user-info.types';

@Injectable()
export class DiiaProvider extends BaseOAuthService {
  public constructor(options: TypeProviderOptions) {
    super({
      name: 'diia',
      authorize_url: 'https://test.id.gov.ua/', 
      access_url: 'https://test.id.gov.ua/get-access-token', 
      profile_url: 'https://test.id.gov.ua/get-user-info', 
      scopes:['offline'],
      cert: options.cert,
      client_id: options.client_id,
      client_secret: options.client_secret,
    }
  );
  }

  public async extractUserInfo(data: any): Promise<TypeUserInfo> {
    return super.extractUserInfo({
      id: data.user_id || data.sub || null,
      email: data.email,
      name: data.name || `${data.firstName || ''} ${data.lastName || ''}`.trim(),
      picture: null,
    });
  }
  
  
}

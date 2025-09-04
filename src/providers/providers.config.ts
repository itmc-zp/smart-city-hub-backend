import { ConfigService } from "@nestjs/config";
import axios from "axios";
import { TypeOptions } from "src/auth/provider/provider.constants";
import { DiiaProvider } from "src/auth/provider/services/diia.provider";
import { GoogleProvider } from "src/auth/provider/services/google.provider";


export async function getGoogleGender(accessToken: string) {
  const response = await axios.get(
    'https://people.googleapis.com/v1/people/me?personFields=genders',
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    },
  );
  return response.data.genders?.[0]?.value ?? 'unknown';
}

export const getProvidersConfig = async (
    configServise: ConfigService,                   
  ): Promise<TypeOptions> => ({
    baseUrl: configServise.getOrThrow<string>('APPLICATION_URL'),
    services: [
      new GoogleProvider({
        client_id:     configServise.getOrThrow<string>('GOOGLE_CLIENT_ID'),
        client_secret: configServise.getOrThrow<string>('GOOGLE_CLIENT_SECRET'),
        scopes: [
          'openid', 
          'email',
          'profile',
          'https://www.googleapis.com/auth/user.gender.read',
        ],
      }),
      new DiiaProvider(
        {
          client_id:     configServise.getOrThrow<string>('DIIA_CLIENT_ID'),
          client_secret: configServise.getOrThrow<string>('DIIA_CLIENT_SECRET'),
          cert:          configServise.getOrThrow<string>('DIIA_ENCRYPTION_CERT'),
          scopes: ['offline', 'email', 'name'],
        },                             
      ),
    ],
  });
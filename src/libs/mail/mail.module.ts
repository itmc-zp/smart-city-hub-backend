import { MailerModule } from "@nestjs-modules/mailer";
import { HandlebarsAdapter } from "@nestjs-modules/mailer/dist/adapters/handlebars.adapter";
import { Global, Module } from "@nestjs/common";
import { ConfigModule, ConfigService } from "@nestjs/config";
import { join } from 'path';
import { MailController } from "./mail.controller";
import { MailService } from "./mail.service";

@Global()
@Module({
  imports: [
    MailerModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => {
        const host = configService.get<string>('MAIL_HOST');
        const port = configService.get<number>('MAIL_PORT');
        return {
          transport: {
            host,
            port,
            secure: false,
            tls: {
              rejectUnauthorized: false,
            },
          },
          template: {
            dir: join(__dirname, '..', '..', 'templates'),
            adapter: new HandlebarsAdapter(),
            options: { strict: true },
          },
        };
      },
      inject: [ConfigService],
    }),
  ],
  controllers: [MailController],
  providers: [MailService],
  exports: [MailService],
})
export class MailModule {}


import {
  Body,
  Controller,
  Post,
  UploadedFiles,
  UseInterceptors,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { FilesInterceptor } from '@nestjs/platform-express';
import { ApiBody, ApiConsumes, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import axios from 'axios';
import {
  FeedbackFormDto,
  IndividualFormDto,
  LegalEntityFormDto,
} from './dto/mail.dto';
import { MailService } from './mail.service';

@ApiTags('Форми подачі')
  @Controller('submissions')
  export class MailController {
    constructor(
      private readonly mailService: MailService,
      private readonly configService: ConfigService,) {}
  
    @Post('individual')
    @UseInterceptors(FilesInterceptor('fileUpload', 3))
    @ApiOperation({ summary: 'Надіслати запит фізичної особи' })
    @ApiConsumes('multipart/form-data')
    @ApiBody({
      description: 'Дані форми фізичної особи з прикріпленими файлами',
      type: IndividualFormDto,
    })
    @ApiResponse({ status: 200, description: 'Лист успішно надіслано' })
    @ApiResponse({ status: 400, description: 'Помилка перевірки Captcha' })
    async sendIndividualFormEmail(
      @Body() formData: IndividualFormDto,
      @UploadedFiles() files: Express.Multer.File[],
    ) {
  
      const isCaptchaValid = await this.verifyCaptcha(formData.captchaToken);
      if (!isCaptchaValid) {
        return { statusCode: 400, message: 'Captcha verification failed' };
      }
  
      const attachments = this.mapFilesToAttachments(files);
  
      return this.mailService.sendMail(
        this.configService.get<string>('MAIL_TO_RECEPTION'),
        formData,
        'Запит на отримання відеозапису',
        'individuals-support',
        attachments,
        formData.email,
      );
    }
  
    @Post('legal-entity')
    @UseInterceptors(FilesInterceptor('fileUpload', 3))
    @ApiOperation({ summary: 'Надіслати запит від юридичної особи' })
    @ApiConsumes('multipart/form-data')
    @ApiBody({
      description: 'Дані форми юридичної особи з прикріпленими файлами',
      type: LegalEntityFormDto,
    })
    @ApiResponse({ status: 200, description: 'Лист успішно надіслано' })
    @ApiResponse({ status: 400, description: 'Помилка перевірки Captcha' })
    async sendLegalEntitiesFormEmail(
      @Body() formData: LegalEntityFormDto,
      @UploadedFiles() files: Express.Multer.File[],
    ) {
  
      const isCaptchaValid = await this.verifyCaptcha(formData.captchaToken);
      if (!isCaptchaValid) {
        return { statusCode: 400, message: 'Captcha verification failed' };
      }
  
      const attachments = this.mapFilesToAttachments(files);
  
      return this.mailService.sendMail(
        this.configService.get<string>('MAIL_TO_RECEPTION'),
        formData,
        'Запит на отримання відеозапису',
        'legal-entities-support',
        attachments,
        formData.email,
      );
    }
  
    @Post('feedback')
    @ApiOperation({ summary: 'Надіслати звернення (зворотній звʼязок)' })
    @ApiBody({
      description: 'Форма зворотного звʼязку',
      type: FeedbackFormDto,
    })
    @ApiResponse({ status: 200, description: 'Звернення успішно надіслано' })
    @ApiResponse({ status: 400, description: 'Помилка перевірки Captcha' })
    async sendOtherFormEmail(@Body() formData: FeedbackFormDto) {
  
     const isCaptchaValid = await this.verifyCaptcha(formData.captchaToken);
      if (!isCaptchaValid) {
        return { statusCode: 400, message: 'Captcha verification failed' };
      } 
      
      return this.mailService.sendMail(
      this.configService.get<string>('MAIL_TO_SUPROVID'),
        formData,
        'Запит на порталі "Цифрове Запоріжжя"',
        'support',
      );
    }
  
   
  
    private async verifyCaptcha(captchaToken: string): Promise<boolean> {
      const secretKey = process.env.TURNSTILE_SECRET_KEY;
      if (!secretKey) {
        console.error('TURNSTILE_SECRET_KEY is not defined');
        return false;
      }
      
      try {
        const params = new URLSearchParams();
        params.append('secret', secretKey);
        params.append('response', captchaToken);
    
        const response = await axios.post(
          'https://challenges.cloudflare.com/turnstile/v0/siteverify',
          params.toString(),
          {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          },
        ); 
        return response.data.success;
      } catch (error) {
        console.error('Captcha verification failed', error);
        return false;
      }
    }
    
    private mapFilesToAttachments(files: Express.Multer.File[]) {
      return files.map((file) => {
        const decodedFilename = Buffer.from(file.originalname, 'latin1').toString(
          'utf8',
        );
        return {
          filename: decodedFilename,
          content: file.buffer,
        };
      });
    }
  }
  
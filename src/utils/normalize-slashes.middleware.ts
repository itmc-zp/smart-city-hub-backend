import { Injectable, NestMiddleware } from '@nestjs/common';
import { NextFunction, Request, Response } from 'express';

@Injectable()
export class NormalizeSlashesMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    const originalUrl = req.originalUrl;
    
    // Зберігаємо префікс (наприклад, http:// або https://)
    const normalizedUrl = originalUrl.replace(/([^:]\/)\/+/g, '$1');

    if (normalizedUrl !== originalUrl) {
      // Запобігаємо циклічним редіректам
      return res.redirect(301, normalizedUrl);
    }

    next();
  }
}


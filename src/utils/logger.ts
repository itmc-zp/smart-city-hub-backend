import { createLogger, format, transports } from 'winston';
import * as fs from 'fs';
import * as path from 'path';

const logDir = path.join(process.cwd(), 'logs');

if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

const logger = createLogger({
  level: 'error',
  format: format.combine(
    format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    format.printf(({ timestamp, level, message, stack }) => {
      return `${timestamp} [${level.toUpperCase()}]: ${message} ${stack ? `\n${stack}` : ''}`;
    })
  ),
  transports: [
    new transports.File({ filename: path.join(logDir, 'error.log'), level: 'error' }),
    new transports.Console(),
  ],
});

export default logger;


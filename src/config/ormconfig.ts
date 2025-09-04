import { config } from 'dotenv';
import { join } from 'path';
import { DataSourceOptions } from 'typeorm';

config(); 

export const typeOrmConfig: DataSourceOptions = {
  type: 'oracle',
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT || '1521', 10),
  username: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  serviceName: process.env.DB_SERVICE_NAME,
  database: process.env.DB_NAME,
  entities: [join(__dirname, '..', 'entities', '*.entity.{ts,js}')],
  migrations: [join(__dirname, '..', 'migrations', '*.{ts,js}')],
  synchronize: false,
};

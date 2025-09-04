import { DataSource } from 'typeorm';
import { typeOrmConfig } from './config/ormconfig';

export const AppDataSource = new DataSource(typeOrmConfig);

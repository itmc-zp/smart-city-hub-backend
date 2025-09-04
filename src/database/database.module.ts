import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { typeOrmConfig } from 'src/config/ormconfig';

@Module({
    imports: [
        ConfigModule.forRoot(),
        TypeOrmModule.forRoot(typeOrmConfig),
      ],
})
export class DatabaseModule {}

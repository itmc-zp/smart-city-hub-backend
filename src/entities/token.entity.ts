import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
} from 'typeorm';
  
  export enum TokenType {
    VERIFICATION = 'VERIFICATION',
    TWO_FACTOR = 'TWO_FACTOR',
    PASSWORD_RESET = 'PASSWORD_RESET',
  }
  
  @Entity('TOKENS')
  export class Token {
    @PrimaryGeneratedColumn('uuid', { name: 'ID' })
    id: string;
  
    @Column({ name: 'EMAIL' })
    email: string;
  
    @Column({ name: 'TOKEN', unique: true })
    token: string;
  
    @Column({
      name: 'TYPE',
      type: 'varchar',
    })
    type: TokenType;
  
    @Column({ name: 'EXPIRES_IN', type: 'timestamp' })
    expiresIn: Date;
  
    @CreateDateColumn({ name: 'CREATED_AT', type: 'timestamp' })
    createdAt: Date;
  }
  
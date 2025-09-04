import {
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { User } from './user.entity';
  
  @Entity('ACCOUNTS')
  export class Account {
    @PrimaryGeneratedColumn('uuid', { name: 'ID' })
    id: string;
  
    @Column({ name: 'TYPE' })
    type: string;
  
    @Column({ name: 'PROVIDER' })
    provider: string;
  
    @Column({ name: 'REFRESH_TOKEN', nullable: true })
    refreshToken?: string;
  
    @Column({ name: 'ACCESS_TOKEN', nullable: true })
    accessToken?: string;
  
    @Column({ name: 'EXPIRES_AT', type: 'number', nullable: true })
    expiresAt?: number;

    @Column({ name: 'PROVIDER_ACCOUNT_ID' })
    providerAccountId: string;
  
    @CreateDateColumn({ name: 'CREATED_AT', type: 'timestamp' })
    createdAt: Date;
  
    @UpdateDateColumn({ name: 'UPDATED_AT', type: 'timestamp' })
    updatedAt: Date;
  
    @ManyToOne(() => User, user => user.accounts, { nullable: true })
    @JoinColumn({ name: 'USER_ID' }) 
    user: User;
  }
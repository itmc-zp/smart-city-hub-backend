import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  OneToMany,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
  ValueTransformer,
} from 'typeorm';
import { Account } from './account.entity';

export const BoolToNumber: ValueTransformer = {
  to: (value?: boolean | null) => (value ? 1 : 0),
  from: (value: any) => value === 1 || value === '1' || value === true,
};

  export enum DeviceType {
    DESKTOP = 'desktop',
    MOBILE = 'mobile',
  }
  
  export enum AuthMethod {
    CREDENTIALS = 'CREDENTIALS',
    GOOGLE = 'GOOGLE',
    DIIA = 'DIIA',
  }

  export enum TwoFactorType {
    NONE = 'NONE',
    EMAIL = 'EMAIL',
    APP = 'APP',
  }
  
  @Entity('USERS')
  export class User {
    @PrimaryGeneratedColumn('uuid', { name: 'ID' })
    id: string;
  
    @Column({ name: 'EMAIL', unique: true })
    email: string;
  
    @Column({ name: 'PASSWORD' })
    password: string;
  
    @Column({ name: 'DISPLAY_NAME' })
    displayName: string;
  
    @Column({ name: 'PICTURE', nullable: true })
    picture: string;
  
    @Column({ name: 'IS_VERIFIED', type: 'number', precision: 1, scale: 0, default: 0, transformer: BoolToNumber })
    isVerified: boolean;
  
    @Column({ name: 'IS_TWO_FACTOR_ENABLED', type: 'number', precision: 1, scale: 0, default: 0, transformer: BoolToNumber })
    isTwoFactorEnabled: boolean;
  
    @Column({ name: 'METHOD', type: 'varchar2', length: 32 })
    method: AuthMethod;
  
    @CreateDateColumn({ name: 'CREATED_AT' })
    createdAt: Date;
  
    @UpdateDateColumn({ name: 'UPDATED_AT' })
    updatedAt: Date;

    @Column({ name: 'REFRESH_TOKEN', type: 'varchar', nullable: true })
    refreshToken?: string;

    @Column({
      name: 'TWO_FA_TYPE',
      type: 'varchar',
      default: TwoFactorType.NONE,
    })
    twoFactorType: TwoFactorType;

    @Column({ name: 'TWO_FA_SECRET', type: 'varchar', nullable: true })
    twoFASecret?: string;

    @Column({
      name: 'DIIA_VERIFIED',
      type: 'number', precision: 1, scale: 0, default: 0, transformer: BoolToNumber,
    })
    diiaVerified: boolean;
  
    @Column({ name: 'DIIA_VERIFIED_AT', type: 'timestamp', nullable: true })
    diiaVerifiedAt: Date | null;
  
    @Index({ unique: true })
    @Column({ name: 'DIIA_STABLE_ID_HASH', type: 'varchar2', length: 128, nullable: true, select: false })
    diiaStableIdHash?: string | null;
  
    @Column({ name: 'DIIA_LAST_DOC_MASK', type: 'varchar2', length: 64, nullable: true })
    diiaLastDocMask?: string | null;
    
    @OneToMany(() => Account, (account) => account.user)
    accounts: Account[];

    @Column({ name: 'DEVICE_TYPE', type: 'varchar2', length: 16, default: 'desktop' })
    deviceType: string;

    @Column({ name: 'GENDER', type: 'varchar2', length: 16, default: 'unknown' })
    gender: string;
    
  }

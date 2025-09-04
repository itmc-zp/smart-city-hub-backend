import { ApiProperty } from '@nestjs/swagger';

export class AccountDto {
  @ApiProperty({ example: 'google', description: 'OAuth провайдер' })
  provider: string;

  @ApiProperty({ example: 'oauth', description: 'Тип акаунта' })
  type: string;

  @ApiProperty({ example: '1234567890', description: 'ID акаунта у провайдера' })
  providerAccountId: string;

  @ApiProperty({ example: '2024-06-01T10:00:00Z', description: 'Дата створення акаунту' })
  createdAt: Date;

  @ApiProperty({ example: '2024-07-01T10:00:00Z', description: 'Дата оновлення акаунту' })
  updatedAt: Date;
}

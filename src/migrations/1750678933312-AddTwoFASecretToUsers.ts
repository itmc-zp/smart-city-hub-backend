import { MigrationInterface, QueryRunner, TableColumn } from "typeorm";

export class AddTwoFASecretToUsers1750678933312 implements MigrationInterface {
    name = 'AddTwoFASecretToUsers1750678933312'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.addColumn('USERS', new TableColumn({
          name: 'TWO_FA_SECRET',
          type: 'varchar',
          isNullable: true,
        }));
      }
    
      public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.dropColumn('USERS', 'TWO_FA_SECRET');
      }

}

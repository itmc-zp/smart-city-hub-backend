import { MigrationInterface, QueryRunner, TableColumn } from "typeorm";

export class AddTwoFactorTypeToUser1750680693566 implements MigrationInterface {
    name = 'AddTwoFactorTypeToUser1750680693566'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.addColumn('USERS', new TableColumn({
          name: 'TWO_FA_TYPE',
          type: 'varchar',
          isNullable: false,
          default: `'NONE'`,
        }));
      }
    
      public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.dropColumn('USERS', 'TWO_FA_TYPE');
      }

}

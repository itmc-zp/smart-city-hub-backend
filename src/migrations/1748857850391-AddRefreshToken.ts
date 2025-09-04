import { MigrationInterface, QueryRunner } from "typeorm";

export class AddRefreshToken1748857850391 implements MigrationInterface {
    name = 'AddRefreshToken1748857850391'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`
            ALTER TABLE "USERS" ADD "REFRESH_TOKEN" varchar2(255)
          `);
          await queryRunner.query(`
            ALTER TABLE "ACCOUNTS" MODIFY "REFRESH_TOKEN" varchar2(255) NULL
          `);
          await queryRunner.query(`
            ALTER TABLE "ACCOUNTS" MODIFY "ACCESS_TOKEN" varchar2(255) NULL
          `);
          await queryRunner.query(`
            ALTER TABLE "ACCOUNTS" MODIFY "EXPIRES_AT" number NULL
          `);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`
            ALTER TABLE "ACCOUNTS" MODIFY "EXPIRES_AT" number NOT NULL
          `);
          await queryRunner.query(`
            ALTER TABLE "ACCOUNTS" MODIFY "ACCESS_TOKEN" varchar2(255) NOT NULL
          `);
          await queryRunner.query(`
            ALTER TABLE "ACCOUNTS" MODIFY "REFRESH_TOKEN" varchar2(255) NOT NULL
          `);
          await queryRunner.query(`
            ALTER TABLE "USERS" DROP COLUMN "REFRESH_TOKEN"
          `);
    }

}

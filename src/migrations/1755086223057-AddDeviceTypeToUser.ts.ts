import { MigrationInterface, QueryRunner } from "typeorm";

export class AddDeviceTypeToUser1755086223057 implements MigrationInterface {
    name = 'AddDeviceTypeToUser1755086223057'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`
            ALTER TABLE "USERS"
            ADD "DEVICE_TYPE" VARCHAR2(50) DEFAULT 'DESKTOP' NOT NULL
        `);

        await queryRunner.query(`
            ALTER TABLE "USERS"
            ADD CONSTRAINT "CHK_USERS_DEVICE_TYPE"
            CHECK ("DEVICE_TYPE" IN ('DESKTOP','MOBILE'))
        `);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`
            ALTER TABLE "USERS"
            DROP CONSTRAINT "CHK_USERS_DEVICE_TYPE"
        `);

        await queryRunner.query(`
            ALTER TABLE "USERS"
            DROP COLUMN "DEVICE_TYPE"
        `);
    }
}


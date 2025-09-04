import { MigrationInterface, QueryRunner } from 'typeorm';

export class UserEntityDiiaVerificationFix1756367932373 implements MigrationInterface {
  name = 'UserEntityDiiaVerificationFix1756367932373';

  public async up(queryRunner: QueryRunner): Promise<void> {
    try {
      await queryRunner.query(`ALTER TABLE "USERS" DROP CONSTRAINT "CHK_USERS_DEVICE_TYPE"`);
    } catch (_) {
    }

    await queryRunner.query(`UPDATE "USERS" SET "DEVICE_TYPE" = lower("DEVICE_TYPE") WHERE "DEVICE_TYPE" IS NOT NULL`);

    await queryRunner.query(`ALTER TABLE "USERS" MODIFY ("DEVICE_TYPE" DEFAULT 'desktop')`);
    await queryRunner.query(
      `ALTER TABLE "USERS" ADD CONSTRAINT "CHK_USERS_DEVICE_TYPE_LOWER" CHECK ("DEVICE_TYPE" IN ('desktop','mobile'))`
    );

    await queryRunner.query(`ALTER TABLE "USERS" ADD ("DIIA_VERIFIED" NUMBER(1,0) DEFAULT 0 NOT NULL)`);
    await queryRunner.query(`ALTER TABLE "USERS" ADD ("DIIA_VERIFIED_AT" TIMESTAMP)`);
    await queryRunner.query(`ALTER TABLE "USERS" ADD ("DIIA_STABLE_ID_HASH" VARCHAR2(128))`);
    await queryRunner.query(`ALTER TABLE "USERS" ADD ("DIIA_LAST_DOC_MASK" VARCHAR2(64))`);
    await queryRunner.query(
      `CREATE UNIQUE INDEX "UQ_USERS_DIIA_STABLE_ID_HASH" ON "USERS" ("DIIA_STABLE_ID_HASH")`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // 4) Удаляем индекс
    await queryRunner.query(`DROP INDEX "UQ_USERS_DIIA_STABLE_ID_HASH"`);

    // 3) Удаляем поля Дії
    await queryRunner.query(`ALTER TABLE "USERS" DROP COLUMN "DIIA_LAST_DOC_MASK"`);
    await queryRunner.query(`ALTER TABLE "USERS" DROP COLUMN "DIIA_STABLE_ID_HASH"`);
    await queryRunner.query(`ALTER TABLE "USERS" DROP COLUMN "DIIA_VERIFIED_AT"`);
    await queryRunner.query(`ALTER TABLE "USERS" DROP COLUMN "DIIA_VERIFIED"`);

    // 2) Сносим новый CHECK и дефолт
    try {
      await queryRunner.query(`ALTER TABLE "USERS" DROP CONSTRAINT "CHK_USERS_DEVICE_TYPE_LOWER"`);
    } catch (_) {
      // no-op
    }
    await queryRunner.query(`ALTER TABLE "USERS" MODIFY ("DEVICE_TYPE" DEFAULT 'DESKTOP')`);

    // 1) Возвращаем верхний регистр (если нужно совместимостью)
    await queryRunner.query(
      `UPDATE "USERS" SET "DEVICE_TYPE" = upper("DEVICE_TYPE") WHERE "DEVICE_TYPE" IS NOT NULL`
    );

    // 0) Возвращаем старый CHECK с верхним регистром
    await queryRunner.query(
      `ALTER TABLE "USERS" ADD CONSTRAINT "CHK_USERS_DEVICE_TYPE" CHECK ("DEVICE_TYPE" IN ('DESKTOP','MOBILE'))`
    );
  }
}


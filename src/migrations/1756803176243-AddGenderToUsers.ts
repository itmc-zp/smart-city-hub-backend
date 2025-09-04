import { MigrationInterface, QueryRunner, TableColumn } from "typeorm";

export class AddGenderToUsers1756803176243 implements MigrationInterface {
    name = 'AddGenderToUsers1756803176243'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.addColumn(
          "USERS",
          new TableColumn({
            name: "GENDER",
            type: "varchar2",
            length: "16",
            isNullable: true,
          })
        );
    
        await queryRunner.query(`UPDATE "USERS" SET "GENDER" = 'unknown' WHERE "GENDER" IS NULL`);
    
        await queryRunner.query(
          `ALTER TABLE "USERS" MODIFY ("GENDER" VARCHAR2(16) DEFAULT 'unknown' NOT NULL)`
        );
    
        await queryRunner.query(
          `ALTER TABLE "USERS" ADD CONSTRAINT "CHK_USERS_GENDER" CHECK ("GENDER" IN ('male','female','unknown'))`
        );
      }
    
      public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "USERS" DROP CONSTRAINT "CHK_USERS_GENDER"`);
        await queryRunner.query(`ALTER TABLE "USERS" DROP COLUMN "GENDER"`);
      }

}

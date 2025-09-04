import { MigrationInterface, QueryRunner } from "typeorm";

export class InitSchemaFixed1748499131939 implements MigrationInterface {
    name = 'InitSchemaFixed1748499131939'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TABLE "ACCOUNTS" ("ID" varchar2(36), "TYPE" varchar2(255) NOT NULL, "PROVIDER" varchar2(255) NOT NULL, "REFRESH_TOKEN" varchar2(255) NOT NULL, "ACCESS_TOKEN" varchar2(255) NOT NULL, "EXPIRES_AT" number NOT NULL, "PROVIDER_ACCOUNT_ID" varchar2(255) NOT NULL, "CREATED_AT" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL, "UPDATED_AT" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL, "USER_ID" varchar2(36), CONSTRAINT "PK_90a102d3b69da05c421706d3df9" PRIMARY KEY ("ID"))`);
        await queryRunner.query(`CREATE TABLE "USERS" ("ID" varchar2(36), "EMAIL" varchar2(255) NOT NULL, "PASSWORD" varchar2(255) NOT NULL, "DISPLAY_NAME" varchar2(255) NOT NULL, "PICTURE" varchar2(255), "IS_VERIFIED" number DEFAULT 0 NOT NULL, "IS_TWO_FACTOR_ENABLED" number DEFAULT 0 NOT NULL, "METHOD" varchar2(255) NOT NULL, "CREATED_AT" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL, "UPDATED_AT" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL, CONSTRAINT "UQ_03c5c0bfa50dcdf69c204bdebf2" UNIQUE ("EMAIL"), CONSTRAINT "PK_475d4b511309ada89807bc2d40b" PRIMARY KEY ("ID"))`);
        await queryRunner.query(`CREATE TABLE "TOKENS" ("ID" varchar2(36), "EMAIL" varchar2(255) NOT NULL, "TOKEN" varchar2(255) NOT NULL, "TYPE" varchar2(255) NOT NULL, "EXPIRES_IN" timestamp NOT NULL, "CREATED_AT" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL, CONSTRAINT "UQ_6d10c721097c69a2ea13288d420" UNIQUE ("TOKEN"), CONSTRAINT "PK_ab8dce27f5d4ba0ea4d90c77446" PRIMARY KEY ("ID"))`);
        await queryRunner.query(`ALTER TABLE "ACCOUNTS" ADD CONSTRAINT "FK_ee19dea0fd22d5c917c70ee2b8c" FOREIGN KEY ("USER_ID") REFERENCES "USERS" ("ID")`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "ACCOUNTS" DROP CONSTRAINT "FK_ee19dea0fd22d5c917c70ee2b8c"`);
        await queryRunner.query(`DROP TABLE "TOKENS"`);
        await queryRunner.query(`DROP TABLE "USERS"`);
        await queryRunner.query(`DROP TABLE "ACCOUNTS"`);
    }

}

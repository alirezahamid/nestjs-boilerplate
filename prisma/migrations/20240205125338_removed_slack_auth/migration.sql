/*
  Warnings:

  - You are about to drop the `user_authentications` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `users` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "user_authentications" DROP CONSTRAINT "user_authentications_userId_fkey";

-- DropTable
DROP TABLE "user_authentications";

-- DropTable
DROP TABLE "users";

-- DropEnum
DROP TYPE "ProviderType";

-- CreateTable
CREATE TABLE "User" (
    "id" SERIAL NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "email" TEXT NOT NULL,
    "password" TEXT,
    "firstName" TEXT,
    "lastName" TEXT,
    "verified" BOOLEAN NOT NULL DEFAULT false,
    "twoFactor" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

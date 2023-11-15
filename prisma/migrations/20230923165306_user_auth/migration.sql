-- CreateEnum
CREATE TYPE "ProviderType" AS ENUM ('SLACK', 'GOOGLE', 'GITHUB');

-- AlterTable
ALTER TABLE "users" ALTER COLUMN "password" DROP NOT NULL;

-- CreateTable
CREATE TABLE "user_authentications" (
    "id" SERIAL NOT NULL,
    "userId" INTEGER NOT NULL,
    "provider" "ProviderType" NOT NULL,
    "identifier" TEXT NOT NULL,
    "accessToken" TEXT NOT NULL,
    "refreshToken" TEXT,

    CONSTRAINT "user_authentications_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "user_authentications" ADD CONSTRAINT "user_authentications_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

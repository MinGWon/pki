-- CreateTable
CREATE TABLE `users` (
    `id` VARCHAR(191) NOT NULL,
    `email` VARCHAR(191) NOT NULL,
    `name` VARCHAR(191) NOT NULL,
    `phone` VARCHAR(191) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `users_email_key`(`email`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `certificates` (
    `id` VARCHAR(191) NOT NULL,
    `userId` VARCHAR(191) NOT NULL,
    `serialNumber` VARCHAR(191) NOT NULL,
    `subjectDN` VARCHAR(191) NOT NULL,
    `issuerDN` VARCHAR(191) NOT NULL,
    `publicKey` TEXT NOT NULL,
    `notBefore` DATETIME(3) NOT NULL,
    `notAfter` DATETIME(3) NOT NULL,
    `status` VARCHAR(191) NOT NULL DEFAULT 'ACTIVE',
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `certificates_serialNumber_key`(`serialNumber`),
    INDEX `certificates_userId_idx`(`userId`),
    INDEX `certificates_serialNumber_idx`(`serialNumber`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `oauth_clients` (
    `id` VARCHAR(191) NOT NULL,
    `clientId` VARCHAR(191) NOT NULL,
    `clientSecret` VARCHAR(191) NOT NULL,
    `name` VARCHAR(191) NOT NULL,
    `redirectUris` JSON NOT NULL,
    `scopes` JSON NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `oauth_clients_clientId_key`(`clientId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `oauth_authorization_codes` (
    `id` VARCHAR(191) NOT NULL,
    `code` VARCHAR(191) NOT NULL,
    `clientId` VARCHAR(191) NOT NULL,
    `userId` VARCHAR(191) NOT NULL,
    `redirectUri` VARCHAR(191) NOT NULL,
    `scope` VARCHAR(191) NULL,
    `codeChallenge` VARCHAR(191) NULL,
    `codeChallengeMethod` VARCHAR(191) NULL,
    `expiresAt` DATETIME(3) NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `oauth_authorization_codes_code_key`(`code`),
    INDEX `oauth_authorization_codes_code_idx`(`code`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `oauth_tokens` (
    `id` VARCHAR(191) NOT NULL,
    `accessToken` VARCHAR(500) NOT NULL,
    `refreshToken` VARCHAR(500) NULL,
    `clientId` VARCHAR(191) NOT NULL,
    `userId` VARCHAR(191) NOT NULL,
    `scope` VARCHAR(191) NULL,
    `expiresAt` DATETIME(3) NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `oauth_tokens_accessToken_key`(`accessToken`),
    UNIQUE INDEX `oauth_tokens_refreshToken_key`(`refreshToken`),
    INDEX `oauth_tokens_accessToken_idx`(`accessToken`),
    INDEX `oauth_tokens_refreshToken_idx`(`refreshToken`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `revoked_certificates` (
    `id` VARCHAR(191) NOT NULL,
    `serialNumber` VARCHAR(191) NOT NULL,
    `reason` VARCHAR(191) NULL,
    `revokedAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `revoked_certificates_serialNumber_key`(`serialNumber`),
    INDEX `revoked_certificates_serialNumber_idx`(`serialNumber`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `challenges` (
    `id` VARCHAR(191) NOT NULL,
    `challenge` VARCHAR(191) NOT NULL,
    `userId` VARCHAR(191) NULL,
    `expiresAt` DATETIME(3) NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `challenges_challenge_key`(`challenge`),
    INDEX `challenges_challenge_idx`(`challenge`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `audit_logs` (
    `id` VARCHAR(191) NOT NULL,
    `action` VARCHAR(191) NOT NULL,
    `userId` VARCHAR(191) NULL,
    `clientId` VARCHAR(191) NULL,
    `ipAddress` VARCHAR(191) NULL,
    `userAgent` TEXT NULL,
    `details` JSON NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `audit_logs_userId_idx`(`userId`),
    INDEX `audit_logs_createdAt_idx`(`createdAt`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `certificates` ADD CONSTRAINT `certificates_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

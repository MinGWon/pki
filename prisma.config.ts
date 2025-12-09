import path from 'node:path';
import { defineConfig } from 'prisma/config';

export default defineConfig({
  earlyAccess: true,
  schema: path.join(__dirname, 'prisma', 'schema.prisma'),
  migrate: {
    async adapter() {
      const { PrismaMysql } = await import('@prisma/adapter-mysql');
      const mysql = await import('mysql2/promise');
      const connection = await mysql.createConnection(process.env.DATABASE_URL!);
      return new PrismaMysql(connection);
    },
  },
});

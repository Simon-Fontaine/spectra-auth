import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export async function userHasRole(userId: string, roleName: string) {
  const count = await prisma.userRoles.count({
    where: {
      userId,
      role: {
        name: roleName,
      },
    },
  });
  return count > 0;
}

export async function userHasPermission(userId: string, permission: string) {
  const roles = await prisma.userRoles.findMany({
    where: { userId },
    include: { role: true },
  });

  const allPermissions = roles.flatMap((ur) => ur.role.permissions);
  return allPermissions.includes(permission);
}

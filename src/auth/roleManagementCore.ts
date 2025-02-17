import { z } from "zod";
import { type ActionResponse, type CoreContext, ErrorCodes } from "../types";
import { getSessionCore } from "./getSessionCore";
import { userHasPermission, userHasRole } from "./permissions";

const ADMIN_ROLE = "ADMIN";
const MANAGE_ROLES_PERMISSION = "MANAGE_ROLES";

const createRoleSchema = z.object({
  name: z.string().min(1, "Role name cannot be empty"),
  permissions: z.array(z.string()).optional(),
});

export async function createRoleCore(
  ctx: CoreContext,
  data: { name: string; permissions?: string[] },
): Promise<ActionResponse> {
  const { prisma, config } = ctx;
  const { logger } = config;

  const parsed = createRoleSchema.safeParse(data);
  if (!parsed.success) {
    logger.warn("createRoleCore invalid input", {
      errors: parsed.error.errors,
    });
    return {
      success: false,
      status: 400,
      message: "Invalid role data",
      code: ErrorCodes.INVALID_INPUT,
    };
  }

  const sessionResult = await getSessionCore(ctx, { disableRefresh: true });
  if (!sessionResult.success || !sessionResult.data?.session) {
    return sessionResult;
  }

  const hasManagePermission = await userHasPermission(
    ctx,
    MANAGE_ROLES_PERMISSION,
  );
  const isAdmin = await userHasRole(ctx, ADMIN_ROLE);
  if (!hasManagePermission && !isAdmin) {
    logger.warn("createRoleCore insufficient permissions", {
      userId: sessionResult.data.user?.id,
    });
    return {
      success: false,
      status: 403,
      message: "Insufficient permissions to create roles",
      code: ErrorCodes.AUTH_INSUFFICIENT_PERMISSIONS,
    };
  }

  const { name, permissions } = parsed.data;
  const existingRole = await prisma.role.findUnique({ where: { name } });
  if (existingRole) {
    logger.warn("createRoleCore role already exists", { roleName: name });
    return {
      success: false,
      status: 409,
      message: `Role "${name}" already exists`,
      code: ErrorCodes.INVALID_INPUT,
    };
  }

  const role = await prisma.role.create({
    data: {
      name,
      permissions: permissions ?? [],
    },
  });

  logger.info("createRoleCore success", {
    roleId: role.id,
    roleName: role.name,
  });
  return {
    success: true,
    status: 201,
    message: `Role "${role.name}" created successfully`,
  };
}

const updateRoleSchema = z.object({
  roleId: z.string().uuid("Invalid role ID provided."),
  name: z.string().optional(),
  permissions: z.array(z.string()).optional(),
});

export async function updateRoleCore(
  ctx: CoreContext,
  data: { roleId: string; name?: string; permissions?: string[] },
): Promise<ActionResponse> {
  const { prisma, config } = ctx;
  const { logger } = config;

  const parsed = updateRoleSchema.safeParse(data);
  if (!parsed.success) {
    logger.warn("updateRoleCore invalid input", {
      errors: parsed.error.errors,
    });
    return {
      success: false,
      status: 400,
      message: "Invalid role data",
      code: ErrorCodes.INVALID_INPUT,
    };
  }

  const sessionResult = await getSessionCore(ctx, { disableRefresh: true });
  if (!sessionResult.success || !sessionResult.data?.session) {
    return sessionResult;
  }

  const hasManagePermission = await userHasPermission(
    ctx,
    MANAGE_ROLES_PERMISSION,
  );
  const isAdmin = await userHasRole(ctx, ADMIN_ROLE);
  if (!hasManagePermission && !isAdmin) {
    logger.warn("updateRoleCore insufficient permissions", {
      userId: sessionResult.data.user?.id,
    });
    return {
      success: false,
      status: 403,
      message: "Insufficient permissions to update roles",
      code: ErrorCodes.AUTH_INSUFFICIENT_PERMISSIONS,
    };
  }

  const { roleId, name, permissions } = parsed.data;
  const role = await prisma.role.findUnique({ where: { id: roleId } });
  if (!role) {
    logger.warn("updateRoleCore role not found", { roleId });
    return {
      success: false,
      status: 404,
      message: "Role not found",
      code: ErrorCodes.ACCOUNT_NOT_FOUND,
    };
  }

  if (name && name !== role.name) {
    const conflict = await prisma.role.findUnique({ where: { name } });
    if (conflict) {
      logger.warn("updateRoleCore duplicate role name", { roleName: name });
      return {
        success: false,
        status: 409,
        message: `Role "${name}" already exists`,
        code: ErrorCodes.INVALID_INPUT,
      };
    }
  }

  await prisma.role.update({
    where: { id: roleId },
    data: {
      name: name ?? role.name,
      permissions: permissions ?? role.permissions,
    },
  });

  logger.info("updateRoleCore success", { roleId });
  return {
    success: true,
    status: 200,
    message: "Role updated successfully",
  };
}

const deleteRoleSchema = z.object({
  roleId: z.string().uuid("Invalid role ID provided."),
});

export async function deleteRoleCore(
  ctx: CoreContext,
  data: { roleId: string },
): Promise<ActionResponse> {
  const { prisma, config } = ctx;
  const { logger } = config;

  const parsed = deleteRoleSchema.safeParse(data);
  if (!parsed.success) {
    logger.warn("deleteRoleCore invalid input", {
      errors: parsed.error.errors,
    });
    return {
      success: false,
      status: 400,
      message: "Invalid role data",
      code: ErrorCodes.INVALID_INPUT,
    };
  }

  const sessionResult = await getSessionCore(ctx, { disableRefresh: true });
  if (!sessionResult.success || !sessionResult.data?.session) {
    return sessionResult;
  }

  const hasManagePermission = await userHasPermission(
    ctx,
    MANAGE_ROLES_PERMISSION,
  );
  const isAdmin = await userHasRole(ctx, ADMIN_ROLE);
  if (!hasManagePermission && !isAdmin) {
    logger.warn("deleteRoleCore insufficient permissions", {
      userId: sessionResult.data.user?.id,
    });
    return {
      success: false,
      status: 403,
      message: "Insufficient permissions to delete roles",
      code: ErrorCodes.AUTH_INSUFFICIENT_PERMISSIONS,
    };
  }

  const { roleId } = parsed.data;
  const role = await prisma.role.findUnique({ where: { id: roleId } });
  if (!role) {
    logger.warn("deleteRoleCore role not found", { roleId });
    return {
      success: false,
      status: 404,
      message: "Role not found",
      code: ErrorCodes.ACCOUNT_NOT_FOUND,
    };
  }

  await prisma.$transaction([
    prisma.userRoles.deleteMany({ where: { roleId } }),
    prisma.role.delete({ where: { id: roleId } }),
  ]);

  logger.info("deleteRoleCore success", { roleId });
  return {
    success: true,
    status: 200,
    message: `Role "${role.name}" deleted successfully.`,
  };
}

const addRoleToUserSchema = z.object({
  userId: z.string().uuid("Invalid user ID provided."),
  roleId: z.string().uuid("Invalid role ID provided."),
});

export async function addRoleToUserCore(
  ctx: CoreContext,
  data: { userId: string; roleId: string },
): Promise<ActionResponse> {
  const { prisma, config } = ctx;
  const { logger } = config;

  const parsed = addRoleToUserSchema.safeParse(data);
  if (!parsed.success) {
    logger.warn("addRoleToUserCore invalid input", {
      errors: parsed.error.errors,
    });
    return {
      success: false,
      status: 400,
      message: "Invalid input",
      code: ErrorCodes.INVALID_INPUT,
    };
  }

  const sessionResult = await getSessionCore(ctx, { disableRefresh: true });
  if (!sessionResult.success || !sessionResult.data?.session) {
    return sessionResult;
  }

  const hasManagePermission = await userHasPermission(
    ctx,
    MANAGE_ROLES_PERMISSION,
  );
  const isAdmin = await userHasRole(ctx, ADMIN_ROLE);
  if (!hasManagePermission && !isAdmin) {
    logger.warn("addRoleToUserCore insufficient permissions", {
      userId: sessionResult.data.user?.id,
    });
    return {
      success: false,
      status: 403,
      message: "Insufficient permissions to assign roles",
      code: ErrorCodes.AUTH_INSUFFICIENT_PERMISSIONS,
    };
  }

  const { userId, roleId } = parsed.data;
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) {
    logger.warn("addRoleToUserCore user not found", { userId });
    return {
      success: false,
      status: 404,
      message: "User not found",
      code: ErrorCodes.ACCOUNT_NOT_FOUND,
    };
  }
  const role = await prisma.role.findUnique({ where: { id: roleId } });
  if (!role) {
    logger.warn("addRoleToUserCore role not found", { roleId });
    return {
      success: false,
      status: 404,
      message: "Role not found",
      code: ErrorCodes.ACCOUNT_NOT_FOUND,
    };
  }

  const existingUserRole = await prisma.userRoles.findFirst({
    where: { userId, roleId },
  });
  if (existingUserRole) {
    logger.warn("addRoleToUserCore user already has role", { userId, roleId });
    return {
      success: false,
      status: 409,
      message: "User already has this role",
      code: ErrorCodes.INVALID_INPUT,
    };
  }

  await prisma.userRoles.create({
    data: {
      userId,
      roleId,
    },
  });

  logger.info("addRoleToUserCore success", { userId, roleId });
  return {
    success: true,
    status: 200,
    message: `Role "${role.name}" assigned to user "${user.username}" successfully.`,
  };
}

const removeRoleFromUserSchema = z.object({
  userId: z.string().uuid("Invalid user ID provided."),
  roleId: z.string().uuid("Invalid role ID provided."),
});

export async function removeRoleFromUserCore(
  ctx: CoreContext,
  data: { userId: string; roleId: string },
): Promise<ActionResponse> {
  const { prisma, config } = ctx;
  const { logger } = config;

  const parsed = removeRoleFromUserSchema.safeParse(data);
  if (!parsed.success) {
    logger.warn("removeRoleFromUserCore invalid input", {
      errors: parsed.error.errors,
    });
    return {
      success: false,
      status: 400,
      message: "Invalid input",
      code: ErrorCodes.INVALID_INPUT,
    };
  }

  const sessionResult = await getSessionCore(ctx, { disableRefresh: true });
  if (!sessionResult.success || !sessionResult.data?.session) {
    return sessionResult;
  }

  const hasManagePermission = await userHasPermission(
    ctx,
    MANAGE_ROLES_PERMISSION,
  );
  const isAdmin = await userHasRole(ctx, ADMIN_ROLE);
  if (!hasManagePermission && !isAdmin) {
    logger.warn("removeRoleFromUserCore insufficient permissions", {
      userId: sessionResult.data.user?.id,
    });
    return {
      success: false,
      status: 403,
      message: "Insufficient permissions to remove roles",
      code: ErrorCodes.AUTH_INSUFFICIENT_PERMISSIONS,
    };
  }

  const { userId, roleId } = parsed.data;

  const userRole = await prisma.userRoles.findFirst({
    where: { userId, roleId },
  });
  if (!userRole) {
    logger.warn("removeRoleFromUserCore user role mapping not found", {
      userId,
      roleId,
    });
    return {
      success: false,
      status: 404,
      message: "User does not have that role",
      code: ErrorCodes.ACCOUNT_NOT_FOUND,
    };
  }

  await prisma.userRoles.delete({ where: { id: userRole.id } });

  logger.info("removeRoleFromUserCore success", { userId, roleId });
  return {
    success: true,
    status: 200,
    message: "Role removed from user successfully.",
  };
}

export async function getRolesCore(ctx: CoreContext): Promise<ActionResponse> {
  const { prisma, config } = ctx;
  const { logger } = config;

  const sessionResult = await getSessionCore(ctx, { disableRefresh: true });
  if (!sessionResult.success || !sessionResult.data?.session) {
    return sessionResult;
  }

  const hasManagePermission = await userHasPermission(
    ctx,
    MANAGE_ROLES_PERMISSION,
  );
  const isAdmin = await userHasRole(ctx, ADMIN_ROLE);
  if (!hasManagePermission && !isAdmin) {
    logger.warn("getRolesCore insufficient permissions", {
      userId: sessionResult.data.user?.id,
    });
    return {
      success: false,
      status: 403,
      message: "Insufficient permissions to list roles",
      code: ErrorCodes.AUTH_INSUFFICIENT_PERMISSIONS,
    };
  }

  const roles = await prisma.role.findMany();
  logger.info("getRolesCore success", { count: roles.length });

  return {
    success: true,
    status: 200,
    message: "Roles fetched successfully",
    data: roles,
  };
}

const getRoleByIdSchema = z.object({
  roleId: z.string().uuid("Invalid role ID provided."),
});

export async function getRoleByIdCore(
  ctx: CoreContext,
  data: { roleId: string },
): Promise<ActionResponse> {
  const { prisma, config } = ctx;
  const { logger } = config;

  const parsed = getRoleByIdSchema.safeParse(data);
  if (!parsed.success) {
    logger.warn("getRoleByIdCore invalid input", {
      errors: parsed.error.errors,
    });
    return {
      success: false,
      status: 400,
      message: "Invalid role ID",
      code: ErrorCodes.INVALID_INPUT,
    };
  }

  const sessionResult = await getSessionCore(ctx, { disableRefresh: true });
  if (!sessionResult.success || !sessionResult.data?.session) {
    return sessionResult;
  }

  const hasManagePermission = await userHasPermission(
    ctx,
    MANAGE_ROLES_PERMISSION,
  );
  const isAdmin = await userHasRole(ctx, ADMIN_ROLE);
  if (!hasManagePermission && !isAdmin) {
    logger.warn("getRoleByIdCore insufficient permissions", {
      userId: sessionResult.data.user?.id,
    });
    return {
      success: false,
      status: 403,
      message: "Insufficient permissions to get role",
      code: ErrorCodes.AUTH_INSUFFICIENT_PERMISSIONS,
    };
  }

  const { roleId } = parsed.data;
  const role = await prisma.role.findUnique({
    where: { id: roleId },
  });

  if (!role) {
    logger.warn("getRoleByIdCore role not found", { roleId });
    return {
      success: false,
      status: 404,
      message: "Role not found",
      code: ErrorCodes.ACCOUNT_NOT_FOUND,
    };
  }

  logger.info("getRoleByIdCore success", { roleId });
  return {
    success: true,
    status: 200,
    message: "Role found",
    data: role,
  };
}

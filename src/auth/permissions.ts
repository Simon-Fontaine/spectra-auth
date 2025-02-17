import type { CoreContext } from "../types";
import { getSessionCore } from "./getSessionCore";

export async function userHasRole(
  ctx: CoreContext,
  roleName: string,
): Promise<boolean> {
  const sessionResult = await getSessionCore(ctx, { disableRefresh: true });
  if (!sessionResult.success || !sessionResult.data) {
    return false;
  }
  const { roles } = sessionResult.data;
  return roles?.includes(roleName) ?? false;
}

export async function userHasAnyRole(
  ctx: CoreContext,
  roleNames: string[],
): Promise<boolean> {
  const sessionResult = await getSessionCore(ctx, { disableRefresh: true });
  if (!sessionResult.success || !sessionResult.data) {
    return false;
  }
  const { roles } = sessionResult.data;
  return roles?.some((r) => roleNames.includes(r)) ?? false;
}

export async function userHasPermission(
  ctx: CoreContext,
  permission: string,
): Promise<boolean> {
  const sessionResult = await getSessionCore(ctx, { disableRefresh: true });
  if (!sessionResult.success || !sessionResult.data) {
    return false;
  }
  const { permissions } = sessionResult.data;
  return permissions?.includes(permission) ?? false;
}

export async function userHasAnyPermission(
  ctx: CoreContext,
  permissionList: string[],
): Promise<boolean> {
  const sessionResult = await getSessionCore(ctx, { disableRefresh: true });
  if (!sessionResult.success || !sessionResult.data) {
    return false;
  }
  const { permissions } = sessionResult.data;
  return permissions?.some((perm) => permissionList.includes(perm)) ?? false;
}

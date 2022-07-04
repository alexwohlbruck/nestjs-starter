// TODO: This is a temporary solution to prevent the user's password hash from being used
// * Some day, hopefully, the Prisma team will allow @hidden to be used in the Prisma schema
// * For now, this workaround is the only reasonable option
// ? https://stackoverflow.com/questions/68140035/exclude-users-password-from-query-with-prisma-2/72695395#72695395
export async function excludePassword(params, next) {
  const result = await next(params)
  const select = params?.args?.select

  if (params?.model === 'User') {
    if (!select?.password) delete result.password
    if (!select?.totpSecret) delete result.totpSecret
  }
  return result
}

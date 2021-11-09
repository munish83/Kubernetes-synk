export const removeAuth = (
  env: Record<string, string>,
): Record<string, string> => {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { SNYK_TOKEN, ...result } = env;
  return result;
};

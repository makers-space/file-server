export const buildCookieOptions = (env = process.env) => {
    const domain = (env.COOKIE_DOMAIN || '').trim();
    return {
        httpOnly: true,
        secure: env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
        ...(domain ? { domain } : {})
    };
};

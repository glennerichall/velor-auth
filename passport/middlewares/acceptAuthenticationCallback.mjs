export const acceptAuthenticationCallback = (req, res, next) => {
    const provider = req.params.provider;
    const accept = composeAuthenticatorMiddleware(req, provider);
    return accept(req, res, next);
};
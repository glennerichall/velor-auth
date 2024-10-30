import {chainHandlers} from "velor-backend/core/chainHandlers.mjs";

export function composeAuthenticator(passport, key, provider) {
    const {
        validatorOptions = {},
        validatorPrologue = [],
        validatorEpilogue = [],
        handleAuthenticationFailure
    } = provider;

    const authenticate = (req, res, next) => {
        let handleFailure = undefined;

        if (handleAuthenticationFailure) {
            handleFailure = (_, user, error) => {
                if (error) {
                    handleAuthenticationFailure(req, res, error);
                } else {
                    req.logIn(user, (err) => {
                        if (err) return next(err);
                        else next();
                    });
                }
            };
        }
        return passport.authenticate(key,
            {
                // failureRedirect: urls[URL_LOGIN_FAILURE],
                failureFlash: true,
                ...validatorOptions
            }, handleFailure)(req, res, next);
    };

    return chainHandlers(
        ...validatorPrologue,

        authenticate,

        ...validatorEpilogue,
    );
}
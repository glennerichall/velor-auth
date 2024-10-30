import {
    isAuthenticated,
    isCsrfTokenValid,
    isSessionValid,
    isSessionValidAndAuthenticated
} from "./predicates.mjs";
import {notAsync} from "velor/utils/predicates.mjs";

export const verify = (predicate, status = 403) => {
    return async (req, res, next) => {
        if (!await predicate(req)) {
            res.sendStatus(status);
        } else {
            next();
        }
    }
};

export const verifySessionAndAuth = verify(isSessionValidAndAuthenticated, 401);

export const verifyAuthentication = verify(isAuthenticated, 401);

export const verifySession = verify(isSessionValid, 401);

export const verifyUnAuthentication = verify(notAsync(isAuthenticated));

export const verifyCsrfToken = verify(isCsrfTokenValid, 401);
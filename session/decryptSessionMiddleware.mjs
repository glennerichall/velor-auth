import {decryptUserSession} from "./decryptUserSession.mjs";

const ERROR_SESSION_EXPIRED = 'Browser session is expired';
const ERROR_SESSION_INVALID = 'Invalid session token';

export const decryptSessionMiddleware = (req, res, next) => {
    if (req.session?.dx) {
        if (!decryptUserSession(req)) {
            req.sessionError = ERROR_SESSION_INVALID;
        }

        // if the cookie came from another ip address, log out user
        if (req.userSession.ip !== req.ip) {
            if (req.session?.passport) {
                req.session.passport.user = null;
            }
            req.sessionError = ERROR_SESSION_EXPIRED;
        }
    } else {
        req.sessionError = ERROR_SESSION_EXPIRED;
    }
    next();
}

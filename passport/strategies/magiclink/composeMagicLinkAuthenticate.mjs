import {decryptUserSession} from "../../../session/decryptUserSession.mjs";

export function composeMagicLinkAuthenticate(loginSuccessUrl, loginFailureUrl, logInFromFetch) {

    return async (req, res, next) => {
        const targetUserSession = req.targetUserSession;

        if (decryptUserSession(req) && req.userSession?.ws === targetUserSession.ws) {
            // the url was called back with the same browser as the login email request was made
            // so reply immediately and the session cookie will be set to the correct browser context
            next();

        } else {
            // the url was called from another browser context. Ask the original browser context
            // to make the call to the callback url. The previous branch will be hit and the correct browser context will
            // receive the session cookie.
            try {
                // ask the browser to make a call using fetch. logInFromFetch should return the response the browser
                // has received.
                const response = await logInFromFetch(targetUserSession.ws);

                if (response.status === 200) {
                    res.redirect(loginSuccessUrl);

                } else {
                    req.flash('error', response.info);
                    res.redirect(loginFailureUrl);
                }

            } catch (e) {
                req.flash('error', e.message);
                res.redirect(loginFailureUrl);
            }
        }
    };
}
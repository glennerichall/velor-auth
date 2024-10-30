import {decryptSessionDetails} from "../../../session/requestDetails.mjs";

export function composeAuthenticate(loginSuccessUrl, loginFailureUrl, requireLogin) {

    return async (req, res, next) => {
        const context = req.redirectDetails;

        if (decryptSessionDetails(req) && req.requestDetails?.ws === context.ws) {
            // the url was called back with the same browser as the login email request was made
            // so on reply the session cookie will be set correctly
            next();

        } else {

            try {
                const response = await requireLogin(context.ws);
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
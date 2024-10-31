import {decryptText} from "velor/utils/encryption.mjs";

export function composeMagicLinkValidateQuery(loginFailureUrl) {

    return (req, res, next) => {
        if (!req.query.ws) {
            req.flash('error', 'Invalid token');
            res.redirect(loginFailureUrl);

        } else {
            try {
                req.targetUserSession = JSON.parse(decryptText(req.query.ws));
                next();

            } catch (e) {
                req.flash('error', 'Invalid token');
                res.redirect(loginFailureUrl);
            }
        }
    };
}
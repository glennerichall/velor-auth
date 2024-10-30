import {getLogger} from "velor/utils/injection/services.mjs";

export const onErrorNotifyFailure = (err, req, res, next) => {
    getLogger(req).debug("Failed to login " + err.message);
    req.session.flash = {
        error: err.message
    };
    res.redirect(getFullHostUrls(req)[URL_LOGIN_FAILURE]);
}
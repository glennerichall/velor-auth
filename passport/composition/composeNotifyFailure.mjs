export function composeNotifyFailure(getLoginFailureUrl) {
    return (err, req, res, next) => {
        req.session.flash = {
            error: err.message
        };
        res.redirect(getLoginFailureUrl());
    };
}
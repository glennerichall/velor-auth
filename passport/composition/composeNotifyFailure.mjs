export function composeNotifyFailure(loginFailureUrl) {
    return (err, req, res, next) => {
        req.session.flash = {
            error: err.message
        };
        res.redirect(loginFailureUrl);
    };
}
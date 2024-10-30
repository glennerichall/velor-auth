export function composeNotifyLoginSuccess(loginFailureUrl, loginSuccessUrl, getUser, insertLoginEvent, isSessionValid) {
    return async (req, res) => {

        const sessionValid = await isSessionValid(req);

        if (sessionValid) {
            const {
                requestDetails,
            } = req;

            const user = getUser(req);

            const {
                fingerprint,
                ip,
            } = requestDetails;

            await insertLoginEvent(fingerprint, user.loginAuth.id, ip, 'login');
            emitLoggedIn(user);
            res.redirect(loginSuccessUrl);

        } else {

            req.flash('warning', "The browser session who initiated the login request was closed");
            res.redirect(loginFailureUrl);
        }
    };
}
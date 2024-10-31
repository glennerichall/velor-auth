export function composeNotifyLoginSuccess(getLoginFailureUrl, getLoginSuccessUrl, emitLoggedIn,
                                          getUser, insertLoginEvent, isSessionValid) {
    return async (req, res) => {

        const sessionValid = await isSessionValid(req);

        if (sessionValid) {
            const user = getUser(req);

            const {
                fingerprint,
                ip,
            } = req.userSession;

            await insertLoginEvent(fingerprint, user.loginAuth.id, ip, 'login');
            emitLoggedIn(user);

            res.redirect(getLoginSuccessUrl());

        } else {

            req.flash('warning', "The browser session who initiated the login request was closed");
            res.redirect(getLoginFailureUrl());
        }
    };
}
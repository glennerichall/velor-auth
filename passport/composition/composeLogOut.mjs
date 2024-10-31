export function composeLogOut(insertLoginEvent, getUser, emitLoggedOut) {

    return async (req, res) => {
        const {
            fingerprint,
            ip,
        } = req.userSession;

        await new Promise((resolve, reject) => {
            req.logout(async err => {
                if (err) reject(err);
                else {
                    const user = getUser(req);
                    await insertLoginEvent(fingerprint, user.loginAuth.id, ip, 'logout');
                    emitLoggedOut(req);
                    resolve();
                }
            });
        });

        res.send();
    };
}
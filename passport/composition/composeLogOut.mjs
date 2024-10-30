export function composeLogOut(insertLoginEvent, logger,
                              getUser, emitLoggedOut) {

    return async (req, res) => {
        emitLoggedOut(req);

        const {
            fingerprint,
            ip,
        } = req.requestDetails;

        const user = getUser(req);

        try {
            await insertLoginEvent(fingerprint, user.loginAuth.id, ip, 'logout');
        } catch (e) {
            logger.error(e)
        }

        await new Promise((resolve, reject) => {
            req.logout(err => {
                if (err) reject(err);
                else resolve();
            });
        });
        res.send();
    };
}
import {
    URL_LOGIN_FAILURE,
    URL_LOGIN_SUCCESS
} from "../../routes/urls.mjs";

export const notifyLoginSuccess = async (req, res) => {

    const clients = await getWsClientsBySession(req);

    if (clients) {
        const {
            requestDetails,
        } = req;

        const user = getUser(req);
        const database = getDatabase(req);
        const urls = getUrls(req);

        const {
            fingerprint,
            ip,
        } = requestDetails;

        await database.users.insertLoginEvent(fingerprint, user.loginAuth.id, ip);

        // set the new userId to ws clients
        // this will also update the client index in ws tracker
        // (see ZupfeWsClientManager#createClient)
        clients.setUserId(user.id);

        const getEmitterFactory = composeAutoSendMessageFactoryProvider(req);
        const emit = await getEmitterFactory(clients);
        emit.loggedIn();
        res.redirect(urls[URL_LOGIN_SUCCESS]);

    } else {

        req.flash('warning', "The browser session who initiated the login request was closed");
        res.redirect(getFullHostUrls(req)[URL_LOGIN_FAILURE]);
    }
};
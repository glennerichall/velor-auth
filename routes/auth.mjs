import {
    createSessionValidation,
    validateSession
} from "../session/requestDetails.mjs";


import {
    URL_CONFIRM_EMAIL,
    URL_LOGIN,
    URL_LOGIN_FAILURE,
    URL_LOGIN_SUCCESS,
    URL_LOGOUT,
    URL_PASSPORT_CALLBACK
} from "./urls.mjs";


import {
    verifyAuthentication,
    verifyCsrfToken
} from "../auth/verification.mjs";

import {MAGIC_LINK} from "../auth/authProviders.mjs";
import {composeRenderLoginFailure} from "../passport/composition/composeRenderLoginFailure.mjs";
import {composeAuthStrategyProvider} from "../passport/middlewares/validateProvider.mjs";
import {composeRenderLoginSuccess} from "../passport/composition/composeRenderLoginSuccess.mjs";
import {composePostConfirmEmail} from "../passport/composition/composePostConfirmEmail.mjs";
import {composeLogOut} from "../passport/composition/composeLogOut.mjs";
import {composeConfirmEmailCallback} from "../passport/composition/composeConfirmEmailCallback.mjs";
import {initiateAuth} from "../passport/composition/initiateAuth.mjs";
import {authenticate} from "../passport/composition/composeAuthAuthenticator.mjs";


export function createConfiguration(options) {

    const {
        views,
        email,
        user,
        database,
        logger,
        strategies,
    } = options;

    return [
        {
            name: URL_LOGIN_SUCCESS,
            path: '/login_success',
            get: composeRenderLoginSuccess(views.logo)
        },
        {
            name: URL_LOGIN_FAILURE,
            path: '/login_failure',
            get: composeRenderLoginFailure(views.logo)
        },
        {
            name: URL_CONFIRM_EMAIL,
            path: '/email/confirm',
            // sending an email confirmation with a link to GET /email/confirm
            post: [
                validateSession,
                verifyAuthentication,
                verifyCsrfToken,
                composePostConfirmEmail(
                    email.sendEmail,
                    email.clientSecret,
                    email.redirectUrl,
                    user.getUser,
                    user.getProfile,
                    user.getLoginAuth
                )
            ],
            // receiving the link from the confirmation email
            get: composeConfirmEmailCallback(
                email.clientSecret,
                database.getTokens,
                database.createToken
            )
        },
        {
            name: URL_LOGOUT,
            path: '/logout',
            post: [
                validateSession,
                verifyAuthentication,
                verifyCsrfToken,
                composeLogOut(
                    database.insertLoginEvent,
                    logger,
                    user.getUser,
                    user.emitLoggedOut
                )
            ]
        },

        {
            // The user initiates the authentication process
            // If it is not redirected to a federated authenticator by the login strategy
            // then it will be considered authenticated and logged in, unless an error is thrown.
            name: URL_LOGIN,
            path: '/login/:provider',
            get: [
                composeAuthStrategyProvider(strategies),
                validateSession,
                initiateAuth
            ]
        },

        {
            // Then, when the browser is redirected to the callback url,
            // we check if the current session cookie is still valid.
            // If the profile is accepted, then all user browser sessions are notified.

            // Magic link session callback must be ignored as it may be called from another
            // browser and still be a valid request. Eventually, the initiating browser
            // will fetch the callback url in XHR transmitting along-way the valid browser session cookie.
            name: URL_PASSPORT_CALLBACK,
            path: '/redirect/:provider',
            get: [
                composeAuthStrategyProvider(strategies),
                createSessionValidation({
                    onFail: {redirect: req => getFullHostUrls(req)[URL_LOGIN_FAILURE]},

                    // Do not validate the session if the callback is for magic-link and
                    // it is not an xhr request.
                    exclude: req => {
                        const provider = req.params.provider;
                        return provider === MAGIC_LINK && !req.xhr;
                    }
                }),
                authenticate
            ]
        }
    ];
}
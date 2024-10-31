import {validateSession} from "../session/createSessionValidation.mjs";

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

import {composeRenderLoginFailure} from "../passport/composition/composeRenderLoginFailure.mjs";
import {composeAuthStrategyProvider} from "../passport/composition/composeAuthStrategyProvider.mjs";
import {composeRenderLoginSuccess} from "../passport/composition/composeRenderLoginSuccess.mjs";
import {composePostConfirmEmail} from "../passport/composition/composePostConfirmEmail.mjs";
import {composeLogOut} from "../passport/composition/composeLogOut.mjs";
import {composeConfirmEmailCallback} from "../passport/composition/composeConfirmEmailCallback.mjs";
import {initiateAuth} from "../passport/middlewares/initiateAuth.mjs";
import {authenticate} from "../passport/middlewares/authenticate.mjs";
import {composeNotifyLoginSuccess} from "../passport/composition/composeNotifyLoginSuccess.mjs";
import {composeNotifyFailure} from "../passport/composition/composeNotifyFailure.mjs";
import {createStrategies} from "../passport/strategies/createStrategies.mjs";


export function createConfiguration(options) {

    const {
        views,
        email,
        user,
        database,
        getUrl,
    } = options;

    const {strategies, initialize} = createStrategies(options);

    const notifyLoginSuccess = composeNotifyLoginSuccess(
        () => getUrl(URL_LOGIN_FAILURE),
        () => getUrl(URL_LOGIN_SUCCESS),
        user.getUser,
        database.insertLoginEvent,
        user.isSessionValid
    );

    const notifyLoginFailure = composeNotifyFailure(
        () => getUrl(URL_LOGIN_FAILURE)
    );


    const configuration = [
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
                initiateAuth,
                notifyLoginSuccess,
                notifyLoginFailure
            ]
        },

        {
            // Then, when the browser is redirected to the callback url,
            name: URL_PASSPORT_CALLBACK,
            path: '/redirect/:provider',
            get: [
                composeAuthStrategyProvider(strategies),
                authenticate,
                notifyLoginSuccess,
                notifyLoginFailure
            ]
        }
    ];

    return {
        configuration,
        initialize
    };
}
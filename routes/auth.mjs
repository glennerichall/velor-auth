import {
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

import passport from "passport";

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
import {GitHubStrategy} from "../passport/strategies/github.mjs";
import {composeOnUserProfile} from "../passport/profile/user.mjs";
import {GoogleStrategy} from "../passport/strategies/google.mjs";
import {TokenStrategy} from "../passport/strategies/token.mjs";
import {MagicLinkStrategy} from "../passport/strategies/magiclink.mjs";


export function createConfiguration(options) {

    const {
        views,
        email,
        user,
        database,
        logger,
        getUrl,
        google,
        github,
        token,
        magiclink
    } = options;

    const notifyLoginSuccess = composeNotifyLoginSuccess(
        getUrl(URL_LOGIN_FAILURE),
        getUrl(URL_LOGIN_SUCCESS),
        user.getUser,
        database.insertLoginEvent,
        user.isSessionValid
    );

    const notifyLoginFailure = composeNotifyFailure(
        getUrl(URL_LOGIN_FAILURE)
    );

    let strategies = [];

    let onProfileReceived = composeOnUserProfile();

    if (github) {
        strategies.push(
            new GitHubStrategy(passport,
                onProfileReceived,
                github.clientID, github.clientSecret)
        )
    }

    if (google) {
        strategies.push(
            new GoogleStrategy(passport,
                onProfileReceived,
                google.clientID, google.clientSecret)
        )
    }

    if (magiclink) {
        strategies.push(
            new MagicLinkStrategy(passport, onProfileReceived, database.authTokens,
                email.sendMail, email.secret, user.requireLogin)
        )
    }

    if (token) {
        strategies.push(
            new TokenStrategy(passport,
                onProfileReceived,
                token.token)
        )
    }

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
}
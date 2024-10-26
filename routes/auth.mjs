import {
    acceptAuthenticationCallback,
    getConfirmEmail,
    initiateAuthentication,
    logOut,
    notifyLoginSuccess,
    onErrorNotifyFailure,
    postConfirmEmail,
    renderLoginFailure,
    renderLoginSuccess,
    replyAvatar,
    replyProfile,
    validateProvider
} from "..//resources/passport/middlewares.mjs";

import {createSessionValidation, validateSession} from "../resources/session/requestDetails.mjs";


import {
    URL_AVATAR,
    URL_CONFIRM_EMAIL,
    URL_LOGIN,
    URL_LOGIN_FAILURE,
    URL_LOGIN_SUCCESS,
    URL_LOGOUT,
    URL_PASSPORT_CALLBACK,
    URL_PROFILE
} from "../../shared/constants/urls.mjs";

import {MAGIC_LINK} from "../../shared/constants/auth_providers.mjs";

import {verifyAuthentication, verifyCsrfToken} from "../auth/middlewares.mjs";


const configuration = [
    {
        name: URL_LOGIN_SUCCESS,
        path: '/login_success',
        get: renderLoginSuccess
    },
    {
        name: URL_LOGIN_FAILURE,
        path: '/login_failure',
        get: renderLoginFailure
    },
    {
        // sending an email confirmation with a link to GET /email/confirm
        name: URL_CONFIRM_EMAIL,
        path: '/email/confirm',
        post: [
            createSessionValidation(),
            verifyAuthentication,
            verifyCsrfToken,
            postConfirmEmail
        ]
    },
    {
        name: URL_CONFIRM_EMAIL,
        path: '/email/confirm',
        // sending an email confirmation with a link to GET /email/confirm
        post: [
            createSessionValidation(),
            verifyAuthentication,
            verifyCsrfToken,
            postConfirmEmail
        ],
        // receiving the link from the confirmation email
        get: getConfirmEmail
    },
    {
        name: URL_LOGOUT,
        path: '/logout',
        post: [
            validateSession,
            verifyAuthentication,
            verifyCsrfToken,
            logOut
        ]
    },
    {
        name: URL_PROFILE,
        path: '/profile',
        get: [
            validateSession,
            verifyAuthentication,
            replyProfile
        ]
    },
    {
        name: URL_AVATAR,
        path: '/avatar',
        get: [
            validateSession,
            verifyAuthentication,
            replyAvatar
        ]
    },

    {
        // The user initiates the authentication process
        // If it is not redirected to a federated authenticator by the login strategy
        // then it will be considered authenticated and logged in, unless an error is thrown.
        name: URL_LOGIN,
        path: '/login/:provider',
        get: [
            validateSession,
            validateProvider,
            initiateAuthentication,
            notifyLoginSuccess,
            onErrorNotifyFailure
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
            validateProvider,
            createSessionValidation({
                onFail: {redirect: req => getFullHostUrls(req)[URL_LOGIN_FAILURE]},

                // Do not validate the session if the callback is for magic-link and
                // it is not an xhr request.
                exclude: req => {
                    const provider = req.params.provider;
                    return provider === MAGIC_LINK && !req.xhr;
                }
            }),
            acceptAuthenticationCallback,
            notifyLoginSuccess,
            onErrorNotifyFailure
        ]
    }
]

export default services => createRouterBuilder(configuration);
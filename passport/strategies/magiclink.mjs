import {configs} from "./magiclink/configs.mjs";
import {PGStorage} from "./magiclink/PGStorage.mjs";
import {MAGIC_LINK} from "../../auth/authProviders.mjs";
import {chainHandlers} from "velor-backend/core/chainHandlers.mjs";
import {composeValidateQuery} from "./magiclink/validateQuery.mjs";
import {composeAuthenticate} from "./magiclink/composeAuthenticate.mjs";
import {composeProfileHandler} from "./magiclink/composeProfileHandler.mjs";
import MagicLink from "passport-magic-link";
import {composeSendTokenByEmail} from "./magiclink/composeSendTokenByEmail.mjs";


export class MagicLinkStrategy {
    #strategy;
    #passport;
    #initiator;
    #authenticator;
    #options;

    constructor(passport, onProfileReceived, database, sendMail, secret,
                loginSuccessUrl, loginFailureUrl, requireLogin) {

        this.#options = {
            onProfileReceived, database, sendMail, secret,
            loginSuccessUrl, loginFailureUrl, requireLogin
        };

        this.#passport = passport;
    }

    initialize(callbackURL) {
        const {
            onProfileReceived, database,
            sendMail, secret
        } = this.#options;

        const config = {
            secret,
            userFields: ['email'],
            tokenField: 'token',
            storage: new PGStorage(database),
            passReqToCallbacks: true,
            userPrimaryKey: 'loginAuth',
            ...configs,
        };
        this.#strategy = new MagicLink.Strategy(
            config,
            composeSendTokenByEmail(callbackURL.replace(':provider', MAGIC_LINK), sendMail),
            composeProfileHandler(onProfileReceived));


        this.#strategy.options = this.#options;
        this.#passport.use(MAGIC_LINK, this.#strategy);

        this.#initiator = composeInitiator(this.#passport);
        this.#authenticator = composeAuthenticator(this.#passport, this.#options);
    }

    initiate(req, res, next) {
        return this.#initiator(req, res, next);
    }

    authenticate(req, res, next) {
        return this.#authenticator(req, res, next);
    }
}

function composeInitiator(passport) {
    const initiate = passport.authenticate(MAGIC_LINK,
        {
            action: 'requestToken',
            passReqToCallback: true,
        });

    const replyRequestId = (req, res) => {
        const requestId = req.requestId;
        res.status(200).json({requestId});
    };

    return chainHandlers(
        initiate,
        replyRequestId
    );
}

function composeAuthenticator(passport, options) {

    const {
        loginSuccessUrl,
        loginFailureUrl,
        requireLogin
    } = options;

    const authenticate = passport.authenticate(MAGIC_LINK,
        {
            action: 'acceptToken',
            userPrimaryKey: 'loginAuth'
        });

    const requestLoginFromXhrIfNeeded = composeAuthenticate(loginSuccessUrl, loginFailureUrl, requireLogin);
    const validateQuery = composeValidateQuery(loginFailureUrl);

    return chainHandlers(
        validateQuery,
        requestLoginFromXhrIfNeeded,
        authenticate,
    );
}
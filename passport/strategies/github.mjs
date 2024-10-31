import Strategy from 'passport-github2';
import {GITHUB} from "../../auth/authProviders.mjs";


export class GitHubStrategy {
    #strategy;
    #passport;
    #clientID;
    #clientSecret;
    #onProfileReceived;

    constructor(passport, onProfileReceived, clientID, clientSecret) {
        this.#clientID = clientID;
        this.#clientSecret = clientSecret;
        this.#onProfileReceived = onProfileReceived;
        this.#passport = passport;
    }

    get initialized() {
        return !!this.#strategy;
    }

    initialize(callbackURL) {
        const configs = {
            clientID: this.#clientID,
            clientSecret: this.#clientSecret,
            callbackURL: callbackURL.replace(':provider', GITHUB),
            passReqToCallback: true,
            scope: ['profile'],
            state: true
        };

        this.#strategy = new Strategy(configs,
            composeOnProfileReceivedAdapter(GITHUB, this.#onProfileReceived));

        this.#passport.use(GITHUB, this.#strategy);
    }

    initiate(req, res, next) {
        return this.#passport.authenticate(GITHUB,
            {
                scope: ['user:email'],
                passReqToCallback: true,
            })(req, res, next);
    }

    authenticate(req, res, next) {
        return this.#passport.authenticate(GITHUB,
            {
                failureFlash: true,
            })(req, res, next);
    }
}
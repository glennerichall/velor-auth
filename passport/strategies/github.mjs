import Strategy from 'passport-github2';
import {GITHUB,} from "../../auth/authProviders.mjs";


export class GitHubStrategy {
    #strategy;
    #passport;

    constructor(passport, callbackURL, onProfileReceived, clientID, clientSecret) {

        const configs = {
            clientID,
            clientSecret,
            callbackURL,
            passReqToCallback: true,
            scope: ['profile'],
            state: true
        };

        this.#passport = passport;
        this.#strategy = new Strategy(configs, onProfileReceived);
        passport.use(GITHUB, this.#strategy);
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
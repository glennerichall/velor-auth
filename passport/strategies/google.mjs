import Strategy from 'passport-google-oauth20';
import {GOOGLE} from "../../auth/authProviders.mjs";

export class GoogleStrategy {
    #strategy;
    #passport;

    constructor(passport, callbackURL, onProfileReceived,
                clientID, clientSecret) {
        const configs = {
            clientID,
            clientSecret,
            callbackURL: callbackURL.replace(':provider', GOOGLE),
            passReqToCallback: true,
            scope: ['profile'],
            state: true,
        };
        this.#passport = passport;
        this.#strategy = new Strategy(configs, onProfileReceived);
        passport.use(GOOGLE, this.#strategy);
    }

    initiate(req, res, next) {
        return this.#passport.authenticate(GOOGLE,
            {
                scope: ['profile', 'email'],
                passReqToCallback: true,
            })(req, res, next);
    }

    authenticate(req, res, next) {
        return this.#passport.authenticate(GOOGLE,
            {
                failureFlash: true,
            })(req, res, next);
    }
}
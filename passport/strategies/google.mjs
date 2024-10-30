import Strategy from 'passport-google-oauth20';
import {GOOGLE} from "../../auth/authProviders.mjs";

export class GoogleStrategy {
    #strategy;
    #passport;
    #clientID;
    #clientSecret;
    #onProfileReceived;

    constructor(passport, onProfileReceived,
                clientID, clientSecret) {
        this.#clientID = clientID;
        this.#clientSecret = clientSecret;
        this.#onProfileReceived = onProfileReceived;
        this.#passport = passport;
    }

    initialize(callbackURL) {
        const configs = {
            clientID: this.#clientID,
            clientSecret: this.#clientSecret,
            callbackURL: callbackURL.replace(':provider', GOOGLE),
            passReqToCallback: true,
            scope: ['profile'],
            state: true,
        };

        this.#strategy = new Strategy(configs,
            composeOnProfileReceived(GOOGLE, this.#onProfileReceived));
        this.#passport.use(GOOGLE, this.#strategy);
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
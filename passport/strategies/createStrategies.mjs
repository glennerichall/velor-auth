import {GitHubStrategy} from "./github.mjs";
import {GoogleStrategy} from "./google.mjs";
import {MagicLinkStrategy} from "./magiclink.mjs";
import {TokenStrategy} from "./token.mjs";

export function createStrategies(configs) {

    const {
        google,
        github,
        token,
        magiclink,
        onProfileReceived,
        passport
    } = configs;

    let strategies = [];

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
            new MagicLinkStrategy(passport,
                onProfileReceived,
                database.authTokens,
                magiclink.sendMail, magiclink.clientSecret, user.requireLogin)
        )
    }

    if (token) {
        strategies.push(
            new TokenStrategy(passport,
                onProfileReceived, token.token)
        )
    }

    return strategies;
}
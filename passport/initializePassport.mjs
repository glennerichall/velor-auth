import {
    decryptText,
    encryptText
} from "velor/utils/encryption.mjs";

export function serializeUser(user) {
    return encryptText(JSON.stringify(user));
}

export function deserializeUser(data) {
    return JSON.parse(decryptText(data));
}

export function initializePassport(passport) {

    passport.serializeUser((user, done) => {
        done(null, serializeUser(user));
    });

    passport.deserializeUser(async (data, done) => {
        const user = deserializeUser(data);
        done(null, user);
    });
}
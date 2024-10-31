import crypto from "crypto";
import {encryptText} from "velor/utils/encryption.mjs";
import {getFingerprint} from "./getFingerprint.mjs";
import {createUserSession} from "./createUserSession.mjs";
import {decryptUserSession} from "./decryptUserSession.mjs";

function initSession(req) {
    createUserSession(req);

    if (req.session.passport) {
        req.session.passport.user = null;
    }
}

export async function createSessionCookie(req, res) {

    if (!req.session.dx || !decryptUserSession(req)) {
        initSession(req);
    }

    if (
        req.userSession.fingerprint !== getFingerprint(req) ||
        req.userSession.ip !== req.ip) {
        initSession(req);
    }

    if (req.userSession.errorMsg) {
        res.status(400).send(req.userSession.errorMsg);

    } else {
        const csrf = crypto.randomUUID();
        req.userSession.csrf = csrf;
        req.session.dx = encryptText(JSON.stringify(req.userSession));

        res.status(200).json({csrf});
    }
}


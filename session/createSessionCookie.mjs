import {createSessionDetails, decryptSessionDetails, getFingerprint} from "./requestDetails.mjs";
import crypto from "crypto";
import {encryptText} from "velor/utils/encryption.mjs";

export async function createSessionCookie(req, res) {
    function initSession() {
        createSessionDetails(req);
        if (req.session.passport) {
            req.session.passport.user = null;
        }
    }

    if (!req.session.dx || !decryptSessionDetails(req)) {
        initSession();
    }

    if (
        req.requestDetails.fingerprint !== getFingerprint(req) ||
        req.requestDetails.ip !== req.ip) {
        initSession();
    }

    if (req.requestDetails.errorMsg) {
        res.status(400).send(req.requestDetails.errorMsg);
    } else {
        const csrf = crypto.randomUUID();
        req.requestDetails.csrf = csrf;
        req.session.dx = encryptText(JSON.stringify(req.requestDetails));
        res.status(200).json({csrf});
    }
}


import {decryptText} from "velor/utils/encryption.mjs";

export function decryptUserSession(req) {
    try {
        req.userSession = JSON.parse(decryptText(req.session.dx));
        return !!req.userSession;

    } catch (e) {
        req.userSession = null;
        return false;
    }
}
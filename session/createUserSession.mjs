import {getFingerprint} from "./getFingerprint.mjs";
import crypto from "crypto";

export const fpSchema = Joi.string().hex();

export function createUserSession(req) {
    let errorMsg;
    const fingerprint = getFingerprint(req);

    if (!fingerprint) {
        errorMsg = 'fpu is undefined';

    } else if (fpSchema.validate(fingerprint).error) {
        errorMsg = 'fpu has invalid format';
    }

    req.userSession = {
        ws: crypto.randomUUID(),
        ip: req.ip,
        fingerprint,
        errorMsg
    };
}
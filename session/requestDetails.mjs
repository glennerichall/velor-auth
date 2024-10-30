import crypto from "crypto";
import Joi from "joi";
import {
    ERROR_SESSION_EXPIRED,
    ERROR_SESSION_INVALID
} from "../../../shared/constants/errors.mjs";
import {decryptText} from "velor/utils/encryption.mjs";

export const fpSchema = Joi.string().hex();

export function decryptSessionDetails(req) {
    try {
        req.requestDetails = JSON.parse(decryptText(req.session.dx));
        return !!req.requestDetails;
    } catch (e) {
        req.requestDetails = null;
        return false;
    }
}

export function getFingerprint(req) {
    return req.header('x-fpu') || req.query.fpu;
}

export function createSessionDetails(req) {
    let errorMsg;
    const fingerprint = getFingerprint(req);

    if (!fingerprint) {
        errorMsg = 'fpu is undefined';
    } else if (fpSchema.validate(fingerprint).error) {
        errorMsg = 'fpu has invalid format';
    }
    const info = {
        ws: crypto.randomUUID(),
        ip: req.ip,
        fingerprint,
        errorMsg
    }
    req.requestDetails = info;
}

export const createSessionValidation = (options = {}) => {
    const {
        exclude = () => false,
        onFail = {status: 403}
    } = options;

    return async (req, res, next) => {
        function fail(msg) {
            if (onFail.throw) {
                throw new Error(msg);
            } else if (onFail.status) {
                res.status(onFail.status).send(msg);
            } else if (onFail.redirect) {
                req.flash('error', msg);
                let url = onFail.redirect;
                if (typeof onFail.redirect === 'function') {
                    url = onFail.redirect(req);
                }
                res.redirect(url);
            }
        }

        if (req.sessionError && !exclude(req)) {
            fail(req.sessionError);
        } else {
            next();
        }
    }
}

export const validateSession = createSessionValidation();

export const decryptSession = (req, res, next) => {
    if (req.session?.dx) {
        if (!decryptSessionDetails(req)) {
            req.sessionError = ERROR_SESSION_INVALID;
        }

        // if the cookie came from another ip address, log out user
        if (req.requestDetails.ip !== req.ip) {
            if (req.session?.passport) {
                req.session.passport.user = null;
            }
            req.sessionError = ERROR_SESSION_EXPIRED;
        }
    } else {
        req.sessionError = ERROR_SESSION_EXPIRED;
    }
    next();
}

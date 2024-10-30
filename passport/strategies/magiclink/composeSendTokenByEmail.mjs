import crypto from "crypto";
import {configs} from "./configs.mjs";

export function composeSendTokenByEmail(callbackURL, sendMail) {

    return async (req, user, token) => {
        req.requestId = crypto.randomInt(10000);

        const link = `You requested to sign in to https://zupfe.velor.ca. Please open the link below in your browser to sign in.
Your request id is ${req.requestId}.

${callbackURL}?token=${token}&ws=${req.session.dx}

Link can only be used once and will expire in ${configs.ttl / 60} minutes
`;
        const email = user.loginAuth.email;
        const ok = await sendMail(email, 'ZupFe sign-in', link);
        if (!ok) {
            throw new Error('Unable to send mail');
        }
    }
}


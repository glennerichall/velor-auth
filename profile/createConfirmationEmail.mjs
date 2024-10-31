import {createJwt} from "./createJwt.mjs";
import crypto from "crypto";

export async function createConfirmationEmail(clientSecret, redirectUrl, user, profile, loginAuth, ttl = 10 * 60) {
    const email = profile.email;

    const token = await createJwt(loginAuth.id,
        {email, userId: user.id},
        clientSecret, ttl);

    const requestId = crypto.randomInt(10000);
    const content = `Please confirm your email by following the link below.
Your request id is ${requestId}.

${redirectUrl}?token=${token}

Link can only be used once and will expire in ${ttl / 60} minutes
`;
    let object = 'ZupFe email confirmation';

    return {
        email,
        object,
        content,
        requestId
    };
}
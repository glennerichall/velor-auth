import jwt from "jsonwebtoken";

export async function createJwt(authId, content, clientSecret, ttl = 60 * 10 /* 10 minutes */) {
    return jwt.sign({
            authId,
            iat: Math.floor(Date.now() / 1000),
            ...content
        },
        clientSecret,
        {
            expiresIn: ttl,
            subject: 'email validation'
        });
}
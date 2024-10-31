import jwt from "jsonwebtoken";

export async function validateConfirmationToken(clientSecret, getTokens, createToken, token) {
    return new Promise((resolve, reject) => {
        jwt.verify(token, clientSecret,
            async (err, decoded) => {
                if (err) {
                    reject(new Error(err.message));
                } else {
                    const existingTokens = await getTokens(decoded.authId);
                    const expiration = new Date(decoded.exp * 1000);

                    for (let tok of existingTokens) {
                        if (tok.value === token) {
                            reject(new Error('token already used'));
                            return;
                        }
                    }

                    await createToken(decoded.authId, {
                        expiration,
                        value: token
                    });

                    resolve(decoded);
                }
            })
    });
}
import querystring from "querystring";

export const composeOnProfileReceivedMagicLinkAdapter = onProfileReceived => (req, auth) => {
    let displayName = null;

    auth.email = querystring.unescape(auth.email);

    if (auth.email) {
        let tokens = auth.email.split('@');
        if (tokens.length === 2) {
            displayName = tokens[0];
        }
    }

    const profile = {
        id: auth.email,
        email: auth.email,
        displayName
    };

    return new Promise((resolve, reject) => {
        const done = (err, result) => {
            if (err) reject(err);
            else resolve(result);
        }
        onProfileReceived(req, null, null, profile, done);
    });
}
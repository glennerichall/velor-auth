const composeOnProfileReceived = (provider, onProfileReceived) =>
    async (req, tok1, tok2, profile, done) => {
        try {
            const user = await onProfileReceived(provider, profile);
            done(null, user);
        } catch (err) {
            done(err);
        }
    };

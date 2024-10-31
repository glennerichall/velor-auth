export function composeInsertAuth(queryByAuthIdProvider, insertAuth) {

    return async (provider, profile) => {
        let auth = await queryByAuthIdProvider(profile.id, provider);

        if (!auth) {
            // The account has not logged in to this app before.  Create a
            // new user record and associate it with the provider account.
            let email = null;
            let displayName = null;
            let verified = false;
            let firstName = null;
            let lastName = null;
            let avatar = null;

            if (Array.isArray(profile.emails) && profile.emails.length !== 0) {
                email = profile.emails[0].value;
                verified = true;
            } else if (profile.email) {
                email = profile.email;
            }

            if (profile.displayName) {
                displayName = profile.displayName
            } else if (typeof profile.name === 'string') {
                displayName = profile.name;
            } else if (profile.name) {
                if (profile.name.givenName && profile.name.familyName) {
                    displayName = `${profile.name.givenName} ${profile.name.familyName}`;
                } else if (profile.name.givenName) {
                    displayName = profile.name.givenName;
                } else if (profile.name.familyName) {
                    displayName = profile.name.familyName;
                }
            }

            if (profile.name) {
                if (profile.name.familyName) {
                    lastName = profile.name.familyName;
                }
                if (profile.name.givenName) {
                    firstName = profile.name.givenName;
                }
            }

            if (Array.isArray(profile.photos) && profile.photos.length >= 1) {
                avatar = profile.photos[0].value;
            } else if (profile.image_url_https) {
                avatar = profile.image_url_https;
            }

            auth = {
                auth_id: profile.id,
                provider,
                email,
                verified,
                displayName,
                avatar,
                firstName,
                lastName
            };
            await insertAuth(auth);
            auth = await queryByAuthIdProvider(profile.id, provider);
        }
        return auth;
    }
}
import {createConfirmationEmail} from "../../profile/createConfirmationEmail.mjs";

export function composePostConfirmEmail(sendEmail, clientSecret, redirectUrl,
                                        getUser, getProfile, getLoginAuth
) {
    return async (req, res) => {

        const user = await getUser(req);
        const profile = await getProfile(user);
        const loginAuth = await getLoginAuth(user);

        if (!profile) {
            return res.status(404).send('Unable to find user profile');
        } else if (profile.confirmed) {
            return res.status(409).send('The email was already confirmed');
        }

        const {
            email,
            object,
            content,
            requestId
        } = await createConfirmationEmail(clientSecret, redirectUrl,
            user, profile, loginAuth);

        try {
            await sendEmail(email, object, content);
            res.status(200).json(requestId);
        } catch (e) {
            res.status(422).send('The profile is not confirmed');
        }
    };
}
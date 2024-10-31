import {validateConfirmationToken} from "../../profile/validateConfirmationToken.mjs";

export function composeConfirmEmailCallback(clientSecret, getTokens, createToken) {

    return async (req, res) => {
        const {token} = req.query;
        try {
            await validateConfirmationToken(clientSecret, getTokens, createToken, token);

            res.render('notification', {
                message: 'You can now safely close this windows',
                success: true,
                title: 'Email confirmed'
            });

        } catch (err) {
            res.render('notification', {
                message: err.message,
                success: false,
                title: 'Failed to confirm email'
            });
        }
    };
}
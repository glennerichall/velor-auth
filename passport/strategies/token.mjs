import DevStrategy from 'passport-custom';
import {getLogger} from "velor/utils/injection/services.mjs";
import {TOKEN} from "../../auth/authProviders.mjs";
import {chainHandlers} from "velor-backend/core/chainHandlers.mjs";

export const registerStrategy = (passport, {onProfileReceived, token}) => {
    const strategy = new DevStrategy(
        (req, done) => {
            getLogger(req).debug(`Logging with dev token[${req.get('Authorization')}]`);

            if (req.get('Authorization') === token) {
                getLogger(req).debug(`Logging successful`);

                onProfileReceived(req, null, null, {
                    id: 'DevOps',
                    email: 'zupfe@velor.ca',
                    displayName: 'DevOps',
                }, done);
            } else {
                done(new Error('Invalid token'));
            }
        }
    );

    passport.use(TOKEN, strategy);
}

export function getInitiator(passport) {
    const initiate = passport.authenticate(TOKEN,
        {
            passReqToCallback: true,
        });

    const replyOnError = (err, req, res, next) => {
        if (err.message === 'Invalid token') {
            res.status(401).end();
        } else {
            next(err);
        }
    };

    return chainHandlers(
        initiate,
        replyOnError
    )
}

export function getAuthenticator(passport) {

}
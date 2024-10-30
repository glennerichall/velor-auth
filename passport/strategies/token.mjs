import Custom from 'passport-custom';
import {TOKEN} from "../../auth/authProviders.mjs";
import {chainHandlers} from "velor-backend/core/chainHandlers.mjs";

export class TokenStrategy {
    #passport;
    #strategy;
    #initiator;

    constructor(passport, onProfileReceived, token) {
        this.#strategy = new Custom.Strategy(
            (req, done) => {
                if (req.get('Authorization') === token) {
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

        passport.use(TOKEN, this.#strategy);
        this.#passport = passport;
        this.#initiator = composeInitiator(passport);
    }

    initiate(req, res, next) {
        return this.#initiator(req, res, next);
    }
}

function composeInitiator(passport) {
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
    );
}
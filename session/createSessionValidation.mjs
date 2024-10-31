export const createSessionValidation = (options = {}) => {
    const {
        exclude = () => false,
        onFail = {status: 403}
    } = options;

    return async (req, res, next) => {
        function fail(msg) {
            if (onFail.throw) {
                throw new Error(msg);

            } else if (onFail.status) {
                res.status(onFail.status).send(msg);

            } else if (onFail.redirect) {
                req.flash('error', msg);
                let url = onFail.redirect;
                if (typeof onFail.redirect === 'function') {
                    url = onFail.redirect(req);
                }
                res.redirect(url);
            }
        }

        if (req.sessionError && !exclude(req)) {
            fail(req.sessionError);

        } else {
            next();
        }
    }
}
export const validateSession = createSessionValidation();
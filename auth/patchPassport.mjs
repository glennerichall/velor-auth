// https://github.com/jaredhanson/passport/issues/904#issuecomment-1307558283
export const patchPassport = (request, response, next) => {
    if (request.session && !request.session.regenerate) {
        request.session.regenerate = (cb) => {
            cb()
        }
    }
    if (request.session && !request.session.save) {
        request.session.save = (cb) => {
            cb()
        }
    }
    next()
}